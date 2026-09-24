//! HTTP route handlers — zero-crate port of `backend/server.ts`.
//!
//! One function per route. Status codes, JSON error bodies, and cookie
//! attributes match the Node server so a parity harness can byte-diff them.

use std::collections::BTreeMap;
use std::os::fd::FromRawFd;
use std::os::unix::process::CommandExt;

use crate::auth::{self, JwtError, JwtPayload, TOKEN_EXPIRATION_DAYS};
use crate::config;
use crate::crypto::{self, ct_eq};
use crate::db::{self, AuthRecord, Subscription, Usage, User, UserQuery};
use crate::http::{Cookie, Request, Response, SameSite};
use crate::json::{self, Json};
use crate::kdf;
use crate::middleware;
use crate::state::AppState;
use crate::stores::CSRF_TOKEN_EXPIRY_MS;
use crate::stripe;
use crate::stripe_worker::OwnedCheckoutParams;
use crate::validation;

/// Dispatch one request: CORS, security headers, routes, access log.
pub fn handle(state: &AppState, req: Request) -> Response {
    let start = config::now_ms();
    middleware::dev_request_log(&state.log, &req, state.prod);
    let res = if req.method.eq_ignore_ascii_case("OPTIONS") {
        middleware::preflight(&req, &state.cors_origins)
    } else {
        let inner = dispatch(state, &req);
        let inner = middleware::apply_secure_headers(inner, state.prod);
        middleware::apply_cors(inner, &req, &state.cors_origins)
    };
    middleware::access_log(&req.method, &req.path, res.status, config::now_ms() - start);
    res
}

fn dispatch(state: &AppState, req: &Request) -> Response {
    match (req.method.as_str(), req.path.as_str()) {
        ("POST", "/api/payment") => payment(state, req),
        ("GET", "/api/health") => health(state),
        ("GET", "/api/__integration_error_test__") if config::env("NODE_ENV").as_deref() == Some("test") => {
            unhandled(state, req, "Intentional integration test error")
        }
        ("POST", "/api/signup") => signup(state, req),
        ("POST", "/api/signin") => signin(state, req),
        ("POST", "/api/signout") => signout(state, req),
        ("GET", "/api/me") => me_get(state, req),
        ("PUT", "/api/me") => me_put(state, req),
        ("POST", "/api/usage") => usage(state, req),
        ("POST", "/api/checkout") => checkout(state, req),
        ("POST", "/api/portal") => portal(state, req),
        // Literal xQR paths before any `:param` segment. `/lookups` is also a
        // legal X username, so it must not fall through to the `/:username` OG handler.
        ("GET", "/lookups") => x_lookups(state, req),
        ("GET", "/clear-cache") => x_clear_cache(state, req),
        ("GET", p) if qr_username(p).is_some() => x_qr_image(state, req),
        ("GET", p) if image_id(p).is_some() => x_profile_image(state, req),
        ("GET", p) if user_username(p).is_some() => x_user(state, req),
        (m, p) if p.starts_with("/api/") => {
            if m == "GET" || m == "HEAD" {
                not_found()
            } else {
                not_found()
            }
        }
        ("GET" | "HEAD", _) => static_or_spa(state, req),
        _ => not_found(),
    }
}

/// Liveness plus a real database round-trip, so a container healthcheck fails when
/// SQLite is unreachable instead of reporting a process that cannot serve anything.
fn health(state: &AppState) -> Response {
    let (status, database) = match state.pool.ping() {
        Ok(()) => (200, "connected"),
        Err(e) => {
            state
                .log
                .error("Health check database probe failed", &[("error", json::s(e.to_string()))]);
            (503, "unavailable")
        }
    };
    json_res(
        status,
        &json::obj([
            ("status", json::s(if status == 200 { "ok" } else { "degraded" })),
            ("database", json::s(database)),
            ("timestamp", json::i(config::now_ms())),
        ]),
    )
}

fn not_found() -> Response {
    Response::text(404, "404 Not Found")
}

fn json_res(status: u16, v: &Json) -> Response {
    Response::json(status, &json::stringify(v))
}

fn err_json(status: u16, msg: &str) -> Response {
    json_res(status, &json::obj([("error", json::s(msg))]))
}

/// Map a Stripe worker / client error to an HTTP response.
///
/// Timeouts answer 504 so a slow Stripe cannot look like an application bug;
/// every other failure stays 500 with a generic body.
fn stripe_err(state: &AppState, log_msg: &str, e: crate::stripe::StripeError) -> Response {
    state
        .log
        .error(log_msg, &[("error", json::s(e.to_string()))]);
    match e {
        crate::stripe::StripeError::Timeout => err_json(504, "Payment provider timed out"),
        crate::stripe::StripeError::Busy => err_json(503, "Payment provider busy"),
        _ if log_msg.starts_with("Portal") => err_json(500, "Stripe portal failed"),
        _ if log_msg.starts_with("Checkout") => err_json(500, "Stripe session failed"),
        _ => err_json(500, "Stripe request failed"),
    }
}

fn unhandled(state: &AppState, req: &Request, message: &str) -> Response {
    let request_id = middleware::request_id();
    let mut meta: Vec<(&str, Json)> = vec![
        ("message", json::s(message)),
        ("path", json::s(req.path.clone())),
        ("method", json::s(req.method.clone())),
        ("requestId", json::s(request_id)),
    ];
    if !state.prod {
        meta.push(("stack", Json::Null));
    }
    state.log.error("Unhandled error occurred", &meta);
    if state.prod {
        err_json(500, "Internal server error")
    } else {
        json_res(500, &json::obj([("error", json::s(message))]))
    }
}

fn parse_json_body(req: &Request) -> Result<Json, Response> {
    json::parse(&req.body).map_err(|_| err_json(400, "Invalid request body"))
}

fn generate_csrf_token() -> Result<String, Response> {
    crypto::random_bytes(32)
        .map(|b| crypto::hex_encode(&b))
        .map_err(|_| err_json(500, "Server error"))
}

fn generate_uuid() -> Result<String, Response> {
    crypto::random_uuid_v4().map_err(|_| err_json(500, "Server error"))
}

fn generate_token(state: &AppState, user_id: &str) -> Result<String, Response> {
    let Some(secret) = state.jwt_secret.as_deref() else {
        state.log.error(
            "Token generation error",
            &[("error", json::s("JWT_SECRET not configured - authentication disabled"))],
        );
        return Err(err_json(500, "Server error"));
    };
    Ok(auth::jwt_sign(
        &JwtPayload {
            user_id: user_id.to_string(),
            exp: Some(auth::token_expire_timestamp(TOKEN_EXPIRATION_DAYS)),
        },
        secret,
    ))
}

fn require_auth(state: &AppState, req: &Request) -> Result<String, Response> {
    let Some(secret) = state.jwt_secret.as_deref() else {
        return Err(err_json(503, "Authentication service unavailable"));
    };
    let Some(token) = req.cookie("token") else {
        return Err(err_json(401, "Unauthorized"));
    };
    match auth::jwt_verify(&token, secret) {
        Ok(p) => Ok(p.user_id),
        Err(JwtError::Expired) => {
            state.log.debug("Token expired", &[]);
            Err(err_json(401, "Token expired"))
        }
        Err(e) => {
            state.log.error(
                "Token verification error",
                &[("error", json::s(format!("{e:?}")))],
            );
            Err(err_json(401, "Invalid token"))
        }
    }
}

/// CSRF check for a state-changing request.
///
/// A token that is missing, mismatched, unknown to the store, or expired is
/// refused with 403. The refusal carries a freshly minted token as a cookie
/// whenever the caller's identity is known, so a client whose token was lost —
/// the in-memory store does not survive a restart — can retry once and succeed.
///
/// Deliberately *not* done here: accepting the request and regenerating the
/// token on a store miss. That turns every post-restart request into a free
/// pass, because the stored token is what the header is checked against.
///
/// # Errors
/// A 403 [`Response`], ready to return, with a replacement cookie when one
/// could be issued.
fn require_csrf(state: &AppState, req: &Request, user_id: &str) -> Result<(), Response> {
    if req.method == "GET" || req.path == "/api/signup" || req.path == "/api/signin" {
        return Ok(());
    }
    let csrf_header = req.header("x-csrf-token");
    if csrf_header.is_none() || user_id.is_empty() {
        state.log.info(
            "CSRF validation failed - missing token or userID",
            &[
                ("hasToken", Json::Bool(csrf_header.is_some())),
                ("hasUserID", Json::Bool(!user_id.is_empty())),
                ("path", json::s(req.path.clone())),
            ],
        );
        return Err(err_json(403, "Invalid CSRF token"));
    }
    let csrf_header = csrf_header.unwrap_or("");
    let Some(stored) = state.csrf.get(user_id) else {
        state.log.info(
            "CSRF validation failed - no token on record for this user",
            &[
                ("userID", json::s(user_id)),
                ("path", json::s(req.path.clone())),
            ],
        );
        return Err(csrf_retry(state, user_id, "CSRF token expired"));
    };
    if csrf_header.len() != stored.token.len()
        || !ct_eq(csrf_header.as_bytes(), stored.token.as_bytes())
    {
        state.log.info(
            "CSRF validation failed - token mismatch",
            &[
                ("userID", json::s(user_id)),
                ("path", json::s(req.path.clone())),
            ],
        );
        return Err(err_json(403, "Invalid CSRF token"));
    }
    if config::now_ms() - stored.timestamp > CSRF_TOKEN_EXPIRY_MS {
        state.log.info(
            "CSRF validation failed - token expired",
            &[
                ("userID", json::s(user_id)),
                (
                    "age",
                    json::s(format!("{}s", (config::now_ms() - stored.timestamp) / 1000)),
                ),
            ],
        );
        return Err(csrf_retry(state, user_id, "CSRF token expired"));
    }
    state.log.debug("CSRF validation passed", &[("userID", json::s(user_id))]);
    Ok(())
}

/// Build a 403 that also hands the caller a usable token for one retry.
///
/// Falls back to a plain 403 when a token cannot be minted, so a failure of the
/// random source can never turn into an accepted request.
fn csrf_retry(state: &AppState, user_id: &str, message: &str) -> Response {
    match generate_csrf_token() {
        Ok(token) => {
            state.csrf.set(user_id, token.clone(), config::now_ms());
            err_json(403, message).cookie(&csrf_cookie(state, &token))
        }
        Err(_) => {
            state.csrf.remove(user_id);
            err_json(403, message)
        }
    }
}

fn token_cookie(state: &AppState, jwt: &str) -> Cookie {
    Cookie {
        name: "token".into(),
        value: jwt.to_string(),
        http_only: true,
        secure: state.prod,
        same_site: SameSite::Strict,
        path: "/".into(),
        max_age: Some(TOKEN_EXPIRATION_DAYS * 24 * 60 * 60),
    }
}

fn csrf_cookie(state: &AppState, token: &str) -> Cookie {
    Cookie {
        name: "csrf_token".into(),
        value: token.to_string(),
        http_only: false,
        secure: state.prod,
        same_site: SameSite::Lax,
        path: "/".into(),
        max_age: Some(CSRF_TOKEN_EXPIRY_MS / 1000),
    }
}

fn delete_token_cookie(state: &AppState) -> Cookie {
    let mut c = token_cookie(state, "");
    c.max_age = Some(0);
    c
}

fn delete_csrf_cookie(state: &AppState) -> Cookie {
    let mut c = csrf_cookie(state, "");
    c.max_age = Some(0);
    c
}

fn set_auth_cookies(state: &AppState, res: Response, user_id: &str, jwt: &str) -> Result<Response, Response> {
    let csrf = generate_csrf_token()?;
    state.csrf.set(user_id, csrf.clone(), config::now_ms());
    Ok(res.cookie(&token_cookie(state, jwt)).cookie(&csrf_cookie(state, &csrf)))
}

fn user_json(u: &User) -> Json {
    let mut m = BTreeMap::new();
    m.insert("_id".into(), Json::Str(u.id.clone()));
    m.insert("email".into(), Json::Str(u.email.clone()));
    m.insert("name".into(), Json::Str(u.name.clone()));
    m.insert("created_at".into(), json::i(u.created_at));
    if let Some(sub) = &u.subscription {
        let mut sm = BTreeMap::new();
        sm.insert("stripeID".into(), Json::Str(sub.stripe_id.clone()));
        sm.insert(
            "expires".into(),
            sub.expires.map(json::i).unwrap_or(Json::Null),
        );
        sm.insert("status".into(), Json::Str(sub.status.clone()));
        m.insert("subscription".into(), Json::Obj(sm));
    }
    if let Some(usage) = &u.usage {
        let mut um = BTreeMap::new();
        um.insert("count".into(), json::i(usage.count));
        um.insert(
            "reset_at".into(),
            usage.reset_at.map(json::i).unwrap_or(Json::Null),
        );
        m.insert("usage".into(), Json::Obj(um));
    }
    Json::Obj(m)
}

fn db_err(state: &AppState, context: &str, e: &db::DbError) -> Response {
    state
        .log
        .error(context, &[("error", json::s(e.to_string()))]);
    err_json(500, "Server error")
}

fn is_duplicate(e: &db::DbError) -> bool {
    e.message.contains("UNIQUE constraint failed") || e.message.contains("duplicate key")
}

fn signup(state: &AppState, req: &Request) -> Response {
    if let Err(res) = enforce_auth_rate_limit(state, req) {
        return res;
    }
    let body = match parse_json_body(req) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Some(mut email) = body.get_str("email").map(str::to_string) else {
        return err_json(400, "Invalid email format or length");
    };
    let Some(password) = body.get_str("password") else {
        return err_json(400, "Password must be 6-72 characters");
    };
    let Some(name) = body.get_str("name") else {
        return err_json(400, "Name required (max 100 characters)");
    };
    if !validation::validate_email(&email) {
        return err_json(400, "Invalid email format or length");
    }
    if !validation::validate_password(password) {
        return err_json(400, "Password must be 6-72 characters");
    }
    if !validation::validate_name(name) {
        return err_json(400, "Name required (max 100 characters)");
    }
    email = email.to_lowercase().trim().to_string();
    let name = validation::escape_html(name.trim());

    let hash = match kdf::hash_password(password) {
        Ok(h) => h,
        Err(e) => {
            state.log.error("Signup error", &[("error", json::s(e.to_string()))]);
            return err_json(500, "Server error");
        }
    };
    let insert_id = match generate_uuid() {
        Ok(id) => id,
        Err(r) => return r,
    };
    let user = User {
        id: insert_id.clone(),
        email: email.clone(),
        name: name.clone(),
        created_at: config::now_ms(),
        subscription: None,
        usage: None,
    };
    let auth_rec = AuthRecord {
        email: email.clone(),
        password: hash,
        user_id: insert_id.clone(),
    };
    // One transaction, so a failure cannot leave a user row with no credentials
    // — an account nobody can sign in to, holding an email address that can
    // never be registered again.
    if let Err(e) = state.pool.create_account(&user, &auth_rec) {
        if is_duplicate(&e) {
            state.log.warn("Signup failed - duplicate account", &[]);
            return err_json(400, "Unable to create account with provided credentials");
        }
        return db_err(state, "Signup error", &e);
    }
    let token = match generate_token(state, &insert_id) {
        Ok(t) => t,
        Err(r) => return r,
    };
    let body = json::obj([
        ("id", json::s(insert_id.clone())),
        ("email", json::s(email)),
        ("name", json::s(name.trim())),
        ("tokenExpires", json::i(auth::token_expire_timestamp(TOKEN_EXPIRATION_DAYS))),
    ]);
    match set_auth_cookies(state, json_res(201, &body), &insert_id, &token) {
        Ok(res) => {
            state.log.info("Signup success", &[]);
            res
        }
        Err(r) => r,
    }
}

fn signin(state: &AppState, req: &Request) -> Response {
    if let Err(res) = enforce_auth_rate_limit(state, req) {
        return res;
    }
    let body = match parse_json_body(req) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Some(mut email) = body.get_str("email").map(str::to_string) else {
        return err_json(400, "Invalid credentials");
    };
    let Some(password) = body.get_str("password") else {
        return err_json(400, "Invalid credentials");
    };
    if !validation::validate_email(&email) {
        return err_json(400, "Invalid credentials");
    }
    email = email.to_lowercase().trim().to_string();
    state.log.debug("Attempting signin", &[]);

    let ip = client_ip(req);
    let lock = state.lockout.is_locked(&email, &ip, config::now_ms());
    if lock.locked {
        let body = json::obj([
            ("error", json::s("Account temporarily locked. Try again later.")),
            ("retryAfter", json::i(lock.remaining_time)),
        ]);
        return json_res(429, &body).header("Retry-After", &lock.remaining_time.to_string());
    }

    let auth = match state.pool.find_auth(&email) {
        Ok(v) => v,
        Err(e) => return db_err(state, "Signin error", &e),
    };
    let Some(auth) = auth else {
        state.log.debug("Auth record not found", &[]);
        state.lockout.record_failure(&email, &ip, config::now_ms());
        return err_json(401, "Invalid credentials");
    };
    if !kdf::verify_password(password, &auth.password) {
        state.log.debug("Password verification failed", &[]);
        state.lockout.record_failure(&email, &ip, config::now_ms());
        return err_json(401, "Invalid credentials");
    }
    if kdf::needs_rehash(&auth.password) {
        match kdf::hash_password(password) {
            Ok(new_hash) => {
                if let Err(e) = state.pool.update_auth_password(&email, &new_hash) {
                    state
                        .log
                        .warn("Password rehash failed", &[("error", json::s(e.to_string()))]);
                } else {
                    state.log.debug("Password hash migrated to scrypt", &[]);
                }
            }
            Err(e) => state
                .log
                .warn("Password rehash failed", &[("error", json::s(e.to_string()))]),
        }
    }
    let user = match state.pool.find_user(&UserQuery::Email(email.clone())) {
        Ok(v) => v,
        Err(e) => return db_err(state, "Signin error", &e),
    };
    let Some(user) = user else {
        state.log.error("User not found for auth record", &[]);
        return err_json(401, "Invalid credentials");
    };
    state.lockout.clear(&email, &ip);
    let token = match generate_token(state, &user.id) {
        Ok(t) => t,
        Err(r) => return r,
    };
    let mut m = BTreeMap::new();
    m.insert("id".into(), Json::Str(user.id.clone()));
    m.insert("email".into(), Json::Str(user.email.clone()));
    m.insert("name".into(), Json::Str(user.name.clone()));
    if let Some(sub) = &user.subscription {
        let mut sm = BTreeMap::new();
        sm.insert("stripeID".into(), Json::Str(sub.stripe_id.clone()));
        sm.insert(
            "expires".into(),
            sub.expires.map(json::i).unwrap_or(Json::Null),
        );
        sm.insert("status".into(), Json::Str(sub.status.clone()));
        m.insert("subscription".into(), Json::Obj(sm));
    }
    m.insert(
        "tokenExpires".into(),
        json::i(auth::token_expire_timestamp(TOKEN_EXPIRATION_DAYS)),
    );
    match set_auth_cookies(state, json_res(200, &Json::Obj(m)), &user.id, &token) {
        Ok(res) => {
            state.log.info("Signin success", &[]);
            res
        }
        Err(r) => r,
    }
}

fn signout(state: &AppState, req: &Request) -> Response {
    let user_id = match require_auth(state, req) {
        Ok(id) => id,
        Err(r) => return r,
    };
    // Sign-out changes server state, so it is CSRF-protected like any other
    // mutation. A refusal still hands back a usable token, so a client holding a
    // stale one can retry immediately rather than being stuck signed in.
    if let Err(res) = require_csrf(state, req, &user_id) {
        return res;
    }
    state.csrf.remove(&user_id);
    state.log.info("Signout success", &[]);
    json_res(200, &json::obj([("message", json::s("Signed out successfully"))]))
        .cookie(&delete_token_cookie(state))
        .cookie(&delete_csrf_cookie(state))
}

fn me_get(state: &AppState, req: &Request) -> Response {
    let user_id = match require_auth(state, req) {
        Ok(id) => id,
        Err(r) => return r,
    };
    state.log.debug("/me checking for user", &[]);
    match state.pool.find_user(&UserQuery::Id(user_id)) {
        Ok(Some(u)) => json_res(200, &user_json(&u)),
        Ok(None) => err_json(404, "User not found"),
        Err(e) => db_err(state, "Unhandled error occurred", &e),
    }
}

fn me_put(state: &AppState, req: &Request) -> Response {
    let user_id = match require_auth(state, req) {
        Ok(id) => id,
        Err(r) => return r,
    };
    if let Err(res) = require_csrf(state, req, &user_id) {
        return res;
    }
    // A malformed body is the caller's mistake, so it answers 400 like every other
    // JSON route — not the 500 an earlier revision returned.
    let body = match parse_json_body(req) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Some(name) = body.get("name") {
        let Some(name) = name.as_str() else {
            return err_json(400, "Name must be 1-100 characters");
        };
        if !validation::validate_name(name) {
            return err_json(400, "Name must be 1-100 characters");
        }
    }
    match state.pool.find_user(&UserQuery::Id(user_id.clone())) {
        Ok(Some(_)) => {}
        Ok(None) => return err_json(404, "User not found"),
        Err(e) => {
            state
                .log
                .error("Update user error", &[("error", json::s(e.to_string()))]);
            return err_json(500, "Failed to update user");
        }
    }
    let Some(name) = body.get_str("name") else {
        return err_json(400, "No valid fields to update");
    };
    let sanitized = validation::escape_html(name.trim());
    match state.pool.update_user_set_name(&user_id, &sanitized) {
        Ok(0) => err_json(400, "No changes made"),
        Ok(_) => match state.pool.find_user(&UserQuery::Id(user_id)) {
            Ok(Some(u)) => json_res(200, &user_json(&u)),
            Ok(None) => err_json(404, "User not found"),
            Err(e) => {
                state
                    .log
                    .error("Update user error", &[("error", json::s(e.to_string()))]);
                err_json(500, "Failed to update user")
            }
        },
        Err(e) => {
            state
                .log
                .error("Update user error", &[("error", json::s(e.to_string()))]);
            err_json(500, "Failed to update user")
        }
    }
}

fn resolve_usage(user: &User) -> Usage {
    user.usage.clone().unwrap_or(Usage {
        count: 0,
        reset_at: None,
    })
}

fn is_subscriber(sub: &Subscription) -> bool {
    sub.status == "active" && sub.expires.map(|e| e > config::now_secs()).unwrap_or(true)
}

fn sub_expires_iso(sub: &Subscription) -> Json {
    match sub.expires {
        Some(secs) => Json::Str(config::iso_from_secs(secs)),
        None => Json::Null,
    }
}

/// Length of a free-tier usage window, in seconds (30 days).
const USAGE_WINDOW_SECS: i64 = 30 * 24 * 60 * 60;

/// The 429 body returned when a free-tier caller has no quota left.
fn usage_limit_reached(limit: i64) -> Response {
    json_res(
        429,
        &json::obj([
            ("error", json::s("Usage limit reached")),
            ("remaining", json::i(0)),
            ("total", json::i(limit)),
            ("isSubscriber", Json::Bool(false)),
        ]),
    )
}

fn usage(state: &AppState, req: &Request) -> Response {
    let user_id = match require_auth(state, req) {
        Ok(id) => id,
        Err(r) => return r,
    };
    // `operation: "track"` increments a stored counter, so this is a mutation.
    // The body is parsed as JSON regardless of Content-Type, which means a
    // cross-site form post could otherwise reach it without a preflight.
    if let Err(res) = require_csrf(state, req, &user_id) {
        return res;
    }
    let body = match json::parse(&req.body) {
        Ok(v) => v,
        Err(e) => {
            state
                .log
                .error("Usage tracking error", &[("error", json::s(e.to_string()))]);
            return err_json(500, "Server error");
        }
    };
    let operation = body.get_str("operation").unwrap_or("");
    if operation != "check" && operation != "track" {
        return err_json(400, "Invalid operation. Must be 'check' or 'track'");
    }
    let user = match state.pool.find_user(&UserQuery::Id(user_id.clone())) {
        Ok(Some(u)) => u,
        Ok(None) => return err_json(404, "User not found"),
        Err(e) => return db_err(state, "Usage tracking error", &e),
    };
    if let Some(sub) = &user.subscription {
        if is_subscriber(sub) {
            let mut sm = BTreeMap::new();
            sm.insert("status".into(), Json::Str(sub.status.clone()));
            sm.insert("expiresAt".into(), sub_expires_iso(sub));
            return json_res(
                200,
                &Json::Obj(BTreeMap::from([
                    ("remaining".into(), json::i(-1)),
                    ("total".into(), json::i(-1)),
                    ("isSubscriber".into(), Json::Bool(true)),
                    ("subscription".into(), Json::Obj(sm)),
                ])),
            );
        }
    }
    let limit = state.free_usage_limit;
    let now = config::now_secs();
    let mut usage = resolve_usage(&user);
    let is_tracking = operation == "track";
    // A limit below 1 admits nothing, including the first request of a new
    // window — which the window reset below would otherwise wave through.
    if is_tracking && limit < 1 {
        return usage_limit_reached(limit);
    }
    if usage.reset_at.map(|r| now > r).unwrap_or(true) {
        let new_reset = now + USAGE_WINDOW_SECS;
        // Reset and first increment together: a separate increment could be
        // issued by a concurrent request and then erased by this reset.
        match state
            .pool
            .reset_usage_window(&user_id, new_reset, is_tracking)
        {
            Ok(count) => {
                usage = Usage {
                    count,
                    reset_at: Some(new_reset),
                }
            }
            Err(e) => return db_err(state, "Usage tracking error", &e),
        }
    } else if is_tracking {
        // The limit is enforced inside the UPDATE, so concurrent requests
        // cannot both be admitted at the boundary.
        match state.pool.consume_usage(&user_id, limit) {
            Ok(Some(count)) => usage.count = count,
            Ok(None) => return usage_limit_reached(limit),
            Err(e) => return db_err(state, "Usage tracking error", &e),
        }
    }
    let remaining = (limit - usage.count).max(0);
    let mut m = BTreeMap::new();
    m.insert("remaining".into(), json::i(remaining));
    m.insert("total".into(), json::i(limit));
    m.insert("isSubscriber".into(), Json::Bool(false));
    m.insert("used".into(), json::i(usage.count));
    m.insert(
        "subscription".into(),
        match &user.subscription {
            Some(sub) => {
                let mut sm = BTreeMap::new();
                sm.insert("status".into(), Json::Str(sub.status.clone()));
                sm.insert("expiresAt".into(), sub_expires_iso(sub));
                Json::Obj(sm)
            }
            None => Json::Null,
        },
    );
    json_res(200, &Json::Obj(m))
}

fn checkout(state: &AppState, req: &Request) -> Response {
    let user_id = match require_auth(state, req) {
        Ok(id) => id,
        Err(r) => return r,
    };
    if let Err(res) = require_csrf(state, req, &user_id) {
        return res;
    }
    let Some(stripe) = state.stripe.as_ref() else {
        return err_json(503, "Stripe is not configured");
    };
    let body = match json::parse(&req.body) {
        Ok(v) => v,
        Err(e) => {
            state
                .log
                .error("Checkout session error", &[("error", json::s(e.to_string()))]);
            return err_json(500, "Stripe session failed");
        }
    };
    let (Some(email), Some(lookup_key)) = (body.get_str("email"), body.get_str("lookup_key")) else {
        return err_json(400, "Missing email or lookup_key");
    };
    if !state
        .stripe_lookup_keys
        .iter()
        .any(|allowed| allowed == lookup_key)
    {
        return err_json(400, "Unknown lookup_key");
    };
    let user = match state.pool.find_user(&UserQuery::Id(user_id)) {
        Ok(u) => u,
        Err(e) => {
            state
                .log
                .error("Checkout session error", &[("error", json::s(e.to_string()))]);
            return err_json(500, "Stripe session failed");
        }
    };
    if user.as_ref().map(|u| u.email.as_str()) != Some(email) {
        return err_json(403, "Email mismatch");
    }
    let price_id = match stripe.price_id_for_lookup_key(lookup_key) {
        Ok(Some(id)) => id,
        Ok(None) => {
            return err_json(400, &format!("No price found for lookup_key: {lookup_key}"))
        }
        Err(e) => return stripe_err(state, "Checkout session error", e),
    };
    let origin = state.redirect_origin(req.header("origin"));
    let app_name = AppState::app_name();
    let success = format!("{origin}/app/payment?success=true");
    let cancel = format!("{origin}/app/payment?canceled=true");
    match stripe.create_checkout_session(OwnedCheckoutParams {
        customer_email: email.to_string(),
        price_id,
        success_url: success,
        cancel_url: cancel,
        app_name,
        idempotency_key: None,
    }) {
        Ok(session) => json_res(
            200,
            &json::obj([
                ("url", session.url.map(json::s).unwrap_or(Json::Null)),
                ("id", json::s(session.id)),
                (
                    "customerID",
                    session.customer.map(json::s).unwrap_or(Json::Null),
                ),
            ]),
        ),
        Err(e) => stripe_err(state, "Checkout session error", e),
    }
}

fn portal(state: &AppState, req: &Request) -> Response {
    let user_id = match require_auth(state, req) {
        Ok(id) => id,
        Err(r) => return r,
    };
    if let Err(res) = require_csrf(state, req, &user_id) {
        return res;
    }
    let Some(stripe) = state.stripe.as_ref() else {
        return err_json(503, "Stripe is not configured");
    };
    let body = match json::parse(&req.body) {
        Ok(v) => v,
        Err(e) => {
            state
                .log
                .error("Portal session error", &[("error", json::s(e.to_string()))]);
            return err_json(500, "Stripe portal failed");
        }
    };
    let Some(customer_id) = body.get_str("customerID") else {
        return err_json(400, "Missing customerID");
    };
    let user = match state.pool.find_user(&UserQuery::Id(user_id)) {
        Ok(u) => u,
        Err(e) => {
            state
                .log
                .error("Portal session error", &[("error", json::s(e.to_string()))]);
            return err_json(500, "Stripe portal failed");
        }
    };
    // The caller may only manage the Stripe customer recorded against their own
    // account. Anything else — no user, no subscription, a blank stored id, or a
    // mismatch — is refused. Defaulting to "allow" when the account has no
    // subscription would let any signed-in user open a billing portal for an
    // arbitrary customer id and read or cancel someone else's subscription.
    let stored_id = user
        .as_ref()
        .and_then(|u| u.subscription.as_ref())
        .map(|s| s.stripe_id.as_str())
        .filter(|id| !id.is_empty());
    let authorized = stored_id
        .is_some_and(|id| ct_eq(id.as_bytes(), customer_id.as_bytes()));
    if !authorized {
        state.log.warn(
            "Portal denied - customerID does not match the caller's subscription",
            &[("path", json::s(req.path.clone()))],
        );
        return err_json(403, "Unauthorized customerID");
    }
    let origin = state.redirect_origin(req.header("origin"));
    let return_url = format!("{origin}/app/payment?portal=return");
    match stripe.create_portal_session(customer_id, &return_url) {
        Ok(session) => json_res(
            200,
            &json::obj([
                ("url", session.url.map(json::s).unwrap_or(Json::Null)),
                ("id", json::s(session.id)),
            ]),
        ),
        Err(e) => stripe_err(state, "Portal session error", e),
    }
}

fn period_end(obj: &Json) -> Option<i64> {
    obj.get_i64("current_period_end").or_else(|| {
        obj.get("items")
            .and_then(Json::as_obj)
            .and_then(|m| m.get("data"))
            .and_then(Json::as_arr)
            .and_then(|d| d.first())
            .and_then(|item| item.get_i64("current_period_end"))
    })
}

fn apply_sub_patch(state: &AppState, email: &str, sub: &Subscription) -> bool {
    match state.pool.find_user(&UserQuery::Email(email.to_string())) {
        Ok(Some(u)) => match state.pool.update_user_subscription(&u.id, sub) {
            Ok(_) => true,
            Err(e) => {
                state
                    .log
                    .error("Webhook processing error", &[("error", json::s(e.to_string()))]);
                false
            }
        },
        Ok(None) => {
            state
                .log
                .warn("Webhook: No user found for email", &[("email", json::s(redact_email(email)))]);
            false
        }
        Err(e) => {
            state
                .log
                .error("Webhook processing error", &[("error", json::s(e.to_string()))]);
            false
        }
    }
}

/// Mask an email address for logging.
///
/// Webhook logs are verbose, shipped off-host, and retained far longer than the
/// request that produced them, so writing full addresses turns the log into a
/// copy of the customer list. Keeping the first character and the domain leaves
/// enough to match a support report against a log line without storing the
/// address itself. Anything without an `@` is dropped entirely rather than
/// guessed at.
fn redact_email(email: &str) -> String {
    let Some((local, domain)) = email.split_once('@') else {
        return "[redacted]".to_string();
    };
    match local.chars().next() {
        Some(first) => format!("{first}***@{domain}"),
        None => format!("***@{domain}"),
    }
}

fn build_sub_patch(stripe_id: &str, stripe_sub: &Json) -> Subscription {
    Subscription {
        stripe_id: stripe_id.to_string(),
        expires: period_end(stripe_sub),
        status: stripe_sub.get_str("status").unwrap_or("").to_string(),
    }
}

fn payment(state: &AppState, req: &Request) -> Response {
    state.log.info("Payment webhook received", &[]);
    if state.stripe.is_none() {
        return err_json(503, "Stripe is not configured");
    }
    let Some(signature) = req.header("stripe-signature") else {
        return err_json(400, "Missing signature");
    };
    let Some(secret) = state.stripe_endpoint_secret.as_deref() else {
        return err_json(503, "Stripe is not configured");
    };
    let event = match stripe::construct_event(
        &req.body,
        signature,
        secret,
        stripe::DEFAULT_WEBHOOK_TOLERANCE_SECS,
    ) {
        Ok(v) => v,
        Err(e) => {
            state.log.error(
                "Webhook signature verification failed",
                &[("error", json::s(e.to_string()))],
            );
            return Response::empty(400);
        }
    };
    state.log.debug(
        "Webhook event received",
        &[("type", json::s(event.get_str("type").unwrap_or("").to_string()))],
    );
    let Some(event_id) = event.get_str("id").map(str::to_string) else {
        return Response::empty(400);
    };
    let event_type = event.get_str("type").unwrap_or("").to_string();
    match state.pool.find_webhook_event(&event_id) {
        Ok(Some(_)) => {
            state.log.info(
                "Webhook event already processed, skipping",
                &[("eventId", json::s(event_id))],
            );
            return Response::empty(200);
        }
        Ok(None) => {}
        Err(e) => {
            state
                .log
                .error("Webhook processing error", &[("error", json::s(e.to_string()))]);
            return Response::empty(500);
        }
    }
    let obj = event
        .get("data")
        .and_then(|d| d.get("object"))
        .cloned()
        .unwrap_or(json::obj([]));
    if let Err(e) = process_webhook(state, &event_id, &event_type, &obj) {
        return e;
    }
    // Recorded only after the effect has been applied, so the record can never
    // claim an event was handled when it was not. Recording first and deleting
    // on failure only covers a returned error: a crash, timeout, or kill
    // between the insert and the update would leave the event marked as
    // processed forever, and the retry Stripe sends would be skipped.
    //
    // This ordering trades that for the possibility of applying an event twice,
    // which is safe here because every write these handlers perform sets
    // subscription columns to absolute values read from Stripe rather than
    // mutating them relative to what is already stored.
    if let Err(e) = state
        .pool
        .insert_webhook_event(&event_id, &event_type, config::now_ms())
    {
        // The effect is already applied. Asking Stripe to retry would only
        // repeat idempotent work, so acknowledge and keep the error visible.
        state.log.error(
            "Applied webhook event but failed to record it - a retry would be reprocessed",
            &[
                ("eventId", json::s(event_id)),
                ("error", json::s(e.to_string())),
            ],
        );
    }
    Response::empty(200)
}

fn process_webhook(
    state: &AppState,
    event_id: &str,
    event_type: &str,
    obj: &Json,
) -> Result<(), Response> {
    let stripe = state.stripe.as_ref();
    if matches!(
        event_type,
        "customer.subscription.deleted"
            | "customer.subscription.updated"
            | "customer.subscription.created"
    ) {
        let Some(stripe_id) = obj.get_str("customer") else {
            state
                .log
                .error("Webhook missing customer ID", &[("type", json::s(event_type))]);
            return Err(Response::empty(400));
        };
        let email = match resolve_customer_email(state, stripe_id) {
            Ok(Some(e)) => e,
            Ok(None) => return Err(Response::empty(400)),
            Err(_) => return Err(Response::empty(400)),
        };
        if period_end(obj).is_none() {
            state.log.error(
                "Webhook: subscription event has no current_period_end",
                &[
                    ("type", json::s(event_type)),
                    ("eventId", json::s(event_id)),
                ],
            );
        }
        let sub = Subscription {
            stripe_id: stripe_id.to_string(),
            expires: period_end(obj),
            status: obj.get_str("status").unwrap_or("").to_string(),
        };
        if apply_sub_patch(state, &email, &sub) {
            state.log.info(
                "Subscription updated",
                &[
                    ("type", json::s(event_type)),
                    ("email", json::s(redact_email(&email))),
                    ("status", json::s(sub.status)),
                ],
            );
        }
    }
    if event_type == "checkout.session.completed" {
        let stripe_id = obj.get_str("customer");
        let subscription_id = obj.get_str("subscription");
        if let (Some(stripe), Some(stripe_id), Some(subscription_id)) =
            (stripe, stripe_id, subscription_id)
        {
            let sub_json = match stripe.retrieve_subscription(subscription_id) {
                Ok(v) => v,
                Err(e) => {
                    state
                        .log
                        .error("Webhook processing error", &[("error", json::s(e.to_string()))]);
                    return Err(Response::empty(500));
                }
            };
            let email = if let Some(e) = obj.get_str("customer_email") {
                e.to_lowercase()
            } else {
                match resolve_customer_email(state, stripe_id) {
                    Ok(Some(e)) => e,
                    Ok(None) => return Ok(()),
                    Err(_) => return Err(Response::empty(500)),
                }
            };
            let patch = build_sub_patch(stripe_id, &sub_json);
            if apply_sub_patch(state, &email, &patch) {
                state.log.info(
                    "Checkout completed",
                    &[
                        ("email", json::s(redact_email(&email))),
                        ("status", json::s(patch.status)),
                    ],
                );
            }
        }
    }
    if event_type == "invoice.paid" {
        let stripe_id = obj.get_str("customer");
        let subscription_id = obj.get_str("subscription").or_else(|| {
            obj.get("parent")
                .and_then(|p| p.get("subscription_details"))
                .and_then(|d| d.get_str("subscription"))
        });
        if let (Some(stripe), Some(stripe_id), Some(subscription_id)) =
            (stripe, stripe_id, subscription_id)
        {
            let sub_json = match stripe.retrieve_subscription(subscription_id) {
                Ok(v) => v,
                Err(e) => {
                    state
                        .log
                        .error("Webhook processing error", &[("error", json::s(e.to_string()))]);
                    return Err(Response::empty(500));
                }
            };
            let email = match resolve_customer_email(state, stripe_id) {
                Ok(Some(e)) => e,
                Ok(None) => return Ok(()),
                Err(_) => return Err(Response::empty(500)),
            };
            let patch = build_sub_patch(stripe_id, &sub_json);
            if apply_sub_patch(state, &email, &patch) {
                state.log.info("Invoice paid", &[("email", json::s(redact_email(&email)))]);
            }
        }
    }
    if event_type == "invoice.payment_failed" {
        if let Some(stripe_id) = obj.get_str("customer") {
            if let Ok(Some(email)) = resolve_customer_email(state, stripe_id) {
                // yagni: SQLite has no paymentFailed columns; Node's dotted $set
                // is a no-op on this adapter. Log the same as Node when a user
                // exists. Add columns if billing UX needs the flag.
                match state.pool.find_user(&UserQuery::Email(email.clone())) {
                    Ok(Some(_)) => {
                        state
                            .log
                            .warn("Invoice payment failed", &[("email", json::s(redact_email(&email)))]);
                    }
                    Ok(None) => {
                        state.log.warn(
                            "Webhook: No user found for email",
                            &[("email", json::s(redact_email(&email)))],
                        );
                    }
                    Err(e) => {
                        state.log.error(
                            "Webhook processing error",
                            &[("error", json::s(e.to_string()))],
                        );
                        return Err(Response::empty(500));
                    }
                }
            }
        }
    }
    Ok(())
}

fn resolve_customer_email(state: &AppState, stripe_id: &str) -> Result<Option<String>, ()> {
    let Some(stripe) = state.stripe.as_ref() else {
        state
            .log
            .warn("Webhook: Stripe not configured", &[("stripeID", json::s(stripe_id))]);
        return Ok(None);
    };
    match stripe.customer_email(stripe_id) {
        Ok(Some(e)) => Ok(Some(e)),
        Ok(None) => {
            state
                .log
                .warn("Webhook: Customer has no email", &[("stripeID", json::s(stripe_id))]);
            Ok(None)
        }
        Err(e) => {
            state
                .log
                .error("Webhook processing error", &[("error", json::s(e.to_string()))]);
            Err(())
        }
    }
}

fn has_extension(path: &str) -> bool {
    path.rsplit('/')
        .next()
        .and_then(|s| s.rsplit_once('.'))
        .map(|(_, ext)| !ext.is_empty() && ext.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(false)
}

fn static_or_spa(state: &AppState, req: &Request) -> Response {
    if let Some(res) = crate::http::serve_file(&state.static_dir, &req.path) {
        return res;
    }
    if req.path.starts_with("/api/") || has_extension(&req.path) {
        return not_found();
    }
    // `/:username` is registered ahead of the SPA catch-all. A missing
    // index.html is 404 text, the same as the Node handler.
    if let Some(name) = og_username(&req.path) {
        return x_profile_html(state, req, name);
    }
    spa_fallback(state)
}

/// Production-only cache of `index.html`, which never changes while the process runs.
static INDEX_HTML: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();

/// Read `index.html` from the static directory.
///
/// In production the file is read once and kept in memory — every client-side route
/// lands here, so re-reading it per request is pure syscall overhead. Development
/// reads from disk each time so a rebuild shows up without restarting the server.
fn read_index(state: &AppState) -> Option<String> {
    let read_index = || {
        std::fs::read(state.static_dir.join("index.html"))
            .ok()
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
    };
    if state.prod {
        INDEX_HTML.get_or_init(read_index).clone()
    } else {
        read_index()
    }
}

/// Serve the SPA shell for any non-API path.
fn spa_fallback(state: &AppState) -> Response {
    match read_index(state) {
        Some(body) => Response::html(200, &body),
        None => Response::text(200, "Welcome to Skateboard API"),
    }
}

/// Drop expired CSRF tokens. Called from the hourly cleanup thread.
pub fn run_csrf_cleanup(state: &AppState) {
    let cleaned = state.csrf.cleanup(config::now_ms());
    if cleaned > 0 {
        state.log.debug(
            "CSRF cleanup completed",
            &[("removedTokens", json::i(cleaned as i64))],
        );
    }
}

/// Days a processed Stripe webhook id is remembered for replay protection.
/// Stripe stops retrying an event after ~3 days, so 30 is generous.
const WEBHOOK_RETENTION_DAYS: i64 = 30;

/// Drop webhook records past [`WEBHOOK_RETENTION_DAYS`]. Called from the hourly thread.
pub fn run_webhook_cleanup(state: &AppState) {
    let cutoff = config::now_ms() - WEBHOOK_RETENTION_DAYS * 24 * 60 * 60 * 1000;
    match state.pool.prune_webhook_events(cutoff) {
        Ok(removed) if removed > 0 => state
            .log
            .debug("Webhook cleanup completed", &[("removedEvents", json::i(removed))]),
        Ok(_) => {}
        Err(e) => state
            .log
            .error("Webhook cleanup failed", &[("error", json::s(e.to_string()))]),
    }
}

/// Drop expired lockout and auth-rate entries. Called from the 15-minute cleanup thread.
pub fn run_lockout_cleanup(state: &AppState) {
    let now = config::now_ms();
    let cleaned = state.lockout.cleanup(now);
    if cleaned > 0 {
        state.log.debug(
            "Lockout cleanup completed",
            &[("removedEntries", json::i(cleaned as i64))],
        );
    }
    let rate_cleaned = state.auth_rate.cleanup(now);
    if rate_cleaned > 0 {
        state.log.debug(
            "Auth rate-limit cleanup completed",
            &[("removedEntries", json::i(rate_cleaned as i64))],
        );
    }
}

/// Client IP used for auth rate limiting and lockout keys.
///
/// Transport `peer_ip` by default. `TRUST_PROXY` is the number of reverse
/// proxies in front of this process (`TRUST_PROXY=1` for a single proxy such as
/// Railway); set it only when every one of those hops is trusted.
///
/// Proxies **append** to `X-Forwarded-For`, so the leftmost entry is whatever
/// the client sent and must never be trusted — rotating it would mint a fresh
/// rate-limit and lockout bucket per request. Index `hops` from the right
/// instead: with one trusted proxy that is the address it observed.
///
/// Falls back to `peer_ip` when the header is absent or carries fewer entries
/// than `hops` (a spoofed-short chain then shares the proxy's bucket rather
/// than escaping into one of its own).
fn client_ip(req: &Request) -> String {
    let hops = config::env("TRUST_PROXY")
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    if hops > 0 {
        if let Some(xff) = req.header("x-forwarded-for") {
            let chain: Vec<&str> = xff
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .collect();
            if let Some(ip) = chain.len().checked_sub(hops).and_then(|i| chain.get(i)) {
                return (*ip).to_string();
            }
        }
    }
    req.peer_ip.clone()
}

// ==== X PROFILE / QR ====

/// One week. Matches the Node `PROFILE_CACHE_TTL`.
const PROFILE_CACHE_TTL_MS: i64 = 7 * 24 * 60 * 60 * 1000;
/// One hour. Matches the Node `SCREENSHOT_CACHE_TTL`.
const SCREENSHOT_CACHE_TTL_MS: i64 = 60 * 60 * 1000;
/// X API attempts: the first call plus three retries (1s, 2s, 4s).
const X_API_ATTEMPTS: u32 = 4;

/// `true` when `name` is a legal X username (1–15 letters, digits, underscore).
fn is_x_username(name: &str) -> bool {
    (1..=15).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Strip one leading `@`, trim, and lowercase. `None` when the result is not a username.
fn clean_username(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_start_matches('@').trim().to_lowercase();
    if is_x_username(&trimmed) {
        Some(trimmed)
    } else {
        None
    }
}

/// Non-empty path segments.
fn segments(path: &str) -> Vec<&str> {
    path.split('/').filter(|s| !s.is_empty()).collect()
}

/// Username from `GET /qr/:username/image`, if the path has that shape.
fn qr_username(path: &str) -> Option<&str> {
    let segs = segments(path);
    match segs.as_slice() {
        ["qr", name, "image"] => Some(*name),
        _ => None,
    }
}

/// Id from `GET /images/:id`, if the path has that shape.
fn image_id(path: &str) -> Option<&str> {
    let segs = segments(path);
    match segs.as_slice() {
        ["images", id] => Some(*id),
        _ => None,
    }
}

/// Username from `GET /user/:username`, if the path has that shape.
fn user_username(path: &str) -> Option<&str> {
    let segs = segments(path);
    match segs.as_slice() {
        ["user", name] => Some(*name),
        _ => None,
    }
}

/// Single path segment that is a legal X username, for the OG `/:username` route.
fn og_username(path: &str) -> Option<&str> {
    let segs = segments(path);
    match segs.as_slice() {
        [name] if is_x_username(name) => Some(*name),
        _ => None,
    }
}

/// `true` when `id` can be a cache filename stem. Rejects dots and slashes.
fn is_image_id(id: &str) -> bool {
    !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Constant-time check of `?key=` against `ADMIN_SECRET`. Missing secret is a denial.
fn admin_ok(state: &AppState, req: &Request) -> bool {
    let Some(secret) = state.admin_secret.as_deref() else {
        return false;
    };
    let Some(key) = req.query_param("key") else {
        return false;
    };
    crypto::ct_eq(secret.as_bytes(), key.as_bytes())
}

/// JavaScript `parseInt`: leading integer, trailing junk ignored, `None` for NaN.
fn js_parse_int(raw: &str) -> Option<i64> {
    let s = raw.trim();
    let (sign, rest) = if let Some(rest) = s.strip_prefix('-') {
        (-1, rest)
    } else if let Some(rest) = s.strip_prefix('+') {
        (1, rest)
    } else {
        (1, s)
    };
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse::<i64>().ok().map(|n| n.saturating_mul(sign))
}

/// JavaScript `parseFloat` for a leading decimal. `None` when the text is NaN.
fn js_parse_f64(raw: &str) -> Option<f64> {
    let s = raw.trim();
    let (sign, rest) = if let Some(rest) = s.strip_prefix('-') {
        (-1.0, rest)
    } else if let Some(rest) = s.strip_prefix('+') {
        (1.0, rest)
    } else {
        (1.0, s)
    };
    let bytes = rest.as_bytes();
    let mut end = 0;
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }
    let mut saw_digit = end > 0;
    if end < bytes.len() && bytes[end] == b'.' {
        end += 1;
        let frac = end;
        while end < bytes.len() && bytes[end].is_ascii_digit() {
            end += 1;
        }
        saw_digit = saw_digit || end > frac;
    }
    if !saw_digit {
        return None;
    }
    rest[..end].parse::<f64>().ok().map(|n| n * sign)
}

/// `Math.min(parseInt(limit || "100"), 1000)`. `Err` is JavaScript NaN.
fn lookup_limit(req: &Request) -> Result<i64, ()> {
    let raw = req.query_param("limit").unwrap_or_else(|| "100".into());
    let n = js_parse_int(&raw).ok_or(())?;
    Ok(n.min(1000))
}

/// Client address for X lookup logs and the daily API cap.
///
/// The Node handler takes the rightmost `X-Forwarded-For` entry and otherwise
/// the literal `unknown`. It does not use the socket peer.
fn x_client_ip(req: &Request) -> String {
    if let Some(forwarded) = req.header("x-forwarded-for") {
        if !forwarded.is_empty() {
            let last = forwarded.split(',').next_back().unwrap_or("").trim();
            return last.to_string();
        }
    }
    "unknown".to_string()
}

/// `DISABLE_RATE_LIMIT=true` skips the daily X API cap, read on each miss.
fn x_rate_disabled(state: &AppState) -> bool {
    state.disable_x_rate_limit || config::env("DISABLE_RATE_LIMIT").as_deref() == Some("true")
}

/// Recent profile lookups. Requires `ADMIN_SECRET` in `?key=`.
fn x_lookups(state: &AppState, req: &Request) -> Response {
    if !admin_ok(state, req) {
        return err_json(401, "Unauthorized");
    }
    let limit = match lookup_limit(req) {
        Ok(limit) => limit,
        Err(()) => return err_json(500, "Internal server error"),
    };
    let rows = match state.pool.get_profile_lookups(limit) {
        Ok(rows) => rows,
        Err(e) => {
            state
                .log
                .error("Lookup list failed", &[("error", json::s(e.to_string()))]);
            return err_json(500, "Failed to load lookups");
        }
    };
    let lookups: Vec<Json> = rows
        .iter()
        .map(|row| {
            let mut m = BTreeMap::new();
            m.insert("id".into(), json::i(row.id));
            m.insert("username".into(), json::s(row.username.clone()));
            m.insert(
                "ip".into(),
                row.ip.clone().map(json::s).unwrap_or(Json::Null),
            );
            m.insert("source".into(), json::s(row.source.clone()));
            m.insert("looked_up_at".into(), json::i(row.looked_up_at));
            Json::Obj(m)
        })
        .collect();
    let mut body = BTreeMap::new();
    body.insert("count".into(), json::i(lookups.len() as i64));
    body.insert("lookups".into(), Json::Arr(lookups));
    json_res(200, &Json::Obj(body))
}

/// Delete on-disk avatar files and every cached profile. Screenshot rows stay.
fn x_clear_cache(state: &AppState, req: &Request) -> Response {
    if !admin_ok(state, req) {
        return err_json(401, "Unauthorized");
    }
    let images = match clear_disk_files(&state.cache_dir) {
        Ok(n) => n,
        Err(e) => {
            state
                .log
                .error("Cache clear failed", &[("error", json::s(e))]);
            return err_json(500, "Failed to clear cache");
        }
    };
    let profiles = match state.pool.clear_all_profiles() {
        Ok(n) => n,
        Err(e) => {
            state
                .log
                .error("Cache clear failed", &[("error", json::s(e.to_string()))]);
            return err_json(500, "Failed to clear cache");
        }
    };
    state.log.info(
        "Caches cleared",
        &[("images", json::i(images)), ("profiles", json::i(profiles))],
    );
    json_res(
        200,
        &json::obj([
            ("browser", json::s("reset")),
            ("images", json::i(images)),
            ("profiles", json::i(profiles)),
        ]),
    )
}

/// Delete every directory entry, matching `readdir` + `unlink`.
///
/// A subdirectory makes `unlink` fail and the route answers 500, same as Node.
/// The success count is the number of entries, not a filtered file count.
fn clear_disk_files(dir: &std::path::Path) -> Result<i64, String> {
    let entries = std::fs::read_dir(dir).map_err(|e| e.to_string())?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        paths.push(entry.path());
    }
    let count = paths.len() as i64;
    for path in paths {
        std::fs::remove_file(&path).map_err(|e| e.to_string())?;
    }
    Ok(count)
}

/// Serve a cached avatar or banner. Jpeg is preferred when both extensions exist.
fn x_profile_image(state: &AppState, req: &Request) -> Response {
    let Some(id) = image_id(&req.path) else {
        return err_json(400, "Invalid image id");
    };
    if !is_image_id(id) {
        return err_json(400, "Invalid image id");
    }
    let jpg = state.cache_dir.join(format!("{id}.jpg"));
    let png = state.cache_dir.join(format!("{id}.png"));
    let (path, content_type) = if jpg.is_file() {
        (jpg, "image/jpeg")
    } else if png.is_file() {
        (png, "image/png")
    } else {
        return err_json(404, "Image not found");
    };
    match std::fs::read(&path) {
        Ok(buf) => Response::bytes(200, content_type, buf).header("Cache-Control", "no-store"),
        Err(e) => {
            state
                .log
                .error("Image serve error", &[("error", json::s(e.to_string()))]);
            err_json(500, "Failed to serve image")
        }
    }
}

/// GET with backoff on 429 and 5xx. Transport errors retry the same way.
///
/// Delays are 1s, then 2s, then 4s, and then the last response is returned.
/// `retries` is the number of extra attempts after the first call.
fn http_get_backoff(
    url: &str,
    headers: &[(&str, &str)],
    timeout_ms: i64,
    retries: u32,
) -> Result<crate::httpc::HttpResponse, crate::httpc::HttpError> {
    let mut delay_s = 1u64;
    let attempts = retries.saturating_add(1);
    let mut last_err = None;
    for attempt in 0..attempts {
        match crate::httpc::get(url, headers, timeout_ms) {
            Ok(res) if res.status != 429 && res.status < 500 => return Ok(res),
            Ok(res) if attempt + 1 == attempts => return Ok(res),
            Ok(_) => {}
            Err(e) if attempt + 1 == attempts => return Err(e),
            Err(e) => last_err = Some(e),
        }
        std::thread::sleep(std::time::Duration::from_secs(delay_s));
        delay_s = delay_s.saturating_mul(2);
    }
    Err(last_err.unwrap_or_else(|| crate::httpc::HttpError("request failed".into())))
}

/// `true` only for `https://pbs.twimg.com` and `https://abs.twimg.com` with no port or userinfo.
fn is_x_cdn_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    host == "pbs.twimg.com" || host == "abs.twimg.com"
}

/// Download one allowlisted image into `cache/{id}.jpg` or `.png`. Failures are logged.
fn cache_remote_image(state: &AppState, image_url: Option<&str>, cache_id: &str) {
    let Some(image_url) = image_url.filter(|url| !url.is_empty()) else {
        return;
    };
    if !is_x_cdn_url(image_url) {
        state.log.warn(
            "Blocked image fetch to non-X domain",
            &[("url", json::s(image_url))],
        );
        return;
    }
    let res = match http_get_backoff(image_url, &[], 10_000, 1) {
        Ok(res) if res.ok() && !res.body.is_empty() => res,
        Ok(_) => return,
        Err(e) => {
            state.log.error(
                "Failed to cache image",
                &[
                    ("cacheId", json::s(cache_id)),
                    ("error", json::s(e.to_string())),
                ],
            );
            return;
        }
    };
    let ext = if res.body.starts_with(b"\x89PNG\r\n\x1a\n") {
        "png"
    } else {
        "jpg"
    };
    let other = if ext == "png" { "jpg" } else { "png" };
    let path = state.cache_dir.join(format!("{cache_id}.{ext}"));
    let _ = std::fs::remove_file(state.cache_dir.join(format!("{cache_id}.{other}")));
    if let Err(e) = std::fs::write(&path, &res.body) {
        state.log.error(
            "Failed to cache image",
            &[
                ("cacheId", json::s(cache_id)),
                ("error", json::s(e.to_string())),
            ],
        );
    }
}

/// Replace t.co links in a bio with the display URL from `entities.description`.
fn expand_description(data: &Json) -> String {
    let mut description = data.get_str("description").unwrap_or("").to_string();
    let urls = data
        .get("entities")
        .and_then(|e| e.get("description"))
        .and_then(|d| d.get("urls"))
        .and_then(|u| u.as_arr())
        .unwrap_or(&[]);
    for info in urls {
        let Some(short) = info.get_str("url") else { continue };
        let Some(display) = info.get_str("display_url") else { continue };
        description = description.replace(short, display);
    }
    description
}

/// Build the JSON body `GET /user/:username` returns, from an X API user object.
fn map_x_user(data: &Json, avatar_path: Option<&str>, banner_path: Option<&str>) -> Json {
    let mut m = BTreeMap::new();
    if let Some(id) = data.get_str("id") {
        m.insert("id".into(), json::s(id));
    }
    if let Some(username) = data.get_str("username") {
        m.insert("username".into(), json::s(username));
    }
    if let Some(name) = data.get_str("name") {
        m.insert("name".into(), json::s(name));
    }
    m.insert(
        "profile_image_url".into(),
        avatar_path.map(json::s).unwrap_or(Json::Null),
    );
    m.insert(
        "profile_banner_url".into(),
        banner_path.map(json::s).unwrap_or(Json::Null),
    );
    m.insert("description".into(), json::s(expand_description(data)));
    if let Some(verified) = data.get("verified").and_then(Json::as_bool) {
        m.insert("verified".into(), Json::Bool(verified));
    }
    match data.get("verified_type") {
        Some(Json::Str(v)) => {
            m.insert("verified_type".into(), json::s(v.clone()));
        }
        Some(Json::Null) => {
            m.insert("verified_type".into(), Json::Null);
        }
        _ => {}
    }
    for key in ["location", "created_at"] {
        match data.get(key) {
            Some(Json::Str(v)) => {
                m.insert(key.into(), json::s(v.clone()));
            }
            Some(Json::Null) => {
                m.insert(key.into(), Json::Null);
            }
            _ => {}
        }
    }
    let entity = data
        .get("entities")
        .and_then(|e| e.get("url"))
        .and_then(|u| u.get("urls"))
        .and_then(|a| a.as_arr())
        .and_then(|a| a.first());
    let expanded = entity
        .and_then(|e| e.get_str("expanded_url"))
        .or_else(|| data.get_str("url"));
    m.insert(
        "url".into(),
        expanded.map(json::s).unwrap_or(Json::Null),
    );
    m.insert(
        "display_url".into(),
        entity
            .and_then(|e| e.get_str("display_url"))
            .map(json::s)
            .unwrap_or(Json::Null),
    );
    if let Some(metrics) = data.get("public_metrics") {
        for (src, dest) in [
            ("followers_count", "followers_count"),
            ("following_count", "following_count"),
            ("tweet_count", "tweet_count"),
        ] {
            if let Some(n) = metrics.get(src).and_then(Json::as_i64) {
                m.insert(dest.into(), json::i(n));
            }
        }
    }
    Json::Obj(m)
}

/// Why `GET /user/:username` could not return a profile.
enum XFetch {
    /// X reported that the username does not exist.
    NotFound,
    /// Transport error, 5xx, or a body we could not read.
    Failed,
}

/// Call the X API and cache avatar bytes. The returned string is the response body.
fn fetch_x_profile(state: &AppState, bearer: &str, username: &str) -> Result<String, XFetch> {
    let url = format!(
        "https://api.x.com/2/users/by/username/{username}?user.fields=profile_image_url,profile_banner_url,name,description,verified,verified_type,location,url,created_at,public_metrics,entities"
    );
    let auth = format!("Bearer {bearer}");
    let res = http_get_backoff(
        &url,
        &[("Authorization", auth.as_str())],
        10_000,
        X_API_ATTEMPTS - 1,
    )
    .map_err(|_| XFetch::Failed)?;
    if res.status == 404 {
        return Err(XFetch::NotFound);
    }
    if !res.ok() {
        return Err(XFetch::Failed);
    }
    let parsed = json::parse(&res.body).map_err(|_| XFetch::Failed)?;
    let Some(data) = parsed.get("data") else {
        return Err(XFetch::NotFound);
    };
    if data.is_null() {
        return Err(XFetch::NotFound);
    }
    let avatar_src = data.get_str("profile_image_url");
    let banner_src = data.get_str("profile_banner_url");
    let avatar_id = format!("{username}_avatar");
    let banner_id = format!("{username}_banner");
    let hi_res = avatar_src.map(|url| url.replacen("_normal", "_400x400", 1));
    cache_remote_image(state, hi_res.as_deref(), &avatar_id);
    cache_remote_image(state, banner_src, &banner_id);
    let avatar_path = avatar_src.map(|_| format!("/images/{avatar_id}"));
    let banner_path = banner_src.map(|_| format!("/images/{banner_id}"));
    let body = json::stringify(&map_x_user(data, avatar_path.as_deref(), banner_path.as_deref()));
    Ok(body)
}

/// Fetch an X profile. Cache hits skip the API. Three misses per IP per day.
fn x_user(state: &AppState, req: &Request) -> Response {
    let Some(bearer) = state.x_bearer.clone() else {
        return err_json(503, "X API service unavailable");
    };
    let Some(raw) = user_username(&req.path) else {
        return err_json(400, "Invalid username");
    };
    let Some(clean) = clean_username(raw) else {
        return err_json(400, "Invalid username format");
    };
    let ip = x_client_ip(req);
    let logged_ip = if ip.is_empty() { None } else { Some(ip.as_str()) };
    let _ = state
        .pool
        .log_profile_lookup(&clean, logged_ip, "api", config::now_ms());
    let refresh = req.query_param("refresh").as_deref() == Some("1");
    if !refresh {
        match state.pool.get_cached_profile(&clean) {
            Ok(Some(row)) if config::now_ms() - row.cached_at < PROFILE_CACHE_TTL_MS => {
                return Response::json(200, &row.data);
            }
            Ok(_) => {}
            Err(e) => {
                state
                    .log
                    .error("Profile cache read failed", &[("error", json::s(e.to_string()))]);
                return err_json(500, "Failed to fetch user data");
            }
        }
    }
    if !x_rate_disabled(state) {
        let status = state.x_rate.check_and_record(&ip, config::now_ms());
        if status.limited {
            state
                .log
                .warn("X API daily limit exceeded", &[("ip", json::s(ip))]);
            return json_res(
                429,
                &json::obj([
                    (
                        "error",
                        json::s(
                            "Daily limit reached. Try again tomorrow or use a previously searched profile.",
                        ),
                    ),
                    ("retryAfter", json::i(status.retry_after_secs)),
                ]),
            );
        }
    }
    match fetch_x_profile(state, &bearer, &clean) {
        Ok(body) => {
            if let Err(e) = state
                .pool
                .set_cached_profile(&clean, &body, config::now_ms())
            {
                state
                    .log
                    .error("Profile cache write failed", &[("error", json::s(e.to_string()))]);
            }
            Response::json(200, &body)
        }
        Err(XFetch::NotFound) => err_json(404, "User not found"),
        Err(XFetch::Failed) => {
            state.log.error(
                "X API error",
                &[("username", json::s(clean))],
            );
            err_json(500, "Failed to fetch user data")
        }
    }
}

/// Wallpaper dimensions accepted by the screenshot route.
fn dims_ok(width: i64, height: i64, scale: f64) -> bool {
    (100..=1200).contains(&width)
        && (100..=1000).contains(&height)
        && scale.is_finite()
        && (1.0..=4.0).contains(&scale)
}

/// Format a scale the way JavaScript stringifies an integral number (`3`, not `3.0`).
fn js_num(n: f64) -> String {
    if n.fract() == 0.0 && n.is_finite() {
        format!("{}", n as i64)
    } else {
        format!("{n}")
    }
}

/// Chromium binary used for wallpaper screenshots.
///
/// Prefer `/usr/lib/chromium/chromium` over `/usr/bin/chromium`. The latter is
/// a desktop launcher that injects Wayland flags and does not exit from a
/// headless screenshot.
fn browser_bin() -> Option<std::path::PathBuf> {
    for fixed in ["/usr/lib/chromium/chromium", "/usr/lib/chromium/chrome"] {
        let path = std::path::PathBuf::from(fixed);
        if path.is_file() {
            return Some(path);
        }
    }
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        for name in [
            "chromium",
            "chromium-browser",
            "google-chrome",
            "google-chrome-stable",
        ] {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

/// `true` when `url` is `http(s)://localhost` or `127.0.0.1`, any port.
fn is_localhost_http(url: &str) -> bool {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"));
    let Some(rest) = rest else {
        return false;
    };
    let hostport = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = hostport.split(':').next().unwrap_or("");
    host == "localhost" || host == "127.0.0.1"
}

/// Headless Chromium speaking the DevTools pipe protocol.
///
/// File descriptors 3 and 4 are the pipe Chrome documents for
/// `--remote-debugging-pipe`: the browser reads fd 3 and writes fd 4.
/// Messages are NUL-terminated JSON.
struct CdpBrowser {
    child: std::process::Child,
    to_browser: std::fs::File,
    from_browser: std::fs::File,
    buf: Vec<u8>,
    next_id: i64,
}

impl Drop for CdpBrowser {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl CdpBrowser {
    /// Launch Chromium with a fresh profile and a DevTools pipe.
    fn launch(profile: &std::path::Path) -> Result<CdpBrowser, String> {
        let bin = browser_bin().ok_or_else(|| "screenshot browser is not installed".to_string())?;
        let mut read_pair = [0i32; 2];
        let mut write_pair = [0i32; 2];
        // SAFETY: pipe() writes two fresh descriptors into a caller-owned array.
        if unsafe { pipe(read_pair.as_mut_ptr()) } != 0 || unsafe { pipe(write_pair.as_mut_ptr()) } != 0
        {
            return Err("failed to create the DevTools pipe".into());
        }
        let browser_read = read_pair[0];
        let parent_write = read_pair[1];
        let parent_read = write_pair[0];
        let browser_write = write_pair[1];
        let mut cmd = std::process::Command::new(bin);
        cmd.arg("--headless=new")
            .arg("--disable-gpu")
            .arg("--no-sandbox")
            .arg("--disable-dev-shm-usage")
            .arg("--hide-scrollbars")
            .arg("--ozone-platform=headless")
            .arg("--use-angle=swiftshader")
            .arg("--remote-debugging-pipe")
            .arg(format!("--user-data-dir={}", profile.display()))
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        // SAFETY: runs in the forked child before exec. dup2 onto 3 and 4 is
        // the contract Chrome checks before it will speak the pipe protocol.
        // No heap allocation besides the error path, which only runs if dup2 fails.
        unsafe {
            cmd.pre_exec(move || {
                if dup2(browser_read, 3) == -1 || dup2(browser_write, 4) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = match cmd.spawn() {
            Ok(child) => child,
            Err(e) => {
                // SAFETY: spawn failed, so these pipe ends are still owned here.
                unsafe {
                    close(browser_read);
                    close(parent_write);
                    close(parent_read);
                    close(browser_write);
                }
                return Err(e.to_string());
            }
        };
        // SAFETY: these descriptors came from pipe() and are still open. The
        // child inherited them; closing the parent's copies does not close the
        // child's. File takes ownership so Drop closes them.
        unsafe {
            close(browser_read);
            close(browser_write);
            Ok(CdpBrowser {
                child,
                to_browser: std::fs::File::from_raw_fd(parent_write),
                from_browser: std::fs::File::from_raw_fd(parent_read),
                buf: Vec::new(),
                next_id: 0,
            })
        }
    }

    /// One DevTools call. Events with no id are skipped.
    fn call(&mut self, method: &str, params: Option<Json>, session: Option<&str>) -> Result<Json, String> {
        self.next_id += 1;
        let id = self.next_id;
        let mut msg = BTreeMap::new();
        msg.insert("id".into(), json::i(id));
        msg.insert("method".into(), json::s(method));
        if let Some(session) = session {
            msg.insert("sessionId".into(), json::s(session));
        }
        if let Some(params) = params {
            msg.insert("params".into(), params);
        }
        let bytes = json::stringify(&Json::Obj(msg));
        use std::io::Write;
        self.to_browser
            .write_all(bytes.as_bytes())
            .and_then(|_| self.to_browser.write_all(&[0]))
            .and_then(|_| self.to_browser.flush())
            .map_err(|e| e.to_string())?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        loop {
            let message = self.read_message(deadline)?;
            let parsed = json::parse(message.as_bytes()).map_err(|e| e.to_string())?;
            if parsed.get_i64("id") != Some(id) {
                continue;
            }
            if parsed.get("error").is_some() {
                return Err(format!("DevTools {method} failed"));
            }
            return Ok(parsed);
        }
    }

    /// Read one NUL-terminated DevTools message.
    fn read_message(&mut self, deadline: std::time::Instant) -> Result<String, String> {
        use std::io::Read;
        let mut tmp = [0u8; 8192];
        loop {
            if let Some(end) = self.buf.iter().position(|b| *b == 0) {
                let message = String::from_utf8_lossy(&self.buf[..end]).into_owned();
                self.buf.drain(..=end);
                if !message.is_empty() {
                    return Ok(message);
                }
                continue;
            }
            if std::time::Instant::now() >= deadline {
                return Err("DevTools timed out".into());
            }
            let mut wait = PollFd {
                fd: file_fd(&self.from_browser),
                events: POLLIN,
                revents: 0,
            };
            // SAFETY: pollfd describes the live read end of the DevTools pipe.
            let rc = unsafe { poll((&mut wait) as *mut PollFd, 1, 200) };
            if rc < 0 {
                return Err("DevTools poll failed".into());
            }
            if rc == 0 {
                continue;
            }
            let n = self.from_browser.read(&mut tmp).map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("DevTools pipe closed".into());
            }
            self.buf.extend_from_slice(&tmp[..n]);
        }
    }
}

/// `pollfd` layout on Linux, matching `<poll.h>`.
#[repr(C)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

const POLLIN: i16 = 1;

extern "C" {
    fn pipe(fds: *mut i32) -> i32;
    fn dup2(old: i32, new: i32) -> i32;
    fn close(fd: i32) -> i32;
    fn poll(fds: *mut PollFd, nfds: u64, timeout: i32) -> i32;
}

/// Borrow the raw descriptor of a `File` without taking ownership.
fn file_fd(file: &std::fs::File) -> i32 {
    use std::os::unix::io::AsRawFd;
    file.as_raw_fd()
}

/// Screenshot `url` the way Playwright did: viewport, scale, color scheme, then PNG.
///
/// Waits up to 10s for a `canvas` (the QR code) and then 500ms, and still
/// captures if the canvas never appears.
fn capture_screenshot(
    url: &str,
    width: i64,
    height: i64,
    scale: f64,
    theme: &str,
) -> Result<Vec<u8>, String> {
    let dir = std::env::temp_dir().join(format!(
        "xqr-shot-{}-{}",
        std::process::id(),
        config::now_ms()
    ));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let profile = dir.join("profile");
    let mut browser = match CdpBrowser::launch(&profile) {
        Ok(browser) => browser,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(e);
        }
    };
    let png = screenshot_page(&mut browser, url, width, height, scale, theme);
    drop(browser);
    let _ = std::fs::remove_dir_all(&dir);
    png
}

/// Drive one page inside an already-launched browser and return PNG bytes.
fn screenshot_page(
    browser: &mut CdpBrowser,
    url: &str,
    width: i64,
    height: i64,
    scale: f64,
    theme: &str,
) -> Result<Vec<u8>, String> {
    let created = browser.call(
        "Target.createTarget",
        Some(json::obj([("url", json::s(url))])),
        None,
    )?;
    let target = created
        .get("result")
        .and_then(|r| r.get_str("targetId"))
        .ok_or_else(|| "DevTools did not return a target".to_string())?
        .to_string();
    let attached = browser.call(
        "Target.attachToTarget",
        Some(json::obj([
            ("targetId", json::s(&target)),
            ("flatten", Json::Bool(true)),
        ])),
        None,
    )?;
    let session = attached
        .get("result")
        .and_then(|r| r.get_str("sessionId"))
        .ok_or_else(|| "DevTools did not attach".to_string())?
        .to_string();
    let session = session.as_str();
    browser.call(
        "Emulation.setDeviceMetricsOverride",
        Some(json::obj([
            ("width", json::i(width)),
            ("height", json::i(height)),
            ("deviceScaleFactor", Json::Num(scale)),
            ("mobile", Json::Bool(false)),
        ])),
        Some(session),
    )?;
    let mut features = BTreeMap::new();
    features.insert("name".into(), json::s("prefers-color-scheme"));
    features.insert("value".into(), json::s(theme));
    browser.call(
        "Emulation.setEmulatedMedia",
        Some(Json::Obj({
            let mut m = BTreeMap::new();
            m.insert("features".into(), Json::Arr(vec![Json::Obj(features)]));
            m
        })),
        Some(session),
    )?;
    browser.call("Page.enable", None, Some(session))?;
    let wait_until = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::time::Instant::now() < wait_until {
        let ev = browser.call(
            "Runtime.evaluate",
            Some(json::obj([
                ("expression", json::s("!!document.querySelector('canvas')")),
                ("returnByValue", Json::Bool(true)),
            ])),
            Some(session),
        )?;
        let ready = ev
            .get("result")
            .and_then(|r| r.get("result"))
            .and_then(|r| r.get("value"))
            .and_then(Json::as_bool)
            .unwrap_or(false);
        if ready {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let _ = browser.call(
        "Runtime.evaluate",
        Some(json::obj([(
            "expression",
            json::s("document.fonts && document.fonts.ready"),
        )])),
        Some(session),
    );
    std::thread::sleep(std::time::Duration::from_millis(500));
    let shot = browser.call(
        "Page.captureScreenshot",
        Some(json::obj([("format", json::s("png"))])),
        Some(session),
    )?;
    let data = shot
        .get("result")
        .and_then(|r| r.get_str("data"))
        .ok_or_else(|| "DevTools did not return a screenshot".to_string())?;
    let bytes = crate::crypto::base64_decode(data).ok_or_else(|| "screenshot was not base64".to_string())?;
    if !bytes.starts_with(b"\x89PNG") {
        return Err("screenshot was not a PNG".into());
    }
    Ok(bytes)
}

/// PNG response with the same download headers the Node route sent.
fn png_attachment(username: &str, bytes: Vec<u8>) -> Response {
    Response::bytes(200, "image/png", bytes)
        .header(
            "Content-Disposition",
            &format!("attachment; filename=\"{username}-qr.png\""),
        )
        .header("Cache-Control", "no-store")
}

/// Screenshot a cached profile. Refuses to launch a browser for an uncached username.
fn x_qr_image(state: &AppState, req: &Request) -> Response {
    let width = match req.query_param("w") {
        Some(raw) => match js_parse_int(&raw) {
            Some(n) => n,
            None => return err_json(400, "Invalid dimensions"),
        },
        None => 393,
    };
    let height = match req.query_param("h") {
        Some(raw) => match js_parse_int(&raw) {
            Some(n) => n,
            None => return err_json(400, "Invalid dimensions"),
        },
        None => 852,
    };
    let scale = match req.query_param("scale") {
        Some(raw) => match js_parse_f64(&raw) {
            Some(n) => n,
            None => return err_json(400, "Invalid dimensions"),
        },
        None => 3.0,
    };
    if !dims_ok(width, height, scale) {
        return err_json(400, "Invalid dimensions");
    }
    let Some(raw) = qr_username(&req.path) else {
        return err_json(400, "Invalid username format");
    };
    let Some(clean) = clean_username(raw) else {
        return err_json(400, "Invalid username format");
    };
    match state.pool.get_cached_profile(&clean) {
        Ok(None) => return err_json(404, "Profile not cached. View the profile first."),
        Ok(Some(_)) => {}
        Err(e) => {
            state
                .log
                .error("Screenshot profile read failed", &[("error", json::s(e.to_string()))]);
            return err_json(500, "Failed to generate image");
        }
    }
    let theme = if req.query_param("theme").as_deref() == Some("light") {
        "light"
    } else {
        "dark"
    };
    let key = format!("{clean}_{width}x{height}_{}_{theme}", js_num(scale));
    if let Ok(Some(row)) = state.pool.get_cached_image(&key) {
        if config::now_ms() - row.cached_at < SCREENSHOT_CACHE_TTL_MS {
            return png_attachment(&clean, row.image);
        }
    }
    if browser_bin().is_none() {
        return err_json(503, "Screenshot service unavailable");
    }
    let base = if state.prod {
        format!("http://localhost:{}", state.port)
    } else {
        "http://localhost:5173".to_string()
    };
    let target = format!(
        "{base}/app/home?u={clean}&screenshot=1&t={}",
        config::now_ms()
    );
    if !is_localhost_http(&target) {
        state.log.error(
            "Blocked non-localhost screenshot target",
            &[("targetUrl", json::s(&target))],
        );
        return err_json(400, "Invalid target");
    }
    match capture_screenshot(&target, width, height, scale, theme) {
        Ok(png) => {
            let _ = state
                .pool
                .set_cached_image(&key, &png, config::now_ms());
            png_attachment(&clean, png)
        }
        Err(e) => {
            state.log.error(
                "Screenshot failed",
                &[("username", json::s(clean)), ("error", json::s(e))],
            );
            err_json(500, "Failed to generate image")
        }
    }
}

/// Public origin from `Host` and `X-Forwarded-Proto`, for OG image URLs.
fn public_origin(state: &AppState, req: &Request) -> String {
    let host = req.header("host").unwrap_or("localhost");
    let forwarded = req.header("x-forwarded-proto").unwrap_or("");
    let proto = if forwarded == "http" || forwarded == "https" {
        forwarded
    } else if state.prod {
        "https"
    } else {
        "http"
    };
    format!("{proto}://{host}")
}

/// Replace one meta `content` value. `marker` ends at the opening quote of `content`.
fn replace_meta(html: &str, marker: &str, content: &str) -> String {
    let Some(start) = html.find(marker) else {
        return html.to_string();
    };
    let value_at = start + marker.len();
    let Some(end) = html[value_at..].find('"') else {
        return html.to_string();
    };
    let mut out = String::with_capacity(html.len() + content.len());
    out.push_str(&html[..value_at]);
    out.push_str(content);
    out.push_str(&html[value_at + end..]);
    out
}

/// `index.html` with OG and Twitter tags filled from a cached profile, when one exists.
fn x_profile_html(state: &AppState, req: &Request, username: &str) -> Response {
    let Some(mut html) = read_index(state) else {
        return Response::text(404, "Not found");
    };
    let Ok(Some(row)) = state.pool.get_cached_profile(&username.to_lowercase()) else {
        return Response::html(200, &html);
    };
    let Ok(data) = json::parse(row.data.as_bytes()) else {
        return Response::html(200, &html);
    };
    let name = data.get_str("name").unwrap_or(username);
    let handle = data.get_str("username").unwrap_or(username);
    let title = validation::escape_html(&format!("{name} (@{handle})"));
    let desc_raw = data.get_str("description").filter(|d| !d.is_empty());
    let desc = validation::escape_html(
        desc_raw.unwrap_or(&format!("View {name}'s X profile wallpaper")),
    );
    let origin = public_origin(state, req);
    let image = match data.get_str("profile_image_url") {
        Some(path) => format!("{origin}{path}"),
        None => "/icons/icon.png".to_string(),
    };
    let page = if req.query.is_empty() {
        format!("{origin}{}", req.path)
    } else {
        format!("{origin}{}?{}", req.path, req.query)
    };
    let image = validation::escape_html(&image);
    let page = validation::escape_html(&page);
    html = replace_meta(&html, "<meta property=\"og:title\" content=\"", &title);
    html = replace_meta(&html, "<meta property=\"og:description\" content=\"", &desc);
    html = replace_meta(&html, "<meta property=\"og:image\" content=\"", &image);
    html = replace_meta(&html, "<meta property=\"og:url\" content=\"", &page);
    html = replace_meta(&html, "<meta name=\"twitter:title\" content=\"", &title);
    html = replace_meta(&html, "<meta name=\"twitter:description\" content=\"", &desc);
    html = replace_meta(&html, "<meta name=\"twitter:image\" content=\"", &image);
    Response::html(200, &html)
}

/// Drop expired profile rows, screenshot rows, and avatar files. Called daily.
pub fn run_x_cache_cleanup(state: &AppState) {
    let now = config::now_ms();
    match state.pool.clean_expired_profiles(now - PROFILE_CACHE_TTL_MS) {
        Ok(n) if n > 0 => state
            .log
            .debug("Expired profiles purged", &[("count", json::i(n))]),
        Ok(_) => {}
        Err(e) => state
            .log
            .error("Cache cleanup error", &[("error", json::s(e.to_string()))]),
    }
    match state.pool.clean_expired_images(now - SCREENSHOT_CACHE_TTL_MS) {
        Ok(n) if n > 0 => state
            .log
            .debug("Expired screenshots purged", &[("count", json::i(n))]),
        Ok(_) => {}
        Err(e) => state
            .log
            .error("Cache cleanup error", &[("error", json::s(e.to_string()))]),
    }
    clean_expired_disk(state);
}

/// Remove avatar files older than [`PROFILE_CACHE_TTL_MS`].
fn clean_expired_disk(state: &AppState) {
    let Ok(entries) = std::fs::read_dir(&state.cache_dir) else {
        return;
    };
    let mut removed = 0i64;
    for entry in entries.flatten() {
        let Ok(meta) = entry.metadata() else { continue };
        if !meta.is_file() {
            continue;
        }
        let Ok(modified) = meta.modified() else { continue };
        let Ok(age) = modified.elapsed() else { continue };
        if age.as_millis() <= PROFILE_CACHE_TTL_MS as u128 {
            continue;
        }
        if std::fs::remove_file(entry.path()).is_ok() {
            removed += 1;
        }
    }
    if removed > 0 {
        state
            .log
            .debug("Disk cache cleanup", &[("removed", json::i(removed))]);
    }
}

/// Refuse the request when this IP has exhausted the auth sliding window.
fn enforce_auth_rate_limit(state: &AppState, req: &Request) -> Result<(), Response> {
    let ip = client_ip(req);
    let status = state.auth_rate.check_and_record(&ip, config::now_ms());
    if !status.limited {
        return Ok(());
    }
    let body = json::obj([
        ("error", json::s("Too many authentication attempts. Try again later.")),
        ("retryAfter", json::i(status.retry_after_secs)),
    ]);
    Err(json_res(429, &body).header("Retry-After", &status.retry_after_secs.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Logger;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;

    static TEST_DIR_SEQ: AtomicU64 = AtomicU64::new(0);

    /// Tests mutate process env; serialize them so they cannot clobber each other.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn test_state() -> (AppState, std::path::PathBuf) {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        test_state_locked()
    }

    /// Like [`test_state`] but assumes the caller already holds [`ENV_LOCK`].
    fn test_state_locked() -> (AppState, std::path::PathBuf) {
        let n = TEST_DIR_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("sk-rs-{}-{n}", std::process::id()));
        std::fs::create_dir_all(dir.join("databases")).unwrap();
        std::fs::write(
            dir.join("config.json"),
            r#"{"staticDir":"dist","database":{"db":"T","dbType":"sqlite","connectionString":"./databases/T.db"}}"#,
        )
        .unwrap();
        // SAFETY: serialized by ENV_LOCK; tests run with a dedicated dir.
        unsafe {
            std::env::set_var("JWT_SECRET", "test-secret-value-at-least-32-chars!!");
            std::env::remove_var("STRIPE_KEY");
            std::env::remove_var("STRIPE_ENDPOINT_SECRET");
            std::env::remove_var("PORT");
            std::env::remove_var("NODE_ENV");
            std::env::remove_var("ADMIN_SECRET");
            std::env::remove_var("X_BEARER_TOKEN");
            std::env::remove_var("DISABLE_RATE_LIMIT");
        }
        let state = AppState::open_in(&dir, 2, Logger::new(true)).expect("open");
        (state, dir)
    }

    /// Like [`test_state`] but sets extra environment variables before boot.
    ///
    /// The extras are copied into [`AppState`] and then removed, so later tests
    /// do not inherit them.
    fn test_state_with(extra: &[(&str, &str)]) -> (AppState, std::path::PathBuf) {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let n = TEST_DIR_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("sk-rs-{}-{n}", std::process::id()));
        std::fs::create_dir_all(dir.join("databases")).unwrap();
        std::fs::write(
            dir.join("config.json"),
            r#"{"staticDir":"dist","database":{"db":"T","dbType":"sqlite","connectionString":"./databases/T.db"}}"#,
        )
        .unwrap();
        unsafe {
            std::env::set_var("JWT_SECRET", "test-secret-value-at-least-32-chars!!");
            std::env::remove_var("STRIPE_KEY");
            std::env::remove_var("STRIPE_ENDPOINT_SECRET");
            std::env::remove_var("PORT");
            std::env::remove_var("NODE_ENV");
            std::env::remove_var("ADMIN_SECRET");
            std::env::remove_var("X_BEARER_TOKEN");
            std::env::remove_var("DISABLE_RATE_LIMIT");
            for (key, value) in extra {
                std::env::set_var(key, value);
            }
        }
        let state = AppState::open_in(&dir, 2, Logger::new(true)).expect("open");
        unsafe {
            for (key, _) in extra {
                std::env::remove_var(key);
            }
        }
        (state, dir)
    }

    fn json_body(res: &Response) -> Json {
        json::parse(&res.body).expect("json")
    }

    fn cookie_header(req: &mut Request, res: &Response) {
        let cookies: Vec<String> = res
            .headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("Set-Cookie"))
            .map(|(_, v)| v.split(';').next().unwrap_or(v).to_string())
            .collect();
        if !cookies.is_empty() {
            req.set_test_header("cookie", &cookies.join("; "));
        }
        if let Some((_, csrf)) = res.headers.iter().find(|(k, v)| {
            k.eq_ignore_ascii_case("Set-Cookie") && v.starts_with("csrf_token=")
        }) {
            let token = csrf.split('=').nth(1).unwrap_or("").split(';').next().unwrap_or("");
            req.set_test_header("x-csrf-token", token);
        }
    }

    /// Replay the cookies set by `sources`, in order, with later responses
    /// overriding earlier ones by cookie name — so an auth cookie from signup
    /// can be combined with a replacement CSRF cookie from a later response.
    ///
    /// `send_csrf` controls whether the matching `x-csrf-token` header is sent,
    /// which is what separates "client has no token" from "token is stale".
    fn replay_cookies(req: &mut Request, sources: &[&Response], send_csrf: bool) {
        let mut jar: Vec<(String, String)> = Vec::new();
        for res in sources {
            let set_cookies = res
                .headers
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case("Set-Cookie"));
            for (_, value) in set_cookies {
                let pair = value.split(';').next().unwrap_or(value);
                let Some((name, token)) = pair.split_once('=') else {
                    continue;
                };
                jar.retain(|(existing, _)| existing != name);
                jar.push((name.to_string(), token.to_string()));
            }
        }
        if !jar.is_empty() {
            let serialized: Vec<String> =
                jar.iter().map(|(n, v)| format!("{n}={v}")).collect();
            req.set_test_header("cookie", &serialized.join("; "));
        }
        if send_csrf {
            if let Some((_, token)) = jar.iter().find(|(name, _)| name == "csrf_token") {
                req.set_test_header("x-csrf-token", token);
            }
        }
    }

    #[test]
    fn health_ok() {
        let (state, dir) = test_state();
        let res = handle(&state, Request::for_test("GET", "/api/health"));
        assert_eq!(res.status, 200);
        let body = json_body(&res);
        assert_eq!(body.get_str("status"), Some("ok"));
        assert!(body.get_i64("timestamp").is_some());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn signup_rejects_bad_email() {
        let (state, dir) = test_state();
        let mut req = Request::for_test("POST", "/api/signup");
        req.set_test_body(br#"{"email":"nope","password":"secret1","name":"Ada"}"#.to_vec());
        let res = handle(&state, req);
        assert_eq!(res.status, 400);
        assert_eq!(json_body(&res).get_str("error"), Some("Invalid email format or length"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn signup_signin_me_round_trip() {
        let (state, dir) = test_state();
        let mut req = Request::for_test("POST", "/api/signup");
        req.set_test_body(br#"{"email":"Ada@Example.COM","password":"secret1","name":"Ada"}"#.to_vec());
        let res = handle(&state, req);
        assert_eq!(res.status, 201, "{}", String::from_utf8_lossy(&res.body));
        let body = json_body(&res);
        assert_eq!(body.get_str("email"), Some("ada@example.com"));
        assert_eq!(body.get_str("name"), Some("Ada"));

        let mut me = Request::for_test("GET", "/api/me");
        cookie_header(&mut me, &res);
        let me_res = handle(&state, me);
        assert_eq!(me_res.status, 200, "{}", String::from_utf8_lossy(&me_res.body));
        assert_eq!(json_body(&me_res).get_str("email"), Some("ada@example.com"));

        let mut signin = Request::for_test("POST", "/api/signin");
        signin.set_test_body(br#"{"email":"ada@example.com","password":"secret1"}"#.to_vec());
        let si = handle(&state, signin);
        assert_eq!(si.status, 200, "{}", String::from_utf8_lossy(&si.body));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn unknown_api_is_404_text() {
        let (state, dir) = test_state();
        let res = handle(&state, Request::for_test("GET", "/api/nope"));
        assert_eq!(res.status, 404);
        assert_eq!(res.body, b"404 Not Found");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn spa_fallback_without_dist() {
        let (state, dir) = test_state();
        // `/app/home` is two segments, so it is the SPA catch-all rather than `/:username`.
        let res = handle(&state, Request::for_test("GET", "/app/home"));
        assert_eq!(res.status, 200);
        assert_eq!(res.body, b"Welcome to Skateboard API");
        let username = handle(&state, Request::for_test("GET", "/ada"));
        assert_eq!(username.status, 404);
        assert_eq!(username.body, b"Not found");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Sign up, then return the state and the signup response (which carries
    /// the auth cookies and the CSRF token).
    fn signed_up(state: &AppState, email: &str) -> Response {
        let mut req = Request::for_test("POST", "/api/signup");
        req.set_test_body(
            format!(r#"{{"email":"{email}","password":"secret1","name":"P"}}"#).into_bytes(),
        );
        let res = handle(state, req);
        assert_eq!(res.status, 201, "{}", String::from_utf8_lossy(&res.body));
        res
    }

    /// POST `/api/portal` with `customer_id`, carrying the cookies from `signup`.
    fn portal_request(state: &AppState, signup: &Response, customer_id: &str) -> Response {
        let mut req = Request::for_test("POST", "/api/portal");
        cookie_header(&mut req, signup);
        req.set_test_body(format!(r#"{{"customerID":"{customer_id}"}}"#).into_bytes());
        handle(state, req)
    }

    #[test]
    fn redact_email_keeps_only_a_hint_and_the_domain() {
        assert_eq!(redact_email("alice@example.com"), "a***@example.com");
        assert_eq!(redact_email("@example.com"), "***@example.com");
        assert_eq!(redact_email("not-an-email"), "[redacted]");
        assert_eq!(redact_email(""), "[redacted]");
    }

    #[test]
    fn redact_email_never_contains_the_local_part() {
        let redacted = redact_email("verylongname@example.com");
        assert!(!redacted.contains("verylongname"));
        assert!(!redacted.contains("erylongname"));
    }

    #[test]
    fn usage_track_requires_csrf() {
        let (state, dir) = test_state();
        let signup = signed_up(&state, "usage@example.com");
        let mut req = Request::for_test("POST", "/api/usage");
        replay_cookies(&mut req, &[&signup], false);
        req.set_test_body(br#"{"operation":"track"}"#.to_vec());
        let res = handle(&state, req);
        assert_eq!(res.status, 403, "{}", String::from_utf8_lossy(&res.body));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn signout_requires_csrf() {
        let (state, dir) = test_state();
        let signup = signed_up(&state, "out@example.com");
        let mut req = Request::for_test("POST", "/api/signout");
        replay_cookies(&mut req, &[&signup], false);
        let res = handle(&state, req);
        assert_eq!(res.status, 403, "{}", String::from_utf8_lossy(&res.body));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn csrf_store_miss_is_refused_not_auto_accepted() {
        let (state, dir) = test_state();
        let signup = signed_up(&state, "miss@example.com");
        let user_id = state
            .pool
            .find_user(&UserQuery::Email("miss@example.com".into()))
            .expect("query")
            .expect("user")
            .id;
        // Simulates a restart: the cookie and header survive, the store does not.
        state.csrf.remove(&user_id);

        let mut req = Request::for_test("PUT", "/api/me");
        replay_cookies(&mut req, &[&signup], true);
        req.set_test_body(br#"{"name":"Renamed"}"#.to_vec());
        let res = handle(&state, req);
        assert_eq!(
            res.status, 403,
            "a store miss must not accept the request: {}",
            String::from_utf8_lossy(&res.body)
        );
        // The name must be unchanged, proving the mutation did not run.
        let after = state
            .pool
            .find_user(&UserQuery::Id(user_id))
            .expect("query")
            .expect("user");
        assert_eq!(after.name, "P");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn csrf_refusal_issues_a_token_usable_on_retry() {
        let (state, dir) = test_state();
        let signup = signed_up(&state, "retry@example.com");
        let user_id = state
            .pool
            .find_user(&UserQuery::Email("retry@example.com".into()))
            .expect("query")
            .expect("user")
            .id;
        state.csrf.remove(&user_id);

        let mut first = Request::for_test("PUT", "/api/me");
        replay_cookies(&mut first, &[&signup], true);
        first.set_test_body(br#"{"name":"Renamed"}"#.to_vec());
        let refused = handle(&state, first);
        assert_eq!(refused.status, 403);

        // Retry with the replacement token the refusal set.
        let mut second = Request::for_test("PUT", "/api/me");
        replay_cookies(&mut second, &[&signup, &refused], true);
        second.set_test_body(br#"{"name":"Renamed"}"#.to_vec());
        let res = handle(&state, second);
        assert_eq!(res.status, 200, "{}", String::from_utf8_lossy(&res.body));
        assert_eq!(json_body(&res).get_str("name"), Some("Renamed"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn portal_refuses_a_customer_id_the_caller_does_not_own() {
        let (mut state, dir) = test_state();
        // A configured client makes the route reach the authorization check; the
        // check itself is local, so a refusal never touches the network.
        state.stripe = Some(crate::stripe_worker::StripeWorker::spawn(
            crate::stripe::StripeClient::new("sk_test_unused".into()),
        ));
        let signup = signed_up(&state, "noone@example.com");

        // This account has no subscription, so it owns no Stripe customer.
        let res = portal_request(&state, &signup, "cus_someoneElsesCustomer");
        assert_eq!(res.status, 403, "{}", String::from_utf8_lossy(&res.body));
        assert_eq!(json_body(&res).get_str("error"), Some("Unauthorized customerID"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn portal_refuses_a_customer_id_belonging_to_another_subscriber() {
        let (mut state, dir) = test_state();
        state.stripe = Some(crate::stripe_worker::StripeWorker::spawn(
            crate::stripe::StripeClient::new("sk_test_unused".into()),
        ));
        let signup = signed_up(&state, "mine@example.com");

        let user = state
            .pool
            .find_user(&UserQuery::Email("mine@example.com".into()))
            .expect("query")
            .expect("user");
        state
            .pool
            .update_user_subscription(
                &user.id,
                &Subscription {
                    stripe_id: "cus_mine".into(),
                    expires: None,
                    status: "active".into(),
                },
            )
            .expect("set subscription");

        let res = portal_request(&state, &signup, "cus_theirs");
        assert_eq!(res.status, 403, "{}", String::from_utf8_lossy(&res.body));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn put_me_requires_csrf() {
        let (state, dir) = test_state();
        let mut req = Request::for_test("POST", "/api/signup");
        req.set_test_body(br#"{"email":"csrf@example.com","password":"secret1","name":"C"}"#.to_vec());
        let signed = handle(&state, req);
        assert_eq!(signed.status, 201);

        let mut put = Request::for_test("PUT", "/api/me");
        cookie_header(&mut put, &signed);
        // cookie_header also copies x-csrf-token from Set-Cookie; strip it to
        // prove a missing header is rejected.
        put.headers = crate::http::Headers::from_pairs(
            put.headers
                .iter()
                .filter(|(k, _)| !k.eq_ignore_ascii_case("x-csrf-token"))
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        );
        put.set_test_body(br#"{"name":"New"}"#.to_vec());
        let res = handle(&state, put);
        assert_eq!(res.status, 403);
        std::fs::remove_dir_all(&dir).ok();
    }


    #[test]
    fn auth_rate_limit_blocks_after_cap() {
        let (state, dir) = test_state();
        let now = config::now_ms();
        for _ in 0..crate::stores::AUTH_RATE_LIMIT {
            assert!(!state.auth_rate.check_and_record("198.51.100.9", now).limited);
        }
        let mut req = Request::for_test("POST", "/api/signup");
        req.peer_ip = "198.51.100.9".into();
        req.set_test_body(br#"{"email":"overflow@example.com","password":"secret1","name":"R"}"#.to_vec());
        let res = handle(&state, req);
        assert_eq!(res.status, 429);
        assert!(res.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("retry-after")));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn auth_rate_limit_honors_forwarded_for_when_trust_proxy_set() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: ENV_LOCK is held for the whole test so TRUST_PROXY cannot race.
        unsafe {
            std::env::set_var("TRUST_PROXY", "1");
        }
        let (state, dir) = test_state_locked();
        let now = config::now_ms();
        for _ in 0..crate::stores::AUTH_RATE_LIMIT {
            assert!(!state.auth_rate.check_and_record("198.51.100.10", now).limited);
        }
        let mut req = Request::for_test("POST", "/api/signup");
        req.peer_ip = "10.0.0.1".into();
        req.set_test_header("x-forwarded-for", "198.51.100.10");
        req.set_test_body(br#"{"email":"xff-over@example.com","password":"secret1","name":"R"}"#.to_vec());
        assert_eq!(handle(&state, req).status, 429);
        // Different forwarded IP still allowed (socket peer is the same proxy).
        let mut req = Request::for_test("POST", "/api/signup");
        req.peer_ip = "10.0.0.1".into();
        req.set_test_header("x-forwarded-for", "198.51.100.11");
        req.set_test_body(br#"{"email":"xff-other@example.com","password":"secret1","name":"R"}"#.to_vec());
        assert_eq!(handle(&state, req).status, 201);
        unsafe {
            std::env::remove_var("TRUST_PROXY");
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn spoofed_leading_forwarded_for_cannot_mint_a_fresh_rate_limit_bucket() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: ENV_LOCK is held for the whole test so TRUST_PROXY cannot race.
        unsafe {
            std::env::set_var("TRUST_PROXY", "1");
        }
        let (state, dir) = test_state_locked();
        let now = config::now_ms();
        // Exhaust the window for the address the single trusted proxy observed.
        for _ in 0..crate::stores::AUTH_RATE_LIMIT {
            assert!(!state.auth_rate.check_and_record("198.51.100.10", now).limited);
        }
        // The client prepends junk; the proxy appends the address it saw. Taking
        // the leftmost hop would hand the attacker an unused bucket every time.
        for (i, spoof) in ["203.0.113.1", "203.0.113.2", "203.0.113.3"].iter().enumerate() {
            let mut req = Request::for_test("POST", "/api/signup");
            req.peer_ip = "10.0.0.1".into();
            req.set_test_header("x-forwarded-for", &format!("{spoof}, 198.51.100.10"));
            req.set_test_body(
                format!(r#"{{"email":"spoof{i}@example.com","password":"secret1","name":"R"}}"#)
                    .into_bytes(),
            );
            assert_eq!(handle(&state, req).status, 429, "spoofed hop {spoof} escaped the limit");
        }
        unsafe {
            std::env::remove_var("TRUST_PROXY");
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn forwarded_for_shorter_than_trusted_hops_falls_back_to_peer_ip() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: ENV_LOCK is held for the whole test so TRUST_PROXY cannot race.
        unsafe {
            std::env::set_var("TRUST_PROXY", "2");
        }
        let (state, dir) = test_state_locked();
        let now = config::now_ms();
        // Only one hop present but two are configured: fail closed to the socket
        // peer rather than trusting the client-supplied entry.
        for _ in 0..crate::stores::AUTH_RATE_LIMIT {
            assert!(!state.auth_rate.check_and_record("10.0.0.1", now).limited);
        }
        let mut req = Request::for_test("POST", "/api/signup");
        req.peer_ip = "10.0.0.1".into();
        req.set_test_header("x-forwarded-for", "203.0.113.9");
        req.set_test_body(br#"{"email":"short-chain@example.com","password":"secret1","name":"R"}"#.to_vec());
        assert_eq!(handle(&state, req).status, 429);
        unsafe {
            std::env::remove_var("TRUST_PROXY");
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn put_me_rejects_malformed_json_as_bad_request() {
        let (state, dir) = test_state();
        let signed = signed_up(&state, "badjson@example.com");

        let mut put = Request::for_test("PUT", "/api/me");
        cookie_header(&mut put, &signed);
        put.set_test_body(b"{not json".to_vec());
        let res = handle(&state, put);

        assert_eq!(res.status, 400);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn health_reports_the_database_probe() {
        let (state, dir) = test_state();
        let body = json_body(&handle(&state, Request::for_test("GET", "/api/health")));

        assert_eq!(body.get_str("database"), Some("connected"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn webhook_cleanup_drops_only_expired_records() {
        let (state, dir) = test_state();
        let day_ms = 24 * 60 * 60 * 1000;
        let now = config::now_ms();
        state
            .pool
            .insert_webhook_event("evt_old", "invoice.paid", now - (WEBHOOK_RETENTION_DAYS + 1) * day_ms)
            .unwrap();
        state.pool.insert_webhook_event("evt_new", "invoice.paid", now).unwrap();

        run_webhook_cleanup(&state);

        assert!(state.pool.find_webhook_event("evt_old").unwrap().is_none());
        assert!(state.pool.find_webhook_event("evt_new").unwrap().is_some());
        std::fs::remove_dir_all(&dir).ok();
    }

    const WHSEC: &str = "whsec_test_route_secret";

    fn stripe_state_with_mock(mock: crate::stripe::StripeMock) -> (AppState, std::path::PathBuf) {
        let (mut state, dir) = test_state();
        let keys: Vec<String> = mock.prices.keys().cloned().collect();
        state.stripe = Some(crate::stripe_worker::StripeWorker::spawn(
            crate::stripe::StripeClient::with_mock(mock),
        ));
        state.stripe_lookup_keys = if keys.is_empty() {
            vec!["pro_monthly".into()]
        } else {
            keys
        };
        state.stripe_endpoint_secret = Some(WHSEC.into());
        (state, dir)
    }

    fn signed_webhook(payload: &[u8]) -> Request {
        let mut req = Request::for_test("POST", "/api/payment");
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(1_800_000_000);
        let header = crate::stripe::sign_webhook_header(WHSEC, payload, ts);
        req.set_test_header("stripe-signature", &header);
        req.set_test_body(payload.to_vec());
        req
    }

    fn user_subscription(state: &AppState, email: &str) -> Option<Subscription> {
        state
            .pool
            .find_user(&UserQuery::Email(email.into()))
            .expect("query")
            .expect("user")
            .subscription
    }

    #[test]
    fn payment_rejects_missing_signature() {
        let (state, dir) = stripe_state_with_mock(crate::stripe::StripeMock::default());
        let mut req = Request::for_test("POST", "/api/payment");
        req.set_test_body(br#"{"id":"evt_x"}"#.to_vec());
        let res = handle(&state, req);
        assert_eq!(res.status, 400);
        assert_eq!(json_body(&res).get_str("error"), Some("Missing signature"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn payment_rejects_bad_signature() {
        let (state, dir) = stripe_state_with_mock(crate::stripe::StripeMock::default());
        let mut req = Request::for_test("POST", "/api/payment");
        req.set_test_header("stripe-signature", "t=1800000000,v1=deadbeef");
        req.set_test_body(br#"{"id":"evt_bad","type":"customer.subscription.updated"}"#.to_vec());
        let res = handle(&state, req);
        assert_eq!(res.status, 400);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn payment_subscription_created_patches_user() {
        let mut mock = crate::stripe::StripeMock::default();
        mock.customers
            .insert("cus_new".into(), "subber@example.com".into());
        let (state, dir) = stripe_state_with_mock(mock);
        let _ = signed_up(&state, "subber@example.com");

        let payload = br#"{
            "id":"evt_sub_created",
            "type":"customer.subscription.created",
            "data":{"object":{
                "id":"sub_1",
                "customer":"cus_new",
                "status":"active",
                "current_period_end":1893456000
            }}
        }"#;
        let res = handle(&state, signed_webhook(payload));
        assert_eq!(res.status, 200, "{}", String::from_utf8_lossy(&res.body));

        let sub = user_subscription(&state, "subber@example.com").expect("subscription");
        assert_eq!(sub.stripe_id, "cus_new");
        assert_eq!(sub.status, "active");
        assert_eq!(sub.expires, Some(1_893_456_000));

        assert!(state
            .pool
            .find_webhook_event("evt_sub_created")
            .expect("find")
            .is_some());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn payment_subscription_updated_and_deleted() {
        let mut mock = crate::stripe::StripeMock::default();
        mock.customers
            .insert("cus_life".into(), "life@example.com".into());
        let (state, dir) = stripe_state_with_mock(mock);
        let _ = signed_up(&state, "life@example.com");

        let updated = br#"{
            "id":"evt_sub_updated",
            "type":"customer.subscription.updated",
            "data":{"object":{
                "customer":"cus_life",
                "status":"past_due",
                "current_period_end":1890000000
            }}
        }"#;
        assert_eq!(handle(&state, signed_webhook(updated)).status, 200);
        let sub = user_subscription(&state, "life@example.com").expect("sub");
        assert_eq!(sub.status, "past_due");

        let deleted = br#"{
            "id":"evt_sub_deleted",
            "type":"customer.subscription.deleted",
            "data":{"object":{
                "customer":"cus_life",
                "status":"canceled",
                "current_period_end":1890000000
            }}
        }"#;
        assert_eq!(handle(&state, signed_webhook(deleted)).status, 200);
        let sub = user_subscription(&state, "life@example.com").expect("sub");
        assert_eq!(sub.status, "canceled");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn payment_checkout_session_completed_retrieves_subscription() {
        let mut mock = crate::stripe::StripeMock::default();
        mock.subscriptions.insert(
            "sub_cs".into(),
            r#"{"id":"sub_cs","status":"active","current_period_end":1900000000}"#.into(),
        );
        let (state, dir) = stripe_state_with_mock(mock);
        let _ = signed_up(&state, "buyer@example.com");

        let payload = br#"{
            "id":"evt_cs_done",
            "type":"checkout.session.completed",
            "data":{"object":{
                "customer":"cus_buyer",
                "customer_email":"Buyer@Example.com",
                "subscription":"sub_cs"
            }}
        }"#;
        let res = handle(&state, signed_webhook(payload));
        assert_eq!(res.status, 200, "{}", String::from_utf8_lossy(&res.body));
        let sub = user_subscription(&state, "buyer@example.com").expect("sub");
        assert_eq!(sub.stripe_id, "cus_buyer");
        assert_eq!(sub.status, "active");
        assert_eq!(sub.expires, Some(1_900_000_000));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn payment_invoice_paid_and_payment_failed() {
        let mut mock = crate::stripe::StripeMock::default();
        mock.customers
            .insert("cus_inv".into(), "invoice@example.com".into());
        mock.subscriptions.insert(
            "sub_inv".into(),
            r#"{"id":"sub_inv","status":"active","current_period_end":1910000000}"#.into(),
        );
        let (state, dir) = stripe_state_with_mock(mock);
        let _ = signed_up(&state, "invoice@example.com");

        let paid = br#"{
            "id":"evt_inv_paid",
            "type":"invoice.paid",
            "data":{"object":{
                "customer":"cus_inv",
                "subscription":"sub_inv"
            }}
        }"#;
        assert_eq!(handle(&state, signed_webhook(paid)).status, 200);
        let sub = user_subscription(&state, "invoice@example.com").expect("sub");
        assert_eq!(sub.status, "active");
        assert_eq!(sub.expires, Some(1_910_000_000));

        // payment_failed only logs when the user exists — still 200.
        let failed = br#"{
            "id":"evt_inv_fail",
            "type":"invoice.payment_failed",
            "data":{"object":{"customer":"cus_inv"}}
        }"#;
        assert_eq!(handle(&state, signed_webhook(failed)).status, 200);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn payment_event_is_idempotent() {
        let mut mock = crate::stripe::StripeMock::default();
        mock.customers
            .insert("cus_idem".into(), "idem@example.com".into());
        let (state, dir) = stripe_state_with_mock(mock);
        let _ = signed_up(&state, "idem@example.com");

        let payload = br#"{
            "id":"evt_idem_1",
            "type":"customer.subscription.updated",
            "data":{"object":{
                "customer":"cus_idem",
                "status":"active",
                "current_period_end":1920000000
            }}
        }"#;
        assert_eq!(handle(&state, signed_webhook(payload)).status, 200);
        assert_eq!(handle(&state, signed_webhook(payload)).status, 200);
        // Still one row, still active.
        assert!(state
            .pool
            .find_webhook_event("evt_idem_1")
            .expect("find")
            .is_some());
        assert_eq!(
            user_subscription(&state, "idem@example.com")
                .expect("sub")
                .status,
            "active"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn checkout_returns_mocked_session() {
        let mut mock = crate::stripe::StripeMock::default();
        mock.prices.insert("pro_monthly".into(), "price_pro".into());
        mock.checkout = Some(crate::stripe::CheckoutSession {
            id: "cs_test_123".into(),
            url: Some("https://checkout.stripe.com/c/pay/cs_test_123".into()),
            customer: Some("cus_from_checkout".into()),
        });
        let (state, dir) = stripe_state_with_mock(mock);
        let signup = signed_up(&state, "pay@example.com");

        let mut req = Request::for_test("POST", "/api/checkout");
        replay_cookies(&mut req, &[&signup], true);
        req.set_test_body(br#"{"email":"pay@example.com","lookup_key":"pro_monthly"}"#.to_vec());
        let res = handle(&state, req);
        assert_eq!(res.status, 200, "{}", String::from_utf8_lossy(&res.body));
        let body = json_body(&res);
        assert_eq!(body.get_str("id"), Some("cs_test_123"));
        assert_eq!(
            body.get_str("url"),
            Some("https://checkout.stripe.com/c/pay/cs_test_123")
        );
        assert_eq!(body.get_str("customerID"), Some("cus_from_checkout"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn checkout_rejects_unknown_lookup_key() {
        let (state, dir) = stripe_state_with_mock(crate::stripe::StripeMock::default());
        let signup = signed_up(&state, "pay2@example.com");
        let mut req = Request::for_test("POST", "/api/checkout");
        replay_cookies(&mut req, &[&signup], true);
        req.set_test_body(br#"{"email":"pay2@example.com","lookup_key":"missing"}"#.to_vec());
        let res = handle(&state, req);
        assert_eq!(res.status, 400);
        assert_eq!(json_body(&res).get_str("error"), Some("Unknown lookup_key"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn checkout_rejects_unlisted_lookup_key_even_when_stripe_has_it() {
        let mut mock = crate::stripe::StripeMock::default();
        mock.prices.insert("internal_price".into(), "price_secret".into());
        let (mut state, dir) = stripe_state_with_mock(mock);
        state.stripe_lookup_keys = vec!["pro_monthly".into()];
        let signup = signed_up(&state, "pay3@example.com");
        let mut req = Request::for_test("POST", "/api/checkout");
        replay_cookies(&mut req, &[&signup], true);
        req.set_test_body(
            br#"{"email":"pay3@example.com","lookup_key":"internal_price"}"#.to_vec(),
        );
        let res = handle(&state, req);
        assert_eq!(res.status, 400);
        assert_eq!(json_body(&res).get_str("error"), Some("Unknown lookup_key"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn checkout_rejects_email_mismatch() {
        let mut mock = crate::stripe::StripeMock::default();
        mock.prices.insert("pro_monthly".into(), "price_pro".into());
        let (state, dir) = stripe_state_with_mock(mock);
        let signup = signed_up(&state, "real@example.com");
        let mut req = Request::for_test("POST", "/api/checkout");
        replay_cookies(&mut req, &[&signup], true);
        req.set_test_body(br#"{"email":"other@example.com","lookup_key":"pro_monthly"}"#.to_vec());
        let res = handle(&state, req);
        assert_eq!(res.status, 403);
        assert_eq!(json_body(&res).get_str("error"), Some("Email mismatch"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn lookups_require_the_admin_secret() {
        let (state, dir) = test_state();
        let res = handle(&state, Request::for_test("GET", "/lookups"));
        assert_eq!(res.status, 401);
        assert_eq!(json_body(&res).get_str("error"), Some("Unauthorized"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn lookups_returns_rows_for_the_matching_key() {
        let (state, dir) = test_state_with(&[("ADMIN_SECRET", "s3cret-value")]);
        state
            .pool
            .log_profile_lookup("ada", Some("203.0.113.5"), "api", 20)
            .unwrap();
        state
            .pool
            .log_profile_lookup("bob", None, "api", 10)
            .unwrap();
        let mut req = Request::for_test("GET", "/lookups");
        req.query = "key=s3cret-value&limit=1".into();
        let res = handle(&state, req);
        assert_eq!(res.status, 200, "{}", String::from_utf8_lossy(&res.body));
        let body = json_body(&res);
        assert_eq!(body.get_i64("count"), Some(1));
        let first = body.get("lookups").and_then(Json::as_arr).unwrap()[0].clone();
        assert_eq!(first.get_str("username"), Some("ada"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn clear_cache_removes_profiles_and_avatar_files() {
        let (state, dir) = test_state_with(&[("ADMIN_SECRET", "s3cret-value")]);
        state
            .pool
            .set_cached_profile("ada", r#"{"username":"ada"}"#, 1)
            .unwrap();
        std::fs::write(state.cache_dir.join("ada_avatar.jpg"), b"jpeg").unwrap();
        let mut req = Request::for_test("GET", "/clear-cache");
        req.query = "key=wrong".into();
        assert_eq!(handle(&state, req).status, 401);
        let mut req = Request::for_test("GET", "/clear-cache");
        req.query = "key=s3cret-value".into();
        let res = handle(&state, req);
        assert_eq!(res.status, 200, "{}", String::from_utf8_lossy(&res.body));
        assert_eq!(json_body(&res).get_i64("profiles"), Some(1));
        assert_eq!(json_body(&res).get_i64("images"), Some(1));
        assert!(state.pool.get_cached_profile("ada").unwrap().is_none());
        assert!(!state.cache_dir.join("ada_avatar.jpg").exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn profile_image_serves_jpeg_before_png_and_rejects_bad_ids() {
        let (state, dir) = test_state();
        let bad = handle(&state, Request::for_test("GET", "/images/bad id"));
        assert_eq!(bad.status, 400);
        let dotted = handle(&state, Request::for_test("GET", "/images/a.b"));
        assert_eq!(dotted.status, 400);
        let missing = handle(&state, Request::for_test("GET", "/images/ada_avatar"));
        assert_eq!(missing.status, 404);
        std::fs::write(state.cache_dir.join("ada_avatar.jpg"), b"jpeg-bytes").unwrap();
        std::fs::write(state.cache_dir.join("ada_avatar.png"), b"png-bytes").unwrap();
        let res = handle(&state, Request::for_test("GET", "/images/ada_avatar"));
        assert_eq!(res.status, 200);
        assert_eq!(res.body, b"jpeg-bytes");
        assert!(res
            .headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("content-type") && v == "image/jpeg"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn user_route_503s_without_a_token_even_when_cached() {
        let (state, dir) = test_state();
        state
            .pool
            .set_cached_profile("ada", r#"{"username":"ada"}"#, config::now_ms())
            .unwrap();
        let res = handle(&state, Request::for_test("GET", "/user/ada"));
        assert_eq!(res.status, 503);
        assert_eq!(
            json_body(&res).get_str("error"),
            Some("X API service unavailable")
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn user_route_serves_a_fresh_cache_and_rejects_a_bad_name() {
        let (state, dir) = test_state_with(&[("X_BEARER_TOKEN", "token-for-tests")]);
        let bad = handle(&state, Request::for_test("GET", "/user/not a name"));
        assert_eq!(bad.status, 400);
        state
            .pool
            .set_cached_profile("ada", r#"{"username":"ada","name":"Ada"}"#, config::now_ms())
            .unwrap();
        let res = handle(&state, Request::for_test("GET", "/user/Ada"));
        assert_eq!(res.status, 200, "{}", String::from_utf8_lossy(&res.body));
        assert_eq!(json_body(&res).get_str("name"), Some("Ada"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn user_route_rate_limits_cache_misses_without_calling_x() {
        let (state, dir) = test_state_with(&[("X_BEARER_TOKEN", "token-for-tests")]);
        let now = config::now_ms();
        for _ in 0..3 {
            let status = state.x_rate.check_and_record("203.0.113.9", now);
            assert!(!status.limited);
        }
        let mut req = Request::for_test("GET", "/user/ada");
        // Rightmost X-Forwarded-For entry, matching the Node getClientIP helper.
        req.set_test_header("x-forwarded-for", "10.0.0.1, 203.0.113.9");
        let res = handle(&state, req);
        assert_eq!(res.status, 429, "{}", String::from_utf8_lossy(&res.body));
        assert!(json_body(&res).get_i64("retryAfter").unwrap() > 0);
        let mut probe = Request::for_test("GET", "/user/bob");
        probe.set_test_header("x-forwarded-for", "10.0.0.1, 203.0.113.9");
        assert_eq!(x_client_ip(&probe), "203.0.113.9");
        assert_eq!(x_client_ip(&Request::for_test("GET", "/user/bob")), "unknown");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn qr_image_validates_dimensions_and_requires_a_cached_profile() {
        let (state, dir) = test_state();
        let mut req = Request::for_test("GET", "/qr/ada/image");
        req.query = "w=10&h=852&scale=3".into();
        assert_eq!(handle(&state, req).status, 400);
        let res = handle(&state, Request::for_test("GET", "/qr/ada/image"));
        assert_eq!(res.status, 404);
        assert_eq!(
            json_body(&res).get_str("error"),
            Some("Profile not cached. View the profile first.")
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn qr_image_returns_a_cached_png() {
        let (state, dir) = test_state();
        state
            .pool
            .set_cached_profile("ada", r#"{"username":"ada"}"#, config::now_ms())
            .unwrap();
        let png = b"\x89PNG\r\n\x1a\ncached".to_vec();
        state
            .pool
            .set_cached_image("ada_393x852_3_dark", &png, config::now_ms())
            .unwrap();
        let res = handle(&state, Request::for_test("GET", "/qr/ada/image"));
        assert_eq!(res.status, 200, "{}", String::from_utf8_lossy(&res.body));
        assert_eq!(res.body, png);
        assert!(res.headers.iter().any(|(k, v)| {
            k.eq_ignore_ascii_case("content-disposition") && v.contains("ada-qr.png")
        }));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn literal_lookups_path_is_not_treated_as_a_username() {
        let (state, dir) = test_state();
        std::fs::create_dir_all(state.static_dir.join("unused")).ok();
        std::fs::create_dir_all(&state.static_dir).unwrap();
        std::fs::write(
            state.static_dir.join("index.html"),
            r#"<meta property="og:title" content="App">"#,
        )
        .unwrap();
        let res = handle(&state, Request::for_test("GET", "/lookups"));
        assert_eq!(res.status, 401);
        assert!(json_body(&res).get_str("error").is_some());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn username_route_injects_open_graph_tags_from_the_cache() {
        let (state, dir) = test_state();
        std::fs::create_dir_all(&state.static_dir).unwrap();
        std::fs::write(
            state.static_dir.join("index.html"),
            concat!(
                r#"<meta property="og:title" content="App">"#,
                r#"<meta property="og:description" content="Tag">"#,
                r#"<meta property="og:image" content="/icons/icon.png">"#,
                r#"<meta property="og:url" content="https://example.test">"#,
                r#"<meta name="twitter:title" content="App">"#,
                r#"<meta name="twitter:description" content="Tag">"#,
                r#"<meta name="twitter:image" content="/icons/icon.png">"#
            ),
        )
        .unwrap();
        state
            .pool
            .set_cached_profile(
                "ada",
                r#"{"name":"Ada <Lovelace>","username":"ada","description":"bio","profile_image_url":"/images/ada_avatar"}"#,
                config::now_ms(),
            )
            .unwrap();
        let mut req = Request::for_test("GET", "/ada");
        req.set_test_header("host", "xqr.test");
        let res = handle(&state, req);
        assert_eq!(res.status, 200);
        let html = String::from_utf8(res.body).unwrap();
        assert!(html.contains("Ada &lt;Lovelace&gt; (@ada)"));
        assert!(html.contains("content=\"bio\""));
        assert!(html.contains("http:&#x2F;&#x2F;xqr.test&#x2F;images&#x2F;ada_avatar"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn map_x_user_rewrites_bio_links_and_points_at_local_images() {
        let raw = json::parse(
            br#"{
                "id":"1",
                "username":"ada",
                "name":"Ada",
                "description":"see https://t.co/abc",
                "profile_image_url":"https://pbs.twimg.com/a_normal.jpg",
                "verified":true,
                "public_metrics":{"followers_count":2,"following_count":3,"tweet_count":4},
                "entities":{
                    "description":{"urls":[{"url":"https://t.co/abc","display_url":"ada.dev"}]},
                    "url":{"urls":[{"expanded_url":"https://ada.dev","display_url":"ada.dev"}]}
                }
            }"#,
        )
        .unwrap();
        let mapped = map_x_user(&raw, Some("/images/ada_avatar"), None);
        assert_eq!(mapped.get_str("description"), Some("see ada.dev"));
        assert_eq!(mapped.get_str("profile_image_url"), Some("/images/ada_avatar"));
        assert_eq!(mapped.get_str("url"), Some("https://ada.dev"));
        assert_eq!(mapped.get_i64("followers_count"), Some(2));
        assert!(is_x_cdn_url("https://pbs.twimg.com/profile.jpg"));
        assert!(!is_x_cdn_url("https://evil.twimg.com.example/a.jpg"));
        assert!(!is_x_cdn_url("http://pbs.twimg.com/a.jpg"));
    }

    #[test]
    fn screenshot_honors_color_scheme_when_chromium_is_installed() {
        if browser_bin().is_none() {
            return;
        }
        let dir = std::env::temp_dir().join(format!("xqr-page-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let page = dir.join("page.html");
        std::fs::write(
            &page,
            r#"<!doctype html><style>
              html,body{margin:0;width:100%;height:100%}
              body{background:#eeeeee}
              @media (prefers-color-scheme: dark){body{background:#111111}}
            </style><canvas id="c"></canvas>"#,
        )
        .unwrap();
        let url = format!("file://{}", page.display());
        let light = capture_screenshot(&url, 80, 40, 1.0, "light").expect("light shot");
        let dark = capture_screenshot(&url, 80, 40, 1.0, "dark").expect("dark shot");
        assert!(light.starts_with(b"\x89PNG"));
        assert!(dark.starts_with(b"\x89PNG"));
        assert_ne!(light, dark);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dimension_parser_matches_javascript_parse_int() {
        assert_eq!(js_parse_int("100px"), Some(100));
        assert_eq!(js_parse_int("  -5"), Some(-5));
        assert_eq!(js_parse_int("foo"), None);
        assert_eq!(js_parse_f64("3.5x"), Some(3.5));
        assert!(is_localhost_http("http://localhost:5173/app/home?u=ada"));
        assert!(!is_localhost_http("http://example.com/app/home"));
    }
}
