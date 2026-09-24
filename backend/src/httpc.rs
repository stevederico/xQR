//! Outbound HTTP client over the system `libcurl`.
//!
//! `http.rs` is the inbound server only, and the curl bindings inside
//! `stripe.rs` are private to that module. xQR uses this client for the X API
//! and for caching avatar and banner bytes from `pbs.twimg.com`. Zero-crate:
//! libcurl is linked as a *system library* (`#[link(name = "curl")]`), exactly
//! as `stripe.rs` links it, and every `unsafe` block below carries a
//! `// SAFETY:` justification. The exported surface ([`get`], [`post_json`],
//! [`post_form`], [`HttpResponse`]) is safe.
//!
//! Deliberately out of scope: response streaming, redirects, proxies and
//! connection reuse. Each call is one blocking request/response with a
//! complete body. Redirects stay off so an `Authorization` header cannot be
//! replayed to another host.

use std::ffi::{c_char, c_int, c_long, c_void, CString};
use std::sync::Once;

/// A completed outbound response.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Raw response body.
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// The body as UTF-8, lossily, for JSON parsing and error text.
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// True for a 2xx status.
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// Why an outbound request could not be completed.
///
/// Carries only transport-level text from `curl_easy_strerror` plus our own
/// wording; request headers never reach it, so an API key cannot leak here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpError(pub String);

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for HttpError {}

/// HTTP method. Only what the agent issues.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Method {
    Get,
    Post,
}

/// `GET url` with the supplied headers.
///
/// # Errors
/// [`HttpError`] when the transfer fails; an HTTP error *status* is a
/// successful transfer and comes back in [`HttpResponse::status`].
pub fn get(url: &str, headers: &[(&str, &str)], timeout_ms: i64) -> Result<HttpResponse, HttpError> {
    request(Method::Get, url, headers, None, timeout_ms)
}

/// `POST url` with a JSON body.
pub fn post_json(
    url: &str,
    headers: &[(&str, &str)],
    body: &str,
    timeout_ms: i64,
) -> Result<HttpResponse, HttpError> {
    let mut all: Vec<(&str, &str)> = vec![("Content-Type", "application/json")];
    all.extend_from_slice(headers);
    request(Method::Post, url, &all, Some(body.as_bytes()), timeout_ms)
}

/// `POST url` with an `application/x-www-form-urlencoded` body.
pub fn post_form(
    url: &str,
    headers: &[(&str, &str)],
    body: &str,
    timeout_ms: i64,
) -> Result<HttpResponse, HttpError> {
    let mut all: Vec<(&str, &str)> = vec![("Content-Type", "application/x-www-form-urlencoded")];
    all.extend_from_slice(headers);
    request(Method::Post, url, &all, Some(body.as_bytes()), timeout_ms)
}

/// Percent-encode one form field value (RFC 3986 unreserved set kept as-is).
pub fn form_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

// ==== FFI ====

/// Opaque libcurl easy handle.
#[repr(C)]
struct CURL {
    _private: [u8; 0],
}

/// Opaque libcurl string list (request headers).
#[repr(C)]
struct CurlSlist {
    _private: [u8; 0],
}

/// libcurl write-callback shape.
type CurlCb = extern "C" fn(*mut c_char, usize, usize, *mut c_void) -> usize;

const CURL_GLOBAL_DEFAULT: c_long = 3;
const CURLE_OK: c_int = 0;

const CURLOPT_WRITEDATA: c_int = 10_001;
const CURLOPT_URL: c_int = 10_002;
const CURLOPT_POSTFIELDS: c_int = 10_015;
const CURLOPT_USERAGENT: c_int = 10_018;
const CURLOPT_HTTPHEADER: c_int = 10_023;
const CURLOPT_WRITEFUNCTION: c_int = 20_011;
const CURLOPT_POST: c_int = 47;
const CURLOPT_POSTFIELDSIZE: c_int = 60;
const CURLOPT_FOLLOWLOCATION: c_int = 52;
const CURLOPT_SSL_VERIFYPEER: c_int = 64;
const CURLOPT_SSL_VERIFYHOST: c_int = 81;
const CURLOPT_NOSIGNAL: c_int = 99;
const CURLOPT_TIMEOUT_MS: c_int = 155;
const CURLOPT_CONNECTTIMEOUT_MS: c_int = 156;

/// `CURLINFO_RESPONSE_CODE` = `CURLINFO_LONG (0x200000) + 2`.
const CURLINFO_RESPONSE_CODE: c_int = 2_097_154;

/// Connect timeout for every outbound call, in milliseconds.
const CONNECT_TIMEOUT_MS: c_long = 5_000;

/// Hard ceiling on a response body, so a hostile or broken peer cannot make
/// the process allocate without bound. 8 MiB is far above any JSON the agent
/// exchanges; the transfer is aborted once it is passed.
const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

#[link(name = "curl")]
extern "C" {
    fn curl_global_init(flags: c_long) -> c_int;
    fn curl_easy_init() -> *mut CURL;
    fn curl_easy_perform(handle: *mut CURL) -> c_int;
    fn curl_easy_cleanup(handle: *mut CURL);
    fn curl_easy_strerror(code: c_int) -> *const c_char;
    fn curl_slist_append(list: *mut CurlSlist, string: *const c_char) -> *mut CurlSlist;
    fn curl_slist_free_all(list: *mut CurlSlist);

    // Both are variadic in C and must be declared variadic here. On the Apple
    // arm64 ABI every variadic argument is passed on the stack, so a
    // non-variadic declaration silently loses the value while still reporting
    // CURLE_OK. Callers must therefore pass each argument at its documented
    // width: `c_long` for long options, a pointer for the rest.
    fn curl_easy_setopt(handle: *mut CURL, option: c_int, ...) -> c_int;
    fn curl_easy_getinfo(handle: *mut CURL, info: c_int, ...) -> c_int;
}

/// `curl_global_init` must run exactly once before any easy handle exists.
static CURL_INIT: Once = Once::new();

/// Run libcurl's one-time global initialization.
fn global_init() {
    CURL_INIT.call_once(|| {
        // SAFETY: called exactly once, before any curl_easy_init, per libcurl's
        // documented contract; CURL_GLOBAL_DEFAULT is a valid flag value.
        unsafe {
            curl_global_init(CURL_GLOBAL_DEFAULT);
        }
    });
}

/// libcurl write callback: append the chunk to the `Vec<u8>` behind `userdata`.
///
/// Must not unwind across the FFI boundary, so the body runs inside
/// `catch_unwind`; a panic — or a body past [`MAX_BODY_BYTES`] — is reported as
/// a short write, which makes libcurl abort the transfer with
/// `CURLE_WRITE_ERROR` rather than aborting the process.
extern "C" fn write_cb(ptr: *mut c_char, size: usize, nmemb: usize, userdata: *mut c_void) -> usize {
    let result = std::panic::catch_unwind(|| {
        let len = size.saturating_mul(nmemb);
        if len == 0 || ptr.is_null() || userdata.is_null() {
            return 0;
        }
        // SAFETY: libcurl guarantees `ptr`/`len` describe a readable buffer for
        // the duration of the call, and `userdata` is the `&mut Vec<u8>` handed
        // to CURLOPT_WRITEDATA, which outlives curl_easy_perform.
        let (chunk, sink) = unsafe {
            (
                std::slice::from_raw_parts(ptr.cast::<u8>(), len),
                &mut *userdata.cast::<Vec<u8>>(),
            )
        };
        if sink.len().saturating_add(len) > MAX_BODY_BYTES {
            return 0;
        }
        sink.extend_from_slice(chunk);
        len
    });
    result.unwrap_or(0)
}

/// Owns a libcurl easy handle and frees it on drop, including on early return.
struct EasyHandle(*mut CURL);

impl Drop for EasyHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` came from curl_easy_init, is non-null, and is
            // cleaned up exactly once — EasyHandle is neither Copy nor Clone.
            unsafe { curl_easy_cleanup(self.0) };
        }
    }
}

/// Owns a libcurl header list and frees it on drop.
struct HeaderList(*mut CurlSlist);

impl Drop for HeaderList {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` is the head returned by curl_slist_append and is
            // freed exactly once.
            unsafe { curl_slist_free_all(self.0) };
        }
    }
}

/// Translate a libcurl result code into a transport error message.
fn curl_message(code: c_int) -> String {
    // SAFETY: curl_easy_strerror returns a pointer to a static NUL-terminated
    // string for any code, valid for the program's lifetime; we only read it.
    let text = unsafe {
        let p = curl_easy_strerror(code);
        if p.is_null() {
            None
        } else {
            std::ffi::CStr::from_ptr(p).to_str().ok().map(str::to_string)
        }
    };
    text.unwrap_or_else(|| format!("curl error {code}"))
}

/// Perform one HTTP request through the system libcurl.
///
/// Certificate verification is forced on (`SSL_VERIFYPEER=1`,
/// `SSL_VERIFYHOST=2`) with no parameter to relax it, and redirects are not
/// followed — so a merchant redirect cannot replay an `Authorization` header
/// to another host.
fn request(
    method: Method,
    url: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
    timeout_ms: i64,
) -> Result<HttpResponse, HttpError> {
    global_init();

    let c_url = CString::new(url).map_err(|_| HttpError("url has a NUL byte".into()))?;
    let user_agent = CString::new(format!(
        "xqr-backend/{} (libcurl)",
        env!("CARGO_PKG_VERSION")
    ))
    .map_err(|_| HttpError("bad user agent".into()))?;

    // SAFETY: curl_easy_init takes no arguments and returns either a fresh
    // handle or NULL; the handle is immediately wrapped so Drop frees it.
    let handle = EasyHandle(unsafe { curl_easy_init() });
    if handle.0.is_null() {
        return Err(HttpError("curl_easy_init failed".into()));
    }

    let mut list = HeaderList(std::ptr::null_mut());
    for (name, value) in headers {
        let line = CString::new(format!("{name}: {value}"))
            .map_err(|_| HttpError("header has a NUL byte".into()))?;
        // SAFETY: `list.0` is NULL on the first call ("start a new list") or a
        // list head from a previous append; `line` is a valid NUL-terminated
        // string that libcurl copies before returning.
        let next = unsafe { curl_slist_append(list.0, line.as_ptr()) };
        if next.is_null() {
            return Err(HttpError("curl_slist_append failed".into()));
        }
        list.0 = next;
    }

    let mut sink: Vec<u8> = Vec::new();

    // SAFETY: every call below targets a live handle from curl_easy_init with
    // an option constant matched to its documented argument class, passed at
    // the width libcurl's `va_arg` reads. All pointer arguments — `c_url`,
    // `user_agent`, `list`, `sink` and `body` — are owned by this stack frame
    // and outlive curl_easy_perform.
    let setup = unsafe {
        let h = handle.0;
        let mut rc = curl_easy_setopt(h, CURLOPT_URL, c_url.as_ptr().cast::<c_void>());
        rc |= curl_easy_setopt(h, CURLOPT_USERAGENT, user_agent.as_ptr().cast::<c_void>());
        rc |= curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, write_cb as CurlCb);
        rc |= curl_easy_setopt(h, CURLOPT_WRITEDATA, (&mut sink as *mut Vec<u8>).cast::<c_void>());
        rc |= curl_easy_setopt(h, CURLOPT_TIMEOUT_MS, timeout_ms.max(1) as c_long);
        rc |= curl_easy_setopt(h, CURLOPT_CONNECTTIMEOUT_MS, CONNECT_TIMEOUT_MS);
        rc |= curl_easy_setopt(h, CURLOPT_FOLLOWLOCATION, 0 as c_long);
        // NOSIGNAL is required for thread safety: without it libcurl uses
        // SIGALRM/alarm() for DNS timeouts, which is process-global.
        rc |= curl_easy_setopt(h, CURLOPT_NOSIGNAL, 1 as c_long);
        // Certificate verification: never relaxed, no knob to relax it.
        rc |= curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, 1 as c_long);
        rc |= curl_easy_setopt(h, CURLOPT_SSL_VERIFYHOST, 2 as c_long);
        if !list.0.is_null() {
            rc |= curl_easy_setopt(h, CURLOPT_HTTPHEADER, list.0);
        }
        if method == Method::Post {
            let payload = body.unwrap_or(&[]);
            rc |= curl_easy_setopt(h, CURLOPT_POST, 1 as c_long);
            // Size first, then the buffer: libcurl then never scans for a NUL.
            rc |= curl_easy_setopt(h, CURLOPT_POSTFIELDSIZE, payload.len() as c_long);
            rc |= curl_easy_setopt(h, CURLOPT_POSTFIELDS, payload.as_ptr().cast::<c_void>());
        }
        rc
    };
    if setup != CURLE_OK {
        return Err(HttpError("failed to configure curl handle".into()));
    }

    // SAFETY: the handle is fully configured and still alive; perform blocks
    // until the transfer finishes, during which every buffer above stays valid.
    let rc = unsafe { curl_easy_perform(handle.0) };
    if rc != CURLE_OK {
        return Err(HttpError(curl_message(rc)));
    }

    let mut status: c_long = 0;
    // SAFETY: CURLINFO_RESPONSE_CODE is a CURLINFO_LONG info, so the out
    // parameter must be a `*mut long` — which is exactly what is passed.
    let rc =
        unsafe { curl_easy_getinfo(handle.0, CURLINFO_RESPONSE_CODE, &mut status as *mut c_long) };
    if rc != CURLE_OK {
        return Err(HttpError("could not read response status".into()));
    }

    Ok(HttpResponse {
        status: status.clamp(0, u16::MAX as c_long) as u16,
        body: sink,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_encode_keeps_unreserved_characters() {
        assert_eq!(form_encode("abcXYZ0-9_.~"), "abcXYZ0-9_.~");
    }

    #[test]
    fn form_encode_escapes_everything_else() {
        assert_eq!(form_encode("a b&c=d"), "a%20b%26c%3Dd");
    }

    #[test]
    fn form_encode_escapes_non_ascii_per_byte() {
        assert_eq!(form_encode("é"), "%C3%A9");
    }

    #[test]
    fn http_response_ok_covers_only_2xx() {
        let body = Vec::new();
        assert!(HttpResponse { status: 200, body: body.clone() }.ok());
        assert!(HttpResponse { status: 299, body: body.clone() }.ok());
        assert!(!HttpResponse { status: 300, body: body.clone() }.ok());
        assert!(!HttpResponse { status: 199, body }.ok());
    }

    #[test]
    fn http_response_text_is_lossy_not_panicking() {
        let r = HttpResponse {
            status: 200,
            body: vec![0xff, 0xfe],
        };
        assert!(!r.text().is_empty());
    }

    #[test]
    fn a_url_with_a_nul_byte_is_refused_before_curl_sees_it() {
        let err = get("https://example.com/\0evil", &[], 1_000).unwrap_err();
        assert_eq!(err.0, "url has a NUL byte");
    }

    #[test]
    fn a_header_with_a_nul_byte_is_refused() {
        let err = get("https://example.com/", &[("X-A", "b\0c")], 1_000).unwrap_err();
        assert_eq!(err.0, "header has a NUL byte");
    }
}
