import { useEffect, useState, useRef } from "react";
import { useParams, useSearchParams } from "react-router-dom";
import qrcode from 'qrcode-generator';
import { version } from '../../package.json';
import demoWallpaperLight from '../assets/demo-wallpaper-light.webp';
import demoWallpaperDark from '../assets/demo-wallpaper-dark.webp';

const API_BASE = import.meta.env.DEV ? 'http://localhost:8000' : '';

export default function HomeView() {
  const [username, setUsername] = useState('');
  const [showResult, setShowResult] = useState(false);
  const [generatedUsername, setGeneratedUsername] = useState('');
  const [userInfo, setUserInfo] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [downloading, setDownloading] = useState(false);
  const [previewBlob, setPreviewBlob] = useState(null);
  const [previewUrl, setPreviewUrl] = useState(null);
  const canvasRef = useRef(null);
  const { username: urlUsername } = useParams();

  // Detect screenshot mode (Playwright adds ?screenshot=1)
  // Use both React Router and window.location for maximum compatibility
  const [searchParams] = useSearchParams();
  const isScreenshotMode = searchParams.get('screenshot') === '1' ||
    window.location.search.includes('screenshot=1');
  // Support username from query param (for screenshot) or URL param
  const queryUsername = searchParams.get('u') ||
    new URLSearchParams(window.location.search).get('u');


  // Fetch user info from X API via backend
  async function fetchUserInfo(user) {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(`${API_BASE}/user/${user}`);
      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || 'User not found');
      }
      const data = await response.json();
      setUserInfo(data);
      return data;
    } catch (err) {
      setError(err.message);
      setUserInfo(null);
      return null;
    } finally {
      setLoading(false);
    }
  }

  // Check for username in URL path or query param on mount
  useEffect(() => {
    const usernameToLoad = urlUsername || queryUsername;
    if (usernameToLoad) {
      setGeneratedUsername(usernameToLoad);
      setShowResult(true);
      fetchUserInfo(usernameToLoad);
    }
  }, [urlUsername, queryUsername]);

  // Generate QR code when showing result (after loading completes)
  useEffect(() => {
    if (showResult && generatedUsername && !loading && canvasRef.current) {
      createQRCode(generatedUsername);
    }
  }, [showResult, generatedUsername, loading]);

  // Add class to body when showing results (for hiding mobile nav)
  useEffect(() => {
    if (showResult) {
      document.body.classList.add('qr-fullscreen');
    } else {
      document.body.classList.remove('qr-fullscreen');
    }
    return () => {
      document.body.classList.remove('qr-fullscreen');
    };
  }, [showResult]);

  // Create stable URL for preview blob
  useEffect(() => {
    if (previewBlob) {
      const url = URL.createObjectURL(previewBlob);
      setPreviewUrl(url);
      return () => URL.revokeObjectURL(url);
    } else {
      setPreviewUrl(null);
    }
  }, [previewBlob]);

  function createQRCode(user) {
    const url = `https://x.com/${user}`;

    const qr = qrcode(0, 'L');
    qr.addData(url);
    qr.make();

    const canvas = canvasRef.current;
    const ctx = canvas.getContext('2d');
    const modules = qr.getModuleCount();
    const cellSize = 8;
    const margin = 4;

    canvas.width = (modules + margin * 2) * cellSize;
    canvas.height = (modules + margin * 2) * cellSize;

    // Fill background white
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    // Draw QR code modules
    ctx.fillStyle = '#000000';
    for (let row = 0; row < modules; row++) {
      for (let col = 0; col < modules; col++) {
        if (qr.isDark(row, col)) {
          ctx.fillRect(
            (col + margin) * cellSize,
            (row + margin) * cellSize,
            cellSize,
            cellSize
          );
        }
      }
    }
  }

  async function handleSubmit(e) {
    e.preventDefault();
    if (downloading) return;
    setError(null);
    const trimmed = username.trim().replace('@', '');
    if (!trimmed) return;

    setGeneratedUsername(trimmed);
    setDownloading(true);

    try {
      const info = await fetchUserInfo(trimmed);
      if (!info) {
        setDownloading(false);
        return;
      }

      const scale = Math.min(window.devicePixelRatio || 2, 3);
      const screenWidth = window.screen.width;
      const screenHeight = window.screen.height;
      const deviceHeights = {
        393: 852, 430: 932, 390: 844, 428: 926, 375: 812, 414: 896,
      };
      // Cap dimensions to reasonable max for wallpapers
      const MAX_WIDTH = 1200;
      const MAX_HEIGHT = 1000;
      const width = Math.min(screenWidth, MAX_WIDTH);
      const height = Math.min(deviceHeights[screenWidth] || screenHeight, MAX_HEIGHT);

      const isDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
      const response = await fetch(
        `${API_BASE}/qr/${trimmed}/image?w=${width}&h=${height}&scale=${scale}&theme=${isDark ? 'dark' : 'light'}`
      );

      if (!response.ok) throw new Error('Failed to generate');

      const responseBlob = await response.blob();
      const imageBlob = new Blob([responseBlob], { type: 'image/png' });
      const file = new File([imageBlob], `${trimmed}-wallpaper.png`, { type: 'image/png' });
      const isIOS = /iPhone|iPad|iPod/i.test(navigator.userAgent);

      if (isIOS) {
        // Check if Web Share API supports files (iOS 15+)
        const canShareFiles = navigator.canShare ? navigator.canShare({ files: [file] }) : false;

        if (navigator.share && canShareFiles) {
          try {
            await navigator.share({ files: [file], title: `${trimmed} Wallpaper` });
          } catch (shareErr) {
            if (shareErr.name !== 'AbortError') {
              // Show image preview with download button (fresh gesture will work)
              setPreviewBlob(imageBlob);
            }
          }
        } else {
          // Fallback: open image in new tab (user can long-press to save)
          window.open(URL.createObjectURL(imageBlob), '_blank');
        }
      } else {
        const url = URL.createObjectURL(imageBlob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${trimmed}-wallpaper.png`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(() => URL.revokeObjectURL(url), 100);
      }
    } catch (err) {
      console.error('Download failed:', err);
      setError('Failed to generate wallpaper');
    } finally {
      setDownloading(false);
    }
  }

  function handleReset() {
    setShowResult(false);
    setUserInfo(null);
    setError(null);
    setUsername('');
  }

  async function handleSaveImage() {
    const canvas = canvasRef.current;
    if (!canvas) return;

    try {
      const blob = await new Promise(resolve => canvas.toBlob(resolve, 'image/png'));
      const file = new File([blob], `${generatedUsername}-qr.png`, { type: 'image/png' });
      const isIOS = /iPhone|iPad|iPod/i.test(navigator.userAgent);

      if (isIOS) {
        // iOS: ONLY use share sheet - NEVER use anchor download
        if (navigator.share) {
          try {
            await navigator.share({ files: [file], title: `${generatedUsername} QR Code` });
          } catch (shareErr) {
            if (shareErr.name !== 'AbortError') {
              window.open(URL.createObjectURL(blob), '_blank');
            }
          }
        } else {
          window.open(URL.createObjectURL(blob), '_blank');
        }
      } else {
        // Non-iOS: traditional download
        const url = canvas.toDataURL('image/png');
        const a = document.createElement('a');
        a.href = url;
        a.download = `${generatedUsername}-qr.png`;
        a.click();
      }
    } catch (err) {
      console.log('Save cancelled');
    }
  }

  async function handleDownloadWallpaper() {
    if (downloading) return;
    setDownloading(true);

    try {
      // Use full device screen resolution for lock screen wallpaper
      // iOS Safari's screen.height may exclude toolbar, so use known device sizes
      const scale = Math.min(window.devicePixelRatio || 2, 3);
      const screenWidth = window.screen.width;
      const screenHeight = window.screen.height;

      // Map to actual device screen heights (logical pixels)
      const deviceHeights = {
        393: 852,  // iPhone 14 Pro, 15 Pro
        430: 932,  // iPhone 14 Pro Max, 15 Pro Max
        390: 844,  // iPhone 14, 13, 12
        428: 926,  // iPhone 14 Plus, 13 Pro Max, 12 Pro Max
        375: 812,  // iPhone 13 mini, 12 mini, X, XS, 11 Pro
        414: 896,  // iPhone 11, XR, XS Max
      };

      // Cap dimensions to reasonable max for wallpapers
      const MAX_WIDTH = 1200;
      const MAX_HEIGHT = 1000;
      const width = Math.min(screenWidth, MAX_WIDTH);
      const height = Math.min(deviceHeights[screenWidth] || screenHeight, MAX_HEIGHT);

      const response = await fetch(
        `${API_BASE}/qr/${generatedUsername}/image?w=${width}&h=${height}&scale=${scale}`
      );

      if (response.status === 503) {
        // Screenshot service unavailable (dev mode) - fall back to canvas export
        await handleSaveImage();
        return;
      }

      if (!response.ok) {
        throw new Error('Failed to generate wallpaper');
      }

      const responseBlob = await response.blob();
      const imageBlob = new Blob([responseBlob], { type: 'image/png' });
      const file = new File([imageBlob], `${generatedUsername}-wallpaper.png`, { type: 'image/png' });
      const isIOS = /iPhone|iPad|iPod/i.test(navigator.userAgent);

      if (isIOS) {
        // iOS: ONLY use share sheet - NEVER use anchor download
        if (navigator.share) {
          try {
            await navigator.share({ files: [file], title: `${generatedUsername} Wallpaper` });
          } catch (shareErr) {
            if (shareErr.name !== 'AbortError') {
              window.open(URL.createObjectURL(imageBlob), '_blank');
            }
          }
        } else {
          window.open(URL.createObjectURL(imageBlob), '_blank');
        }
      } else {
        // Non-iOS: traditional anchor download
        const url = URL.createObjectURL(imageBlob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${generatedUsername}-wallpaper.png`;
        a.style.display = 'none';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(() => URL.revokeObjectURL(url), 100);
      }
    } catch (err) {
      console.error('Download failed:', err);
      await handleSaveImage();
    } finally {
      setDownloading(false);
    }
  }

  // Verified badge SVG - color based on verified_type
  // blue = X Premium, business = gold
  const VerifiedBadge = ({ type }) => {
    let colorClass = 'text-blue-400'; // default blue
    if (type === 'business') colorClass = 'text-yellow-500';

    return (
      <svg viewBox="0 0 22 22" className={`w-5 h-5 inline-block ml-1 ${colorClass} fill-current`}>
        <path d="M20.396 11c-.018-.646-.215-1.275-.57-1.816-.354-.54-.852-.972-1.438-1.246.223-.607.27-1.264.14-1.897-.131-.634-.437-1.218-.882-1.687-.47-.445-1.053-.75-1.687-.882-.633-.13-1.29-.083-1.897.14-.273-.587-.704-1.086-1.245-1.44S11.647 1.62 11 1.604c-.646.017-1.273.213-1.813.568s-.969.854-1.24 1.44c-.608-.223-1.267-.272-1.902-.14-.635.13-1.22.436-1.69.882-.445.47-.749 1.055-.878 1.688-.13.633-.08 1.29.144 1.896-.587.274-1.087.705-1.443 1.245-.356.54-.555 1.17-.574 1.817.02.647.218 1.276.574 1.817.356.54.856.972 1.443 1.245-.224.606-.274 1.263-.144 1.896.13.634.433 1.218.877 1.688.47.443 1.054.747 1.687.878.633.132 1.29.084 1.897-.136.274.586.705 1.084 1.246 1.439.54.354 1.17.551 1.816.569.647-.016 1.276-.213 1.817-.567s.972-.854 1.245-1.44c.604.239 1.266.296 1.903.164.636-.132 1.22-.447 1.68-.907.46-.46.776-1.044.908-1.681s.075-1.299-.165-1.903c.586-.274 1.084-.705 1.439-1.246.354-.54.551-1.17.569-1.816zM9.662 14.85l-3.429-3.428 1.293-1.302 2.072 2.072 4.4-4.794 1.347 1.246z" />
      </svg>
    );
  };

  // Format follower count (e.g., 84600 -> "84.6K")
  function formatCount(num) {
    if (!num) return '0';
    if (num >= 1000000) return (num / 1000000).toFixed(1).replace(/\.0$/, '') + 'M';
    if (num >= 1000) return (num / 1000).toFixed(1).replace(/\.0$/, '') + 'K';
    return num.toString();
  }

  // Format joined date (e.g., "2011-06-01T00:00:00.000Z" -> "Joined June 2011")
  function formatJoinedDate(dateStr) {
    if (!dateStr) return null;
    const date = new Date(dateStr);
    const month = date.toLocaleString('en-US', { month: 'long' });
    const year = date.getFullYear();
    return `Joined ${month} ${year}`;
  }

  // Extract display URL from full URL
  function formatUrl(url) {
    if (!url) return null;
    try {
      const parsed = new URL(url);
      return parsed.hostname.replace('www.', '');
    } catch {
      return url;
    }
  }

  // Fullscreen image preview with download button (iOS share fallback)
  if (previewBlob && previewUrl) {
    return (
      <div className="fixed inset-0 z-50 bg-black flex flex-col">
        <div className="flex-1 flex items-center justify-center p-4">
          <img
            src={previewUrl}
            alt="Wallpaper preview"
            className="max-h-[70vh] max-w-[90vw] object-contain rounded-2xl"
            onError={(e) => console.error('Image failed to load:', e)}
          />
        </div>
        <div className="absolute bottom-0 left-0 right-0 p-6 bg-gradient-to-t from-black/80 to-transparent">
          <button
            onClick={async () => {
              const file = new File([previewBlob], `${generatedUsername}-wallpaper.png`, { type: 'image/png' });
              try {
                await navigator.share({ files: [file], title: `${generatedUsername} Wallpaper` });
                setPreviewBlob(null);
              } catch (e) {
                if (e.name !== 'AbortError') {
                  window.open(previewUrl, '_blank');
                }
                setPreviewBlob(null);
              }
            }}
            className="w-full py-4 bg-white text-black font-semibold rounded-xl"
          >
            Save Wallpaper
          </button>
        </div>
      </div>
    );
  }

  if (showResult) {
    return (
      <div className="min-h-screen bg-white dark:bg-black" style={{ fontFamily: '"Inter", "Inter var", -apple-system, BlinkMacSystemFont, "SF Pro Display", "SF Pro Text", system-ui, sans-serif' }}>
        {window.location.search.includes('screenshot=1') && <div style={{ height: 71 }} />}
        {loading ? (
          <div className="flex items-center justify-center py-20">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-400"></div>
          </div>
        ) : (
          <>
            {/* Banner */}
            <div className="relative h-32">
              {userInfo?.profile_banner_url ? (
                <img
                  src={`${API_BASE}${userInfo.profile_banner_url}`}
                  alt="Banner"
                  className="absolute inset-0 w-full h-full object-cover"
                />
              ) : (
                <div className="absolute inset-0 bg-gradient-to-r from-gray-200 to-gray-300 dark:from-gray-800 dark:to-gray-700"></div>
              )}
            </div>

            {/* Profile section */}
            <div className="px-4 pb-3">
              {/* Profile image and buttons */}
              <div className="flex justify-between items-start">
                <div className="-mt-10 relative z-10">
                  {userInfo?.profile_image_url ? (
                    <img
                      src={`${API_BASE}${userInfo.profile_image_url}`}
                      alt={userInfo.name}
                      className="w-20 h-20 rounded-full border-4 border-white dark:border-black"
                    />
                  ) : (
                    <div className="w-20 h-20 rounded-full border-4 border-white dark:border-black bg-gray-200 dark:bg-gray-700 flex items-center justify-center">
                      <span className="text-2xl text-gray-400">@</span>
                    </div>
                  )}
                </div>
                <div className="flex gap-2 mt-3">
                  <button className="w-9 h-9 border border-gray-300 dark:border-gray-600 rounded-full flex items-center justify-center hover:bg-gray-100 dark:hover:bg-gray-800">
                    <svg className="w-4 h-4 text-gray-900 dark:text-white" fill="currentColor" viewBox="0 0 24 24">
                      <circle cx="5" cy="12" r="2" />
                      <circle cx="12" cy="12" r="2" />
                      <circle cx="19" cy="12" r="2" />
                    </svg>
                  </button>
                  <button
                    className="px-4 py-1.5 bg-gray-900 dark:bg-white text-white dark:text-black font-bold rounded-full text-sm"
                  >
                    Follow
                  </button>
                </div>
              </div>

              {/* Name and username */}
              <div className="mb-3 -mt-1">
                <h2 className="text-gray-900 dark:text-white font-bold text-xl flex items-center">
                  {userInfo?.name || generatedUsername}
                  {(userInfo?.verified || userInfo?.verified_type) && userInfo?.verified_type !== 'government' && <VerifiedBadge type={userInfo?.verified_type} />}
                </h2>
                <p className="text-gray-500">@{generatedUsername}</p>
              </div>

              {/* Bio */}
              {userInfo?.description && (
                <p className="text-gray-900 dark:text-white mb-3 text-[15px] leading-relaxed">{userInfo.description}</p>
              )}

              {/* Location, URL, Joined Date */}
              <div className="flex flex-wrap gap-x-4 gap-y-1 text-gray-500 text-sm mb-3">
                  {userInfo?.location && (
                    <span className="flex items-center gap-1">
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17.657 16.657L13.414 20.9a1.998 1.998 0 01-2.827 0l-4.244-4.243a8 8 0 1111.314 0z" />
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 11a3 3 0 11-6 0 3 3 0 016 0z" />
                      </svg>
                      {userInfo.location}
                    </span>
                  )}
                  {(userInfo?.display_url || userInfo?.url) && (
                    <a href={userInfo.url} target="_blank" rel="noopener noreferrer" className="flex items-center gap-1 text-blue-400 hover:underline">
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
                      </svg>
                      {userInfo.display_url || formatUrl(userInfo.url)}
                    </a>
                  )}
                  {userInfo?.created_at && (
                    <span className="flex items-center gap-1">
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
                      </svg>
                      {formatJoinedDate(userInfo.created_at)}
                    </span>
                  )}
              </div>

              {/* Following / Followers */}
              <div className="flex gap-4 text-sm">
                <span>
                  <span className="text-gray-900 dark:text-white font-bold">{formatCount(userInfo?.following_count)}</span>
                  <span className="text-gray-500"> Following</span>
                </span>
                <span>
                  <span className="text-gray-900 dark:text-white font-bold">{formatCount(userInfo?.followers_count)}</span>
                  <span className="text-gray-500"> Followers</span>
                </span>
              </div>

              {/* Tabs */}
              <div className="flex mt-2 -mx-4 border-b border-gray-200 dark:border-gray-800">
                <button className="flex-1 py-4 text-center text-gray-900 dark:text-white font-bold relative">
                  QR
                  <div className="absolute bottom-0 left-1/2 -translate-x-1/2 w-14 h-1 bg-blue-400 rounded-full"></div>
                </button>
                <button className="flex-1 py-4 text-center text-gray-500">Posts</button>
                <button className="flex-1 py-4 text-center text-gray-500">Replies</button>
                <button className="flex-1 py-4 text-center text-gray-500">Media</button>
              </div>
            </div>

            {/* QR Code content area */}
            <div className={`flex flex-col items-center justify-center pt-2 px-4 ${isScreenshotMode ? '' : 'pb-[200vh]'}`}>
              <canvas
                ref={canvasRef}
                className="rounded-2xl border border-gray-200 dark:border-0"
              />
            </div>
          </>
        )}
      </div>
    );
  }

  return (
    <div className="h-dvh flex items-center justify-center p-6 overflow-hidden relative bg-gray-50 dark:bg-black">
      {/* Demo wallpaper background */}
      <div className="absolute inset-0 flex items-center justify-center">
        <img
          src={demoWallpaperLight}
          alt=""
          className="h-full max-h-full w-auto max-w-[430px] object-contain opacity-50 dark:hidden rounded-3xl"
        />
        <img
          src={demoWallpaperDark}
          alt=""
          className="h-full max-h-full w-auto max-w-[430px] object-contain opacity-50 hidden dark:block rounded-3xl"
        />
      </div>

      {/* Main card */}
      <div
        className="relative w-full max-w-sm animate-fade-up bg-white/20 dark:bg-black/20 border border-white/20 dark:border-white/10 rounded-3xl p-10"
        style={{
          backdropFilter: 'blur(12px)',
          WebkitBackdropFilter: 'blur(12px)',
        }}
      >
        {/* X logo mark */}
        <div className="flex justify-center mb-4 animate-fade-up animate-fade-up-delay-1">
          <div className="w-14 h-14 rounded-2xl flex items-center justify-center bg-black dark:bg-white shadow-lg">
            <svg className="w-7 h-7 text-white dark:text-black" viewBox="0 0 24 24" fill="currentColor">
              <path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/>
            </svg>
          </div>
        </div>

        <h1 className="text-2xl font-extrabold text-gray-900 dark:text-white tracking-tight text-center mb-5 animate-fade-up animate-fade-up-delay-2 whitespace-nowrap">QR Code Wallpaper</h1>

        <form onSubmit={handleSubmit} className="space-y-5">
          {/* Username input */}
          <div className="animate-fade-up animate-fade-up-delay-3">
            <div className="relative flex items-center">
              <span className="absolute left-3 text-gray-400 dark:text-gray-500 text-lg font-medium select-none">
                @
              </span>
              <input
                type="text"
                id="username"
                name="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="username"
                autoComplete="off"
                autoCorrect="off"
                autoCapitalize="off"
                spellCheck="false"
                inputMode="text"
                data-form-type="other"
                data-lpignore="true"
                data-1p-ignore
                className="w-full pl-8 pr-4 py-4 rounded-xl text-gray-900 dark:text-white bg-gray-100 dark:bg-white/5 border border-gray-200 dark:border-white/10 placeholder:text-gray-400 dark:placeholder:text-gray-600 focus:outline-none focus:border-gray-400 dark:focus:border-gray-500 transition-colors text-base"
                required
              />
            </div>
          </div>

          {/* Submit button */}
          <div className="animate-fade-up animate-fade-up-delay-4">
            <button
              type="submit"
              disabled={downloading}
              className="w-full py-4 rounded-xl font-semibold transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed relative overflow-hidden group bg-black dark:bg-white text-white dark:text-black hover:bg-gray-800 dark:hover:bg-gray-100 shadow-lg"
            >
              {/* Shimmer effect */}
              {!downloading && (
                <div
                  className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-300"
                  style={{
                    background: 'linear-gradient(90deg, transparent, rgba(255,255,255,0.1), transparent)',
                    backgroundSize: '200% 100%',
                    animation: 'shimmer 2s linear infinite',
                  }}
                />
              )}
              <span className="relative flex items-center justify-center gap-2">
                {downloading ? (
                  <>
                    <svg className="w-5 h-5 animate-spin" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"/>
                    </svg>
                    Generating...
                  </>
                ) : (
                  <>
                    Generate
                    <svg className="w-5 h-5 transition-transform group-hover:translate-x-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7l5 5m0 0l-5 5m5-5H6" />
                    </svg>
                  </>
                )}
              </span>
            </button>
          </div>
        </form>

        {/* Error display */}
        {error && (
          <div className="mt-4 p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-red-500 dark:text-red-400 text-sm text-center">
            {error}
          </div>
        )}
      </div>

      {/* Version tag */}
      <div className="fixed bottom-6 left-0 right-0 text-center">
        <span className="text-xs text-gray-400 dark:text-gray-600 font-mono">v{version}</span>
      </div>
    </div>
  );
}
