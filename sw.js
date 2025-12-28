// ============================================================
// KONVO SERVICE WORKER
// Version: 3.0 (Security Hardened)
// 
// Features:
// - Network-first caching strategy
// - Secure cache validation
// - Push notification handling
// - Offline fallback
// ============================================================

'use strict';

const CACHE_VERSION = 'v11';
const CACHE_NAME = `konvo-cache-${CACHE_VERSION}`;

// Files to cache (static assets only)
const STATIC_ASSETS = [
  '/',
  '/index.html',
  '/dist/style.css',
  '/app.js',
  '/icon.jpg',
  '/konvo.png'
];

// Security: Domains allowed for caching
const ALLOWED_ORIGINS = [
  self.location.origin
];

// Security: Never cache these paths/patterns
const NO_CACHE_PATTERNS = [
  /\/api\//i,
  /firebase/i,
  /googleapis/i,
  /firestore/i,
  /identitytoolkit/i,
  /securetoken/i,
  /cloudfunctions/i,
  /recaptcha/i,
  /fpjs/i,
  /ipify/i,
  /\.json$/i,  // Don't cache JSON API responses
];

// Security: File types that are safe to cache
const CACHEABLE_TYPES = [
  'text/html',
  'text/css',
  'application/javascript',
  'text/javascript',
  'image/png',
  'image/jpeg',
  'image/jpg',
  'image/svg+xml',
  'image/webp',
  'font/woff',
  'font/woff2',
  'application/font-woff',
  'application/font-woff2',
];

/**
 * Security: Check if URL should be cached
 * @param {string} url - URL to check
 * @returns {boolean}
 */
function shouldCache(url) {
  try {
    const urlObj = new URL(url);

    // Only cache same-origin requests
    if (!ALLOWED_ORIGINS.includes(urlObj.origin)) {
      return false;
    }

    // Don't cache API, Firebase, or external service requests
    for (const pattern of NO_CACHE_PATTERNS) {
      if (pattern.test(url)) {
        return false;
      }
    }

    // Don't cache URLs with query strings (often dynamic)
    if (urlObj.search && urlObj.search.length > 0) {
      // Exception for version query strings on static assets
      if (!urlObj.search.match(/^\?v=\d+$/)) {
        return false;
      }
    }

    return true;
  } catch (e) {
    console.warn('SW: Error checking URL for caching:', e.message);
    return false;
  }
}

/**
 * Security: Validate response before caching
 * @param {Response} response - Response to validate
 * @returns {boolean}
 */
function isValidResponse(response) {
  // Must be a valid response
  if (!response) {
    return false;
  }

  // Only cache successful responses
  if (response.status !== 200) {
    return false;
  }

  // Only cache basic (same-origin) responses
  if (response.type !== 'basic') {
    return false;
  }

  // Check content type if available
  const contentType = response.headers.get('content-type');
  if (contentType) {
    const isAllowedType = CACHEABLE_TYPES.some(type => 
      contentType.toLowerCase().includes(type.toLowerCase())
    );
    if (!isAllowedType) {
      return false;
    }
  }

  return true;
}

/**
 * Sanitize notification data
 * @param {string} text - Text to sanitize
 * @param {number} maxLength - Maximum length
 * @returns {string}
 */
function sanitizeText(text, maxLength = 100) {
  if (typeof text !== 'string') return '';
  
  // Remove control characters
  let sanitized = text.replace(/[\x00-\x1F\x7F]/g, '');
  
  // Remove HTML tags
  sanitized = sanitized.replace(/<[^>]*>/g, '');
  
  // Truncate
  if (sanitized.length > maxLength) {
    sanitized = sanitized.substring(0, maxLength - 3) + '...';
  }
  
  return sanitized;
}

// ============================
// INSTALL EVENT
// ============================
self.addEventListener('install', (event) => {
  console.log('SW: Installing version', CACHE_VERSION);
  
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => {
        console.log('SW: Caching static assets');
        
        // Cache static assets individually to handle failures gracefully
        return Promise.allSettled(
          STATIC_ASSETS.map((url) =>
            cache.add(url).catch((err) => {
              console.warn(`SW: Failed to cache ${url}:`, err.message);
            })
          )
        );
      })
      .then(() => {
        console.log('SW: Installation complete');
        return self.skipWaiting();
      })
      .catch((err) => {
        console.error('SW: Installation failed:', err.message);
      })
  );
});

// ============================
// ACTIVATE EVENT
// ============================
self.addEventListener('activate', (event) => {
  console.log('SW: Activating version', CACHE_VERSION);
  
  event.waitUntil(
    caches.keys()
      .then((cacheNames) => {
        return Promise.all(
          cacheNames
            .filter((name) => {
              // Delete old Konvo caches
              return name.startsWith('konvo-cache-') && name !== CACHE_NAME;
            })
            .map((name) => {
              console.log('SW: Deleting old cache:', name);
              return caches.delete(name);
            })
        );
      })
      .then(() => {
        console.log('SW: Activation complete');
        return self.clients.claim();
      })
      .catch((err) => {
        console.error('SW: Activation error:', err.message);
      })
  );
});

// ============================
// FETCH EVENT
// ============================
self.addEventListener('fetch', (event) => {
  const request = event.request;

  // Only handle GET requests
  if (request.method !== 'GET') {
    return;
  }

  // Skip non-cacheable URLs
  if (!shouldCache(request.url)) {
    return;
  }

  // Network-first strategy with cache fallback
  event.respondWith(
    fetch(request)
      .then((response) => {
        // Clone the response before caching
        if (isValidResponse(response)) {
          const responseClone = response.clone();
          
          caches.open(CACHE_NAME)
            .then((cache) => {
              cache.put(request, responseClone);
            })
            .catch((err) => {
              console.warn('SW: Cache put error:', err.message);
            });
        }
        
        return response;
      })
      .catch((error) => {
        console.log('SW: Network failed, trying cache for:', request.url);
        
        return caches.match(request)
          .then((cachedResponse) => {
            if (cachedResponse) {
              console.log('SW: Serving from cache:', request.url);
              return cachedResponse;
            }

            // For navigation requests, return the cached index.html
            if (request.mode === 'navigate') {
              console.log('SW: Serving offline page');
              return caches.match('/index.html');
            }

            // Return offline response
            return new Response('Offline', {
              status: 503,
              statusText: 'Service Unavailable',
              headers: {
                'Content-Type': 'text/plain'
              }
            });
          });
      })
  );
});

// ============================
// PUSH NOTIFICATION EVENT
// ============================
self.addEventListener('push', (event) => {
  console.log('SW: Push notification received');
  
  if (!event.data) {
    console.log('SW: Push event has no data');
    return;
  }

  let data;
  
  try {
    data = event.data.json();
  } catch (e) {
    console.warn('SW: Failed to parse push data:', e.message);
    
    // Try to use raw text
    try {
      const text = event.data.text();
      data = { title: 'Konvo', body: sanitizeText(text, 200) };
    } catch (textError) {
      data = { title: 'Konvo', body: 'New message' };
    }
  }

  // Sanitize notification content (Issue #22)
  const title = sanitizeText(data.title, 50) || 'Konvo';
  const body = sanitizeText(data.body, 200) || 'New message';

  const options = {
    body: body,
    icon: '/icon.jpg',
    badge: '/icon.jpg',
    tag: 'konvo-notification',
    renotify: true,
    requireInteraction: false,
    silent: false,
    vibrate: [200, 100, 200],
    data: {
      url: data.url || '/',
      timestamp: Date.now()
    },
    actions: [
      {
        action: 'open',
        title: 'Open'
      },
      {
        action: 'dismiss',
        title: 'Dismiss'
      }
    ]
  };

  event.waitUntil(
    self.registration.showNotification(title, options)
      .catch((err) => {
        console.error('SW: Failed to show notification:', err.message);
      })
  );
});

// ============================
// NOTIFICATION CLICK EVENT
// ============================
self.addEventListener('notificationclick', (event) => {
  console.log('SW: Notification clicked');
  
  event.notification.close();

  const action = event.action;
  const notificationData = event.notification.data || {};
  const urlToOpen = notificationData.url || '/';

  // Handle dismiss action
  if (action === 'dismiss') {
    return;
  }

  event.waitUntil(
    clients.matchAll({
      type: 'window',
      includeUncontrolled: true
    })
      .then((clientList) => {
        // Try to focus an existing window
        for (const client of clientList) {
          if (client.url.includes(self.location.origin) && 'focus' in client) {
            console.log('SW: Focusing existing window');
            return client.focus();
          }
        }
        
        // Open a new window if none exists
        if (clients.openWindow) {
          console.log('SW: Opening new window');
          return clients.openWindow(urlToOpen);
        }
      })
      .catch((err) => {
        console.error('SW: Notification click error:', err.message);
      })
  );
});

// ============================
// NOTIFICATION CLOSE EVENT
// ============================
self.addEventListener('notificationclose', (event) => {
  console.log('SW: Notification closed');
  
  // Optional: Track notification dismissals
  const notificationData = event.notification.data || {};
  
  // Could send analytics here if needed
});

// ============================
// MESSAGE EVENT
// ============================
self.addEventListener('message', (event) => {
  const { type, payload } = event.data || {};

  console.log('SW: Message received:', type);

  switch (type) {
    case 'SKIP_WAITING':
      console.log('SW: Skip waiting requested');
      self.skipWaiting();
      break;

    case 'CLEAR_CACHE':
      console.log('SW: Clear cache requested');
      caches.delete(CACHE_NAME)
        .then((success) => {
          if (event.ports && event.ports[0]) {
            event.ports[0].postMessage({ 
              success: success,
              message: success ? 'Cache cleared' : 'Cache not found'
            });
          }
        })
        .catch((err) => {
          console.error('SW: Clear cache error:', err.message);
          if (event.ports && event.ports[0]) {
            event.ports[0].postMessage({ 
              success: false, 
              error: 'Failed to clear cache'
            });
          }
        });
      break;

    case 'GET_CACHE_STATUS':
      caches.open(CACHE_NAME)
        .then((cache) => cache.keys())
        .then((keys) => {
          if (event.ports && event.ports[0]) {
            event.ports[0].postMessage({
              success: true,
              cacheVersion: CACHE_VERSION,
              cachedItems: keys.length
            });
          }
        })
        .catch((err) => {
          if (event.ports && event.ports[0]) {
            event.ports[0].postMessage({
              success: false,
              error: 'Failed to get cache status'
            });
          }
        });
      break;

    case 'PRECACHE':
      // Allow dynamic precaching of additional URLs
      if (payload && Array.isArray(payload.urls)) {
        caches.open(CACHE_NAME)
          .then((cache) => {
            const validUrls = payload.urls.filter(url => {
              try {
                const urlObj = new URL(url, self.location.origin);
                return ALLOWED_ORIGINS.includes(urlObj.origin);
              } catch {
                return false;
              }
            });
            return cache.addAll(validUrls);
          })
          .then(() => {
            if (event.ports && event.ports[0]) {
              event.ports[0].postMessage({ success: true });
            }
          })
          .catch((err) => {
            if (event.ports && event.ports[0]) {
              event.ports[0].postMessage({ success: false, error: err.message });
            }
          });
      }
      break;

    default:
      console.log('SW: Unknown message type:', type);
      break;
  }
});

// ============================
// ERROR HANDLING
// ============================
self.addEventListener('error', (event) => {
  console.error('SW: Uncaught error:', event.error?.message || 'Unknown error');
});

self.addEventListener('unhandledrejection', (event) => {
  console.error('SW: Unhandled promise rejection:', event.reason?.message || 'Unknown reason');
  event.preventDefault();
});

// ============================
// PERIODIC SYNC (if supported)
// ============================
self.addEventListener('periodicsync', (event) => {
  if (event.tag === 'konvo-sync') {
    console.log('SW: Periodic sync triggered');
    // Could refresh cached data here
  }
});

// ============================
// BACKGROUND SYNC (if supported)
// ============================
self.addEventListener('sync', (event) => {
  if (event.tag === 'konvo-background-sync') {
    console.log('SW: Background sync triggered');
    // Could retry failed requests here
  }
});

console.log('SW: Service Worker loaded, version', CACHE_VERSION);