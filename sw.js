// sw.js - Secure Service Worker
// Version: 2.0 (Security Hardened)
'use strict';

const CACHE_VERSION = 'v8';
const CACHE_NAME = `konvo-cache-${CACHE_VERSION}`; // ✅ Backticks

// Files to cache (static assets only)
const STATIC_ASSETS = [
  '/',
  '/index.html',
  '/dist/style.css',
  '/app.js'
];

// Security: Domains allowed for caching
const ALLOWED_ORIGINS = [
  self.location.origin
];

// Security: Never cache these paths
const NO_CACHE_PATTERNS = [
  /\/api\//,           // ✅ Fixed regex escaping
  /firebase/i,
  /googleapis/i,
  /firestore/i,
  /identitytoolkit/i,
  /securetoken/i,
  /\/favicon\./i,
  /\/icon\.(png|jpg|jpeg|svg|ico)/i,
  /\/favicon\.(png|ico)/i
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

    // Don't cache API or Firebase requests
    for (const pattern of NO_CACHE_PATTERNS) {
      if (pattern.test(url)) {
        return false;
      }
    }

    return true;
  } catch (e) {
    return false;
  }
}

/**
 * Security: Validate response before caching
 * @param {Response} response - Response to validate
 * @returns {boolean}
 */
function isValidResponse(response) {
  if (!response || response.status !== 200) {
    return false;
  }
  if (response.type !== 'basic') {
    return false;
  }
  return true;
}

// Install event
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => {
        return Promise.allSettled(
          STATIC_ASSETS.map((url) =>
            cache.add(url).catch((err) => {
              console.warn(`Failed to cache ${url}:`, err); // ✅ Backticks
            })
          )
        );
      })
      .then(() => self.skipWaiting())
      .catch((err) => {
        console.error('SW install error:', err);
      })
  );
});

// Activate event - clean old caches
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((cacheNames) => {
        return Promise.all(
          cacheNames
            .filter((name) => name.startsWith('konvo-cache-') && name !== CACHE_NAME)
            .map((name) => {
              console.log('Deleting old cache:', name);
              return caches.delete(name);
            })
        );
      })
      .then(() => self.clients.claim())
      .catch((err) => {
        console.error('SW activate error:', err);
      })
  );
});

// Fetch event - network first, fallback to cache
self.addEventListener('fetch', (event) => {
  const request = event.request;

  if (request.method !== 'GET') {
    return;
  }

  if (!shouldCache(request.url)) {
    return;
  }

  event.respondWith(
    fetch(request)
      .then((response) => {
        if (isValidResponse(response)) {
          const responseClone = response.clone();
          caches.open(CACHE_NAME)
            .then((cache) => {
              cache.put(request, responseClone);
            })
            .catch((err) => {
              console.warn('Cache put error:', err);
            });
        }
        return response;
      })
      .catch(() => {
        return caches.match(request)
          .then((cachedResponse) => {
            if (cachedResponse) {
              return cachedResponse;
            }
            if (request.mode === 'navigate') {
              return caches.match('/index.html');
            }
            return new Response('Offline', {
              status: 503,
              statusText: 'Service Unavailable'
            });
          });
      })
  );
});

// Handle notification clicks
self.addEventListener('notificationclick', (event) => {
  event.notification.close();

  event.waitUntil(
    clients.matchAll({
      type: 'window',
      includeUncontrolled: true
    })
      .then((clientList) => {
        for (const client of clientList) {
          if (client.url.includes(self.location.origin) && 'focus' in client) {
            return client.focus();
          }
        }
        if (clients.openWindow) {
          return clients.openWindow('/');
        }
      })
      .catch((err) => {
        console.error('Notification click error:', err);
      })
  );
});

// Handle push notifications
self.addEventListener('push', (event) => {
  if (!event.data) {
    return;
  }

  try {
    const data = event.data.json();

    const title = typeof data.title === 'string'
      ? data.title.substring(0, 50)
      : 'Konvo';

    const body = typeof data.body === 'string'
      ? data.body.substring(0, 200)
      : 'New message';

    const options = {
      body: body,
      icon: '/icon.jpg',
      badge: '/icon.jpg',
      tag: 'konvo-notification',
      renotify: true,
      requireInteraction: false,
      data: {
        url: '/'
      }
    };

    event.waitUntil(
      self.registration.showNotification(title, options)
    );
  } catch (e) {
    console.error('Push notification error:', e);
  }
});

// Security: Handle message events from main thread
self.addEventListener('message', (event) => {
  // Note: In SW context, event.origin may be undefined
  // Validate based on source instead
  
  const { type } = event.data || {};

  switch (type) {
    case 'SKIP_WAITING':
      self.skipWaiting();
      break;
    case 'CLEAR_CACHE':
      caches.delete(CACHE_NAME)
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
      break;
    default:
      break;
  }
});