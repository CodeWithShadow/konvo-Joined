'use strict';

// ═══════════════════════════════════════════════════════════════════
// DISABLE ALL CONSOLE OUTPUT IN PRODUCTION
// ═══════════════════════════════════════════════════════════════════

(function() {
  console.log = () => {};
  console.warn = () => {};
  console.error = () => {};
  console.info = () => {};
  console.debug = () => {};
  console.trace = () => {};
  console.dir = () => {};
  console.dirxml = () => {};
  console.table = () => {};
  console.group = () => {};
  console.groupEnd = () => {};
  console.groupCollapsed = () => {};
  console.time = () => {};
  console.timeEnd = () => {};
  console.timeLog = () => {};
  console.assert = () => {};
  console.count = () => {};
  console.countReset = () => {};
  console.clear = () => {};
})();

// ═══════════════════════════════════════════════════════════════════
// MOBILE VIEWPORT HANDLING (KEYBOARD FIX)
// ═══════════════════════════════════════════════════════════════════

(function setupMobileViewport() {
  let pendingUpdate = false;
  
  const apply = () => {
    if (pendingUpdate) return;
    pendingUpdate = true;
    
    requestAnimationFrame(() => {
      const viewport = window.visualViewport;
      const height = viewport?.height || window.innerHeight;
      const offsetTop = viewport?.offsetTop || 0;
      
      // Set CSS custom property for dynamic height
      document.documentElement.style.setProperty('--app-height', `${height}px`);
      document.documentElement.style.setProperty('--viewport-offset', `${offsetTop}px`);
      
      if (document.body) {
        document.body.style.height = `${height}px`;
        document.body.style.maxHeight = `${height}px`;
      }
      
      // Scroll feed to bottom if user was already at bottom (keyboard opened)
      if (typeof state !== 'undefined' && state?.userIsAtBottom && feedContainer) {
        feedContainer.scrollTop = feedContainer.scrollHeight;
      }
      
      pendingUpdate = false;
    });
  };
  
  // Apply immediately
  apply();
  
  // Debounced resize handler
  let resizeTimeout;
  const debouncedApply = () => {
    clearTimeout(resizeTimeout);
    resizeTimeout = setTimeout(apply, 50);
  };
  
  // Listen for all viewport changes
  window.addEventListener('resize', debouncedApply, { passive: true });
  
  if (window.visualViewport) {
    window.visualViewport.addEventListener('resize', apply, { passive: true });
    window.visualViewport.addEventListener('scroll', apply, { passive: true });
  }
  
  // Handle orientation change
  window.addEventListener('orientationchange', () => {
    setTimeout(apply, 100);
  }, { passive: true });
})();

// ═══════════════════════════════════════════════════════════════════
// FIREBASE IMPORTS
// ═══════════════════════════════════════════════════════════════════

import { initializeApp } from "https://www.gstatic.com/firebasejs/9.22.1/firebase-app.js";
import { getAuth, signInAnonymously, onAuthStateChanged } from "https://www.gstatic.com/firebasejs/9.22.1/firebase-auth.js";
import {
  initializeFirestore,
  persistentLocalCache,
  persistentMultipleTabManager,
  collection,
  addDoc,
  onSnapshot,
  query,
  serverTimestamp,
  doc,
  setDoc,
  getDoc,
  getDocs,
  where,
  orderBy,
  updateDoc,
  deleteDoc,
  writeBatch,
  arrayUnion,
  arrayRemove,
} from "https://www.gstatic.com/firebasejs/9.22.1/firebase-firestore.js";

// ═══════════════════════════════════════════════════════════════════
// DEVICE STATE
// ═══════════════════════════════════════════════════════════════════

const deviceState = {
  fingerprint: null,
  ipAddress: null,
  isIdentified: false,
  isBannedDevice: false,
};

// ═══════════════════════════════════════════════════════════════════
// UTILITY FUNCTIONS
// ═══════════════════════════════════════════════════════════════════

function withTimeout(promise, ms, fallbackValue = null) {
  return Promise.race([
    promise,
    new Promise((resolve) => setTimeout(() => resolve(fallbackValue), ms))
  ]);
}

// ═══════════════════════════════════════════════════════════════════
// FINGERPRINT GENERATION WITH LOCALSTORAGE PERSISTENCE
// ═══════════════════════════════════════════════════════════════════

const FINGERPRINT_STORAGE_KEY = 'konvo_device_fp';

async function generateDeviceFingerprint() {
  // Check if we already have a saved fingerprint
  try {
    const savedFingerprint = localStorage.getItem(FINGERPRINT_STORAGE_KEY);
    
    if (savedFingerprint && savedFingerprint.length > 0) {
      console.log('Using saved fingerprint from localStorage');
      deviceState.fingerprint = savedFingerprint;
      return savedFingerprint;
    }
  } catch (e) {
    console.warn('LocalStorage not available:', e);
  }

  // No saved fingerprint, try FingerprintJS
  try {
    if (typeof FingerprintJS === 'undefined') {
      console.warn('FingerprintJS not loaded, using fallback');
      return createAndSaveStableFallback();
    }

    const fp = await withTimeout(FingerprintJS.load(), 5000, null);
    if (!fp) {
      console.warn('FingerprintJS.load() timed out, using fallback');
      return createAndSaveStableFallback();
    }

    const result = await withTimeout(fp.get(), 5000, null);
    if (!result) {
      console.warn('FingerprintJS.get() timed out, using fallback');
      return createAndSaveStableFallback();
    }

    // Got fingerprint from FingerprintJS, SAVE IT!
    const fingerprint = result.visitorId;
    saveFingerprint(fingerprint);
    deviceState.fingerprint = fingerprint;
    console.log('Device fingerprint generated and saved');
    return fingerprint;

  } catch (error) {
    console.error('Fingerprint generation error:', error);
    return createAndSaveStableFallback();
  }
}

function createAndSaveStableFallback() {
  // Check localStorage again (in case called directly)
  try {
    const savedFingerprint = localStorage.getItem(FINGERPRINT_STORAGE_KEY);
    if (savedFingerprint && savedFingerprint.length > 0) {
      deviceState.fingerprint = savedFingerprint;
      return savedFingerprint;
    }
  } catch (e) {
    // Continue to generate new one
  }

  // Create a stable fingerprint from device info
  const components = [
    navigator.userAgent,
    navigator.language,
    screen.width + 'x' + screen.height,
    screen.colorDepth,
    new Date().getTimezoneOffset(),
    navigator.hardwareConcurrency || 'unknown',
    navigator.deviceMemory || 'unknown',
    navigator.platform,
  ];

  // Create a hash from components
  let hash = 0;
  const str = components.join('|||');
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }

  // Generate unique ID with random part (generated ONCE, saved forever)
  const randomPart = generateRandomString(8);
  const fallbackId = 'fb_' + Math.abs(hash).toString(36) + '_' + randomPart;

  // Save to localStorage
  saveFingerprint(fallbackId);
  deviceState.fingerprint = fallbackId;
  
  console.log('Fallback fingerprint created and saved');
  return fallbackId;
}

function generateRandomString(length) {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  
  // Try crypto.getRandomValues first (more secure)
  try {
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    for (let i = 0; i < length; i++) {
      result += chars[array[i] % chars.length];
    }
    return result;
  } catch (e) {
    // Fallback to Math.random
    for (let i = 0; i < length; i++) {
      result += chars[Math.floor(Math.random() * chars.length)];
    }
    return result;
  }
}

function saveFingerprint(fingerprint) {
  try {
    localStorage.setItem(FINGERPRINT_STORAGE_KEY, fingerprint);
  } catch (e) {
    console.warn('Could not save fingerprint to localStorage:', e);
  }
}

// ═══════════════════════════════════════════════════════════════════
// IP ADDRESS DETECTION
// ═══════════════════════════════════════════════════════════════════

async function getUserIPAddress() {
  const ipServices = [
    'https://api.ipify.org?format=json',
    'https://ipapi.co/json/'
  ];

  try {
    const fetchPromises = ipServices.map(async (service) => {
      const response = await fetch(service, { mode: 'cors' });
      if (!response.ok) throw new Error('Failed');
      const data = await response.json();
      if (data.ip && isValidIP(data.ip)) {
        return data.ip;
      }
      throw new Error('Invalid IP');
    });

    const result = await withTimeout(
      Promise.any(fetchPromises),
      3000,  
      null
    );

    if (result) {
      deviceState.ipAddress = result;
      console.log('IP address retrieved');
      return result;
    }
  } catch (error) {
    console.warn('IP detection failed:', error.message);
  }

  console.warn('Could not retrieve IP address');
  return null;
}

function isValidIP(ip) {
  if (!ip || typeof ip !== 'string') return false;
  const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6Pattern = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:)*:([0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}$|^::$/;

  if (ipv4Pattern.test(ip)) {
    const parts = ip.split('.').map(Number);
    return parts.every(part => part >= 0 && part <= 255);
  }

  return ipv6Pattern.test(ip);
}

function hashIP(ip) {
  if (!ip) return '';
  let hash = 0;
  for (let i = 0; i < ip.length; i++) {
    const char = ip.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return 'ip_' + Math.abs(hash).toString(36);
}

// ═══════════════════════════════════════════════════════════════════
// DEVICE IDENTIFICATION
// ═══════════════════════════════════════════════════════════════════

async function initializeDeviceIdentification() {
  try {
    const result = await withTimeout(
      Promise.all([
        generateDeviceFingerprint(),
        getUserIPAddress()
      ]),
      8000,
      null  
    );

    if (!result) {
      console.warn('Device identification timed out, using fallback');
      return {
        fingerprint: createAndSaveStableFallback(),
        ipAddress: null,
        ipHash: null,
        userAgent: navigator.userAgent,
        language: navigator.language,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        screenResolution: `${screen.width}x${screen.height}`,
        platform: navigator.platform,
      };
    }

    const [fingerprint, ipAddress] = result;

    deviceState.fingerprint = fingerprint;
    deviceState.ipAddress = ipAddress;
    deviceState.isIdentified = true;

    return {
      fingerprint,
      ipAddress,
      ipHash: hashIP(ipAddress),
      userAgent: navigator.userAgent,
      language: navigator.language,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      screenResolution: `${screen.width}x${screen.height}`,
      platform: navigator.platform,
    };

  } catch (error) {
    console.error('Device identification error:', error);
    return {
      fingerprint: createAndSaveStableFallback(),
      ipAddress: null,
      ipHash: null,
      userAgent: navigator.userAgent,
      language: navigator.language,
      timezone: null,
      screenResolution: `${screen.width}x${screen.height}`,
      platform: navigator.platform,
    };
  }
}

// ═══════════════════════════════════════════════════════════════════
// BAN CHECKING FUNCTIONS
// ═══════════════════════════════════════════════════════════════════

async function checkDeviceBan(db, deviceInfo) {
  if (!db || !deviceInfo) {
    return { isBanned: false, reason: null };
  }

  try {
    if (deviceInfo.fingerprint) {
      const fingerprintBanRef = doc(db, "banned_devices", deviceInfo.fingerprint);
      const fingerprintBanSnap = await getDoc(fingerprintBanRef);

      if (fingerprintBanSnap.exists()) {
        const banData = fingerprintBanSnap.data();
        return { 
          isBanned: true, 
          reason: 'Device banned',
          bannedAt: banData.timestamp,
          banType: 'fingerprint'
        };
      }
    }

    if (deviceInfo.ipAddress) {
      const ipHash = hashIP(deviceInfo.ipAddress);
      const ipBanRef = doc(db, "banned_ips", ipHash);
      const ipBanSnap = await getDoc(ipBanRef);

      if (ipBanSnap.exists()) {
        const banData = ipBanSnap.data();
        return { 
          isBanned: true, 
          reason: 'IP address banned',
          bannedAt: banData.timestamp,
          banType: 'ip'
        };
      }

      const rawIpBanRef = doc(db, "banned_ips", deviceInfo.ipAddress.replace(/\./g, '_'));
      const rawIpBanSnap = await getDoc(rawIpBanRef);

      if (rawIpBanSnap.exists()) {
        return { 
          isBanned: true, 
          reason: 'IP address banned',
          banType: 'ip'
        };
      }
    }

    return { isBanned: false, reason: null };

  } catch (error) {
    console.error('Ban check error:', error);
    return { isBanned: false, reason: null, error: error.message };
  }
}

async function isMyDeviceBanned(db, userId, fingerprint) {
  if (!db || !userId || !fingerprint) return false;

  try {
    const deviceDocId = `${userId}_${fingerprint}`;
    const deviceRef = doc(db, "user_devices", deviceDocId);
    const deviceSnap = await getDoc(deviceRef);

    if (!deviceSnap.exists()) return false;

    const banRef = doc(db, "banned_devices", fingerprint);
    const banSnap = await getDoc(banRef);

    return banSnap.exists();
  } catch (error) {
    console.error('Device ban check error:', error);
    return false;
  }
}

async function registerDevice(db, userId, deviceInfo) {
  if (!db || !userId || !deviceInfo?.fingerprint) return;

  try {
    const deviceDocId = `${userId}_${deviceInfo.fingerprint}`;
    const deviceRef = doc(db, "user_devices", deviceDocId);
    const deviceSnap = await getDoc(deviceRef);

    if (deviceSnap.exists()) {
      await updateDoc(deviceRef, {
        lastSeen: serverTimestamp(),
        ipAddress: deviceInfo.ipAddress || null,
        ipHash: deviceInfo.ipHash || null,
        userAgent: deviceInfo.userAgent || null,
      });
    } else {
      await setDoc(deviceRef, {
        userId: userId,
        fingerprint: deviceInfo.fingerprint,
        ipAddress: deviceInfo.ipAddress || null,
        ipHash: deviceInfo.ipHash || null,
        userAgent: deviceInfo.userAgent || null,
        language: deviceInfo.language || null,
        timezone: deviceInfo.timezone || null,
        screenResolution: deviceInfo.screenResolution || null,
        platform: deviceInfo.platform || null,
        firstSeen: serverTimestamp(),
        lastSeen: serverTimestamp(),
      });
    }

    console.log('Device registered');
  } catch (error) {
    console.error('Device registration error:', error);
  }
}

// ═══════════════════════════════════════════════════════════════════
// UI HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════════

function hideBanCheckOverlay() {
  const overlay = document.getElementById('banCheckOverlay');
  if (overlay) {
    overlay.classList.add('hidden');
    setTimeout(() => {
      overlay.style.display = 'none';
    }, 300);
  }
}

async function checkFullUnbanStatus() {
  if (!state.db || !state.deviceInfo) return;

  try {
    let stillBanned = false;

    if (state.currentUserId) {
      const userBanRef = doc(state.db, "banned_users", state.currentUserId);
      const userBanSnap = await getDoc(userBanRef);
      if (userBanSnap.exists()) stillBanned = true;
    }

    if (!stillBanned && state.deviceInfo.fingerprint) {
      const fpBanRef = doc(state.db, "banned_devices", state.deviceInfo.fingerprint);
      const fpBanSnap = await getDoc(fpBanRef);
      if (fpBanSnap.exists()) stillBanned = true;
    }

    if (!stillBanned && state.deviceInfo.ipHash) {
      const ipBanRef = doc(state.db, "banned_ips", state.deviceInfo.ipHash);
      const ipBanSnap = await getDoc(ipBanRef);
      if (ipBanSnap.exists()) stillBanned = true;
    }

    if (!stillBanned && state.deviceInfo.ipAddress) {
      const rawIpKey = state.deviceInfo.ipAddress.replace(/\./g, '_');
      const rawIpBanRef = doc(state.db, "banned_ips", rawIpKey);
      const rawIpBanSnap = await getDoc(rawIpBanRef);
      if (rawIpBanSnap.exists()) stillBanned = true;
    }

    if (!stillBanned) {
      state.isBanned = false;
      state.isDeviceBanned = false;
      showUnbannedScreen();
    }
  } catch (error) {
    console.error("Error checking unban status:", error);
  }
}

function showDeviceBannedScreen(reason = 'Device banned') {
  const appContainer = document.getElementById('app') || document.body;

  Array.from(appContainer.children).forEach(child => {
    if (child.id !== 'banOverlayScreen') {
      child.style.display = 'none';
    }
  });

  const existingOverlay = document.getElementById('banOverlayScreen');
  if (existingOverlay) existingOverlay.remove();

  const existingCheck = document.getElementById('banCheckOverlay');
  if (existingCheck) existingCheck.style.display = 'none';

  const overlay = document.createElement('div');
  overlay.id = 'banOverlayScreen';
  overlay.style.cssText = `
    position: fixed;
    inset: 0;
    background-color: #0a0a0a;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    z-index: 99999;
    gap: 0.5rem;
    padding: 1rem;
  `;

  const h1 = document.createElement('h1');
  h1.style.cssText = 'font-size: 1.875rem; color: #ef4444; font-weight: bold;';
  h1.textContent = '🚫 ACCESS DENIED';

  const p1 = document.createElement('p');
  p1.style.cssText = 'color: #888; font-size: 0.875rem;';
  p1.textContent = 'This device has been banned from Konvo.';

  const p2 = document.createElement('p');
  p2.style.cssText = 'color: #666; font-size: 0.75rem;';
  p2.textContent = 'Reason: ' + sanitizeText(reason);

  const p3 = document.createElement('p');
  p3.style.cssText = 'color: #555; font-size: 0.75rem; margin-top: 1rem;';
  p3.textContent = 'If you believe this is a mistake, please wait for admin review.';

  overlay.appendChild(h1);
  overlay.appendChild(p1);
  overlay.appendChild(p2);
  overlay.appendChild(p3);
  document.body.appendChild(overlay);
  document.body.classList.add('device-banned');
}

// ═══════════════════════════════════════════════════════════════════
// TEXT SANITIZATION & VALIDATION
// ═══════════════════════════════════════════════════════════════════

function sanitizeText(text) {
  if (typeof text !== 'string') return '';
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\r?\n/g, ' ')
    .replace(/`/g, '&#x60;');
}

function isValidUsername(username) {
  if (typeof username !== 'string') return false;
  const trimmed = username.trim();

  if (trimmed.length === 0 || trimmed.length > 30) return false;

  const reserved = ['anonymous', 'admin', 'moderator', 'system', 'konvo', 'mod'];
  const lowerUsername = trimmed.toLowerCase();
  if (reserved.some(r => lowerUsername === r || lowerUsername.includes(r))) {
    return false;
  }

  const usernameRegex = /^[A-Za-z0-9_\- ]+$/;
  return usernameRegex.test(trimmed);
}

function isValidMessageText(text) {
  if (typeof text !== 'string') return false;
  const trimmed = text.trim();

  if (trimmed.length === 0 || trimmed.length > MESSAGE_MAX_LENGTH) return false;

  const controlCharRegex = /[\x00-\x08\x0B\x0C\x0E-\x1F]/;
  return !controlCharRegex.test(trimmed);
}

function isValidProfilePhotoURL(url) {
  if (typeof url !== 'string') return false;
  if (url.length > 500) return false;

  const allowedPatterns = [
    /^https:\/\/placehold\.co\/.+$/,
    /^https:\/\/ui-avatars\.com\/.+$/,
    /^https:\/\/api\.dicebear\.com\/.+$/,
  ];

  return allowedPatterns.some(pattern => pattern.test(url));
}

function validateMessageBeforePost(text) {
  if (typeof text !== 'string') {
    return { valid: false, error: "Invalid message format" };
  }

  const trimmed = text.trim();

  if (trimmed.length === 0) {
    return { valid: false, error: "Message cannot be empty" };
  }

  if (trimmed.length > MESSAGE_MAX_LENGTH) {
    return { valid: false, error: `Message too long (max ${MESSAGE_MAX_LENGTH} characters)` };
  }

  const controlCharRegex = /[\x00-\x08\x0B\x0C\x0E-\x1F]/;
  if (controlCharRegex.test(trimmed)) {
    return { valid: false, error: "Message contains invalid characters" };
  }

  return { valid: true, text: trimmed };
}

function setTextSafely(element, text) {
  if (element && element instanceof HTMLElement) {
    element.textContent = text || '';
  }
}

function createSafeTextNode(text) {
  return document.createTextNode(text || '');
}

// ═══════════════════════════════════════════════════════════════════
// UTILITY FUNCTIONS
// ═══════════════════════════════════════════════════════════════════

function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

function throttle(func, limit) {
  let inThrottle;
  return function(...args) {
    if (!inThrottle) {
      func.apply(this, args);
      inThrottle = true;
      setTimeout(() => inThrottle = false, limit);
    }
  };
}

function escapeSelector(selector) {
  if (typeof selector !== 'string') return '';
  return CSS.escape(selector);
}

// ═══════════════════════════════════════════════════════════════════
// SVG ICON CREATORS
// ═══════════════════════════════════════════════════════════════════

function createEnabledBellIcon() {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("width", "18");
  svg.setAttribute("height", "18");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "currentColor");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "2");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("aria-hidden", "true");

  const path1 = document.createElementNS(ns, "path");
  path1.setAttribute("d", "M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9");

  const path2 = document.createElementNS(ns, "path");
  path2.setAttribute("d", "M13.73 21a2 2 0 0 1-3.46 0");

  svg.appendChild(path1);
  svg.appendChild(path2);

  return svg;
}

function createDisabledBellIcon() {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("width", "18");
  svg.setAttribute("height", "18");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "2");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("aria-hidden", "true");

  const paths = [
    "M13.73 21a2 2 0 0 1-3 0",
    "M18.63 13A17.89 17.89 0 0 1 18 8",
    "M6.26 6.26A5.86 5.86 0 0 0 6 8c0 7-3 9-3 9h14",
    "M18 8a6 6 0 0 0-9.33-5"
  ];

  paths.forEach(d => {
    const path = document.createElementNS(ns, "path");
    path.setAttribute("d", d);
    svg.appendChild(path);
  });

  const line = document.createElementNS(ns, "line");
  line.setAttribute("x1", "1");
  line.setAttribute("y1", "1");
  line.setAttribute("x2", "23");
  line.setAttribute("y2", "23");
  svg.appendChild(line);

  return svg;
}

function createKebabIcon() {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("width", "14");
  svg.setAttribute("height", "14");
  svg.setAttribute("fill", "currentColor");
  svg.setAttribute("viewBox", "0 0 16 16");
  svg.setAttribute("aria-hidden", "true");

  const path = document.createElementNS(ns, "path");
  path.setAttribute("d", "M9.5 13a1.5 1.5 0 1 1-3 0 1.5 1.5 0 0 1 3 0zm0-5a1.5 1.5 0 1 1-3 0 1.5 1.5 0 0 1 3 0zm0-5a1.5 1.5 0 1 1-3 0 1.5 1.5 0 0 1 3 0z");
  svg.appendChild(path);

  return svg;
}

// ═══════════════════════════════════════════════════════════════════
// FIREBASE CONFIGURATION
// ═══════════════════════════════════════════════════════════════════

const firebaseConfig = {
  apiKey: "AIzaSyDOiYfkCf3Y1Fq7625HimKsm3wYwjBWoxc",
  authDomain: "konvo-d357d.firebaseapp.com",
  projectId: "konvo-d357d",
  storageBucket: "konvo-d357d.firebasestorage.app",
  messagingSenderId: "924631278394",
  appId: "1:924631278394:web:84b8642b5366d869926603"
};
const appStartTime = Date.now();

// ═══════════════════════════════════════════════════════════════════
// DOM ELEMENT REFERENCES
// ═══════════════════════════════════════════════════════════════════

const elements = {
  feedContainer: document.getElementById("feedContainer"),
  loading: document.getElementById("loading"),
  navConfessions: document.getElementById("navConfessions"),
  navChat: document.getElementById("navChat"),
  confessionForm: document.getElementById("confessionForm"),
  confessionInput: document.getElementById("confessionInput"),
  chatForm: document.getElementById("chatForm"),
  chatInput: document.getElementById("chatInput"),
  chatCharCount: document.getElementById("chatCharCount"),
  confessionCharCount: document.getElementById("confessionCharCount"),
  typingIndicator: document.getElementById("typingIndicator"),
  pinnedMessageBar: document.getElementById("pinnedMessageBar"),
  pinnedMessageText: document.getElementById("pinnedMessageText"),
  scrollToBottomBtn: document.getElementById("scrollToBottomBtn"),
  newMsgCount: document.getElementById("newMsgCount"),
  profileButton: document.getElementById("profileButton"),
  notificationButton: document.getElementById("notificationButton"),
  profileModal: document.getElementById("profileModal"),
  modalCloseButton: document.getElementById("modalCloseButton"),
  modalSaveButton: document.getElementById("modalSaveButton"),
  modalUsernameInput: document.getElementById("modalUsernameInput"),
  editModal: document.getElementById("editModal"),
  modalEditTextArea: document.getElementById("modalEditTextArea"),
  editModalCancelButton: document.getElementById("editModalCancelButton"),
  editModalSaveButton: document.getElementById("editModalSaveButton"),
  confirmModal: document.getElementById("confirmModal"),
  confirmModalText: document.getElementById("confirmModalText"),
  confirmModalNoButton: document.getElementById("confirmModalNoButton"),
  confirmModalActionContainer: document.getElementById("confirmModalActionContainer"),
  contextMenu: document.getElementById("contextMenu"),
  menuEdit: document.getElementById("menuEdit"),
  menuDelete: document.getElementById("menuDelete"),
  menuSelect: document.getElementById("menuSelect"),
  selectionBar: document.getElementById("selectionBar"),
  selectionCount: document.getElementById("selectionCount"),
  selectionCancel: document.getElementById("selectionCancel"),
  selectionDelete: document.getElementById("selectionDelete"),
  replyBar: document.getElementById("replyBar"),
  replyAuthor: document.getElementById("replyAuthor"),
  replyText: document.getElementById("replyText"),
  cancelReply: document.getElementById("cancelReply"),
};

const {
  feedContainer, loading, navConfessions, navChat,
  confessionForm, confessionInput, chatForm, chatInput,
  chatCharCount, confessionCharCount,
  typingIndicator, pinnedMessageBar, pinnedMessageText,
  scrollToBottomBtn, newMsgCount, profileButton, notificationButton,
  profileModal, modalCloseButton, modalSaveButton, modalUsernameInput,
  editModal, modalEditTextArea, editModalCancelButton, editModalSaveButton,
  confirmModal, confirmModalText, confirmModalNoButton, confirmModalActionContainer,
  contextMenu, menuEdit, menuDelete, menuSelect,
  selectionBar, selectionCount, selectionCancel, selectionDelete,
  replyBar, replyAuthor, replyText, cancelReply
} = elements;

let menuPin = null;
let menuBan = null;

// ═══════════════════════════════════════════════════════════════════
// APPLICATION STATE
// ═══════════════════════════════════════════════════════════════════

const state = {
  app: null,
  db: null,
  auth: null,
  currentUserId: null,
  currentUsername: "Anonymous",
  currentProfilePhotoURL: null,
  isCurrentUserAdmin: false,
  deviceInfo: null,
  userProfiles: {},
  lastConfessionDocs: [],
  lastChatDocs: [],
  pendingProfileLoads: new Set(),
  profileLoadTimeout: null,
  confessionsCollection: null,
  chatCollection: null,
  typingStatusCollection: null,
  currentPage: "chat",
  isSelectionMode: false,
  selectedMessages: new Set(),
  currentContextMenuData: null,
  replyToMessage: null,
  notificationsEnabled: false,
  unreadMessages: 0,
  userIsAtBottom: true,
  bottomObserver: null,
  docToEditId: null,
  collectionToEdit: null,
  typingTimeout: null,
  isInitialized: false,
  isBanned: false,
  isDeviceBanned: false,
};

// ═══════════════════════════════════════════════════════════════════
// SPAM TRACKING
// ═══════════════════════════════════════════════════════════════════

const spamTracker = {
  messageTimestamps: [],      
  warningShown: false,        
  lastCleanup: Date.now(),    
};

// ═══════════════════════════════════════════════════════════════════
// LISTENER UNSUBSCRIBERS
// ═══════════════════════════════════════════════════════════════════

const unsubscribers = {
  confessions: () => {},
  chat: () => {},
  userProfiles: () => {},
  typingStatus: () => {},
  pinned: () => {},
  banCheck: () => {},
  deviceBanCheck: () => {},
  ipBanCheck: () => {},
};

// ═══════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════

const REACTION_TYPES = Object.freeze({
  thumbsup: "👍",
  laugh: "😂",
  surprised: "😮",
  heart: "❤️",
  skull: "💀"
});

const USER_COLORS = Object.freeze([
  "#ff79c6", "#8be9fd", "#50fa7b", "#bd93f9", "#ffb86c",
  "#f1fa8c", "#ff5555", "#00e5ff", "#fab1a0", "#a29bfe",
  "#55efc4", "#fdcb6e", "#e17055", "#d63031", "#e84393",
  "#0984e3", "#00b894"
]);

const MESSAGE_MAX_LENGTH = 500;
const USERNAME_MAX_LENGTH = 30;
const TYPING_TIMEOUT = 3000;
const TYPING_STALE_THRESHOLD = 5000;

const SPAM_CONFIG = Object.freeze({
  MAX_MESSAGES: 10,           
  TIME_WINDOW: 20000,         
  WARNING_THRESHOLD: 7,       
  CLEANUP_INTERVAL: 30000,    
});

// ═══════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════════

function getUserColor(userId) {
  if (!userId || typeof userId !== 'string') return USER_COLORS[0];
  let hash = 0;
  for (let i = 0; i < userId.length; i++) {
    hash = userId.charCodeAt(i) + ((hash << 5) - hash);
  }
  const index = Math.abs(hash % USER_COLORS.length);
  return USER_COLORS[index];
}

function formatMessageTime(date) {
  if (!(date instanceof Date) || isNaN(date)) {
    return 'Just now';
  }

  const diff = Date.now() - date.getTime();
  const seconds = Math.floor(diff / 1000);
  const minutes = Math.floor(seconds / 60);

  if (minutes < 1) return "Just now";
  if (minutes < 5) return `${minutes} mins ago`;

  return date.toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    hour12: false
  });
}

function getDateHeader(date) {
  if (!(date instanceof Date) || isNaN(date)) {
    return 'Today';
  }

  const today = new Date();
  const yesterday = new Date(today);
  yesterday.setDate(yesterday.getDate() - 1);

  if (date.toDateString() === today.toDateString()) return "Today";
  if (date.toDateString() === yesterday.toDateString()) return "Yesterday";

  return date.toLocaleDateString([], { 
    day: '2-digit', 
    month: '2-digit', 
    year: 'numeric' 
  });
}

function showToast(message, type = 'info') {
  console.log(`[${type.toUpperCase()}]:`, message);
  if (type === 'error') {
    alert(message);
  }
}

function createActionContainer() {
  const existingYesBtn = document.getElementById("confirmModalYesButton");
  if (existingYesBtn && existingYesBtn.parentNode) {
    const container = document.createElement("div");
    container.id = "confirmModalActionContainer";
    container.className = "flex gap-2 flex-1";
    existingYesBtn.parentNode.replaceChild(container, existingYesBtn);
    return container;
  }
  return confirmModalActionContainer;
}

// ═══════════════════════════════════════════════════════════════════
// CLEANUP FUNCTIONS
// ═══════════════════════════════════════════════════════════════════

function cleanupAllListeners() {
  Object.entries(unsubscribers).forEach(([key, unsub]) => {
    if (typeof unsub === 'function') {
      try {
        unsub();
        unsubscribers[key] = () => {};
      } catch (e) {
        console.warn(`Failed to unsubscribe ${key}:`, e);
      }
    }
  });
}

function cleanupNonBanListeners() {
  const banListenerKeys = ['banCheck', 'deviceBanCheck', 'ipBanCheck'];

  Object.entries(unsubscribers).forEach(([key, unsub]) => {
    if (banListenerKeys.includes(key)) return;

    if (typeof unsub === 'function') {
      try {
        unsub();
        unsubscribers[key] = () => {};
      } catch (e) {
        console.warn(`Failed to unsubscribe ${key}:`, e);
      }
    }
  });
}

// ═══════════════════════════════════════════════════════════════════
// SPAM DETECTION
// ═══════════════════════════════════════════════════════════════════

function cleanupSpamTracker() {
  const now = Date.now();
  const cutoff = now - SPAM_CONFIG.TIME_WINDOW;

  spamTracker.messageTimestamps = spamTracker.messageTimestamps.filter(
    ts => ts > cutoff
  );

  if (spamTracker.messageTimestamps.length < SPAM_CONFIG.WARNING_THRESHOLD) {
    spamTracker.warningShown = false;
  }

  spamTracker.lastCleanup = now;
}

function checkSpamStatus() {
  const now = Date.now();

  if (now - spamTracker.lastCleanup > SPAM_CONFIG.CLEANUP_INTERVAL) {
    cleanupSpamTracker();
  }

  const cutoff = now - SPAM_CONFIG.TIME_WINDOW;
  spamTracker.messageTimestamps = spamTracker.messageTimestamps.filter(
    ts => ts > cutoff
  );

  const messageCount = spamTracker.messageTimestamps.length;

  if (messageCount >= SPAM_CONFIG.MAX_MESSAGES) {
    return { 
      allowed: false, 
      reason: 'spam_limit',
      shouldBan: true 
    };
  }

  if (messageCount >= SPAM_CONFIG.WARNING_THRESHOLD && !spamTracker.warningShown) {
    spamTracker.warningShown = true;
    const remaining = SPAM_CONFIG.MAX_MESSAGES - messageCount;
    return { 
      allowed: true, 
      warning: `Spamming = Getting Banned ⚠️.`
    };
  }

  return { allowed: true };
}

function recordMessage() {
  spamTracker.messageTimestamps.push(Date.now());
}

async function autoBanForSpam() {
  if (!state.db || !state.currentUserId) return;

  console.log('Auto-banning user for spam...');

  try {
    const userId = state.currentUserId;
    const fingerprint = state.deviceInfo?.fingerprint;
    const ipHash = state.deviceInfo?.ipHash;

    let actualUsername = '';
    try {
      const userDoc = await getDoc(doc(state.db, "users", userId));
      if (userDoc.exists()) {
        actualUsername = userDoc.data().username || '';
      }
    } catch (e) {
      console.warn('Could not fetch username for ban:', e);
    }

    let deviceRegistered = false;
    let storedIpHash = null;

    if (fingerprint) {
      const deviceDocId = `${userId}_${fingerprint}`;
      const deviceRef = doc(state.db, "user_devices", deviceDocId);

      try {
        const deviceSnap = await getDoc(deviceRef);
        if (deviceSnap.exists()) {
          deviceRegistered = true;
          storedIpHash = deviceSnap.data().ipHash || null;
        } else {
          await setDoc(deviceRef, {
            userId: userId,
            fingerprint: fingerprint,
            ipHash: ipHash || null,
            ipAddress: state.deviceInfo?.ipAddress || null,
            firstSeen: serverTimestamp(),
            lastSeen: serverTimestamp(),
            userAgent: state.deviceInfo?.userAgent || null,
            platform: state.deviceInfo?.platform || null,
          });
          deviceRegistered = true;
          storedIpHash = ipHash;
          console.log('Device registered for ban');
        }
      } catch (e) {
        console.warn('Device check/registration failed:', e);
      }
    }

    const batch = writeBatch(state.db);

    const userRef = doc(state.db, "users", userId);
    batch.set(userRef, { banned: true }, { merge: true });

    const banRef = doc(state.db, "banned_users", userId);
    batch.set(banRef, {
      bannedBy: "SYSTEM_AUTO_BAN",
      timestamp: serverTimestamp(),
      reason: "Automatic ban: Spam detection (exceeded message limit)",
      username: actualUsername
    });

    if (fingerprint && deviceRegistered) {
      const fingerprintBanRef = doc(state.db, "banned_devices", fingerprint);
      batch.set(fingerprintBanRef, {
        fingerprint: fingerprint,
        userId: userId,
        username: actualUsername,
        bannedBy: "SYSTEM_AUTO_BAN",
        timestamp: serverTimestamp(),
        reason: "Automatic ban: Spam detection",
        userAgent: state.deviceInfo?.userAgent || null,
        platform: state.deviceInfo?.platform || null,
      });
      console.log('Fingerprint ban queued');
    }

    if (ipHash && deviceRegistered && storedIpHash && ipHash === storedIpHash) {
      const ipBanRef = doc(state.db, "banned_ips", ipHash);
      batch.set(ipBanRef, {
        ipHash: ipHash,
        fingerprint: fingerprint,  
        userId: userId,
        username: actualUsername,
        bannedBy: "SYSTEM_AUTO_BAN",
        timestamp: serverTimestamp(),
        reason: "Automatic ban: Spam detection",
      });
      console.log('IP hash ban queued');
    } else {
      console.warn('IP ban skipped - hash mismatch or not available');
    }

    await batch.commit();
    console.log('User auto-banned for spam successfully');

    state.isBanned = true;
    state.isDeviceBanned = true;

    showSpamBannedScreen();

  } catch (error) {
    console.error('Auto-ban error:', error);
    showSpamBannedScreen();
  }
}

function showSpamBannedScreen() {
  const appContainer = document.getElementById('app') || document.body;

  Array.from(appContainer.children).forEach(child => {
    if (child.id !== 'banOverlayScreen') {
      child.style.display = 'none';
    }
  });

  const existingOverlay = document.getElementById('banOverlayScreen');
  if (existingOverlay) existingOverlay.remove();

  const overlay = document.createElement('div');
  overlay.id = 'banOverlayScreen';
  overlay.style.cssText = `
    position: fixed;
    inset: 0;
    background-color: #0a0a0a;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    z-index: 99999;
    gap: 0.5rem;
    padding: 1rem;
    text-align: center;
  `;

  const h1 = document.createElement('h1');
  h1.style.cssText = 'font-size: 1.875rem; color: #ef4444; font-weight: bold;';
  h1.textContent = '🚫 BANNED FOR SPAMMING';

  const p1 = document.createElement('p');
  p1.style.cssText = 'color: #888; font-size: 0.875rem;';
  p1.textContent = 'You have been banned by ADMIN for SPAMMING.';

  const p2 = document.createElement('p');
  p2.style.cssText = 'color: #666; font-size: 0.75rem;';
  p2.textContent = `Reason: Mana kiya tha Maat kar.`;

  const p3 = document.createElement('p');
  p3.style.cssText = 'color: #555; font-size: 0.7rem; margin-top: 1rem;';
  p3.textContent = 'Le Lauda ho gya BAN.';

  overlay.appendChild(h1);
  overlay.appendChild(p1);
  overlay.appendChild(p2);
  overlay.appendChild(p3);
  document.body.appendChild(overlay);
}

function showSpamWarning(message) {
  const existingToast = document.getElementById('spam-warning-toast');
  if (existingToast) {
    existingToast.remove();
  }

  const toast = document.createElement('div');
  toast.id = 'spam-warning-toast';
  toast.style.cssText = `
    position: fixed;
    top: 70px;
    left: 50%;
    transform: translateX(-50%);
    background: linear-gradient(135deg, #ff6b6b, #ee5a5a);
    color: white;
    padding: 12px 24px;
    border-radius: 8px;
    font-weight: bold;
    font-size: 14px;
    z-index: 10000;
    box-shadow: 0 4px 20px rgba(238, 90, 90, 0.4);
    animation: slideDown 0.3s ease-out, shake 0.5s ease-in-out;
    text-align: center;
    max-width: 90%;
  `;
  toast.textContent = message;
  document.body.appendChild(toast);

  setTimeout(() => {
    if (toast.parentNode) {
      toast.style.animation = 'fadeOut 0.3s ease-out forwards';
      setTimeout(() => toast.remove(), 300);
    }
  }, 4000);
}

// ═══════════════════════════════════════════════════════════════════
// CHARACTER COUNTER
// ═══════════════════════════════════════════════════════════════════

function updateCharacterCounter(input, counter) {
  if (!input || !counter) return;

  const currentLength = input.value.length;
  const maxLength = MESSAGE_MAX_LENGTH;

  counter.textContent = `${currentLength}/${maxLength}`;

  if (currentLength > 0) {
    counter.classList.add('visible');
  } else {
    counter.classList.remove('visible');
  }

  counter.classList.remove('warning', 'danger', 'limit');

  if (currentLength >= maxLength) {
    counter.classList.add('limit');
  } else if (currentLength >= maxLength * 0.95) {
    counter.classList.add('danger');
  } else if (currentLength >= maxLength * 0.8) {
    counter.classList.add('warning');
  }
}

// ═══════════════════════════════════════════════════════════════════
// SERVICE WORKER & CONNECTION MONITORING
// ═══════════════════════════════════════════════════════════════════

function registerServiceWorker() {
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('sw.js', { scope: '/' })
      .then(reg => {
        console.log('SW registered:', reg.scope);

        reg.addEventListener('updatefound', () => {
          const newWorker = reg.installing;
          if (newWorker) {
            newWorker.addEventListener('statechange', () => {
              if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
                console.log('New version available');
              }
            });
          }
        });
      })
      .catch(err => console.error('SW registration failed:', err));
  }
}

function setupConnectionMonitor() {
  window.addEventListener('online', () => {
    console.log('Connection restored');
    if (state.isInitialized) {
      showPage(state.currentPage);
    }
  });

  window.addEventListener('offline', () => {
    console.log('Connection lost');
    showToast("You're offline. Messages will sync when connected.", "info");
  });
}

// ═══════════════════════════════════════════════════════════════════
// NOTIFICATION HANDLING
// ═══════════════════════════════════════════════════════════════════

function setupNotificationButton() {
  if (!notificationButton) return;

  notificationButton.addEventListener("click", handleNotificationClick);

  if ("Notification" in window && Notification.permission === "granted") {
    state.notificationsEnabled = true;
  }

  updateNotificationIcon();
}

async function handleNotificationClick(e) {
  e.preventDefault();
  e.stopPropagation();

  if (!("Notification" in window)) {
    showToast("Notifications not supported in this browser", "error");
    return;
  }

  if (Notification.permission === "granted") {
    state.notificationsEnabled = !state.notificationsEnabled;
    updateNotificationIcon();
  } else if (Notification.permission !== "denied") {
    try {
      const permission = await Notification.requestPermission();
      if (permission === "granted") {
        state.notificationsEnabled = true;
        updateNotificationIcon();
      }
    } catch (err) {
      console.error("Notification permission error:", err);
    }
  } else {
    showToast("Notifications are blocked. Please enable in browser settings.", "error");
  }
}

function updateNotificationIcon() {
  if (!notificationButton) return;

  notificationButton.innerHTML = '';

  if (state.notificationsEnabled) {
    notificationButton.classList.add("text-yellow-400");
    notificationButton.appendChild(createEnabledBellIcon());
    notificationButton.title = "Notifications enabled - Click to disable";
  } else {
    notificationButton.classList.remove("text-yellow-400");
    notificationButton.appendChild(createDisabledBellIcon());
    notificationButton.title = "Notifications disabled - Click to enable";
  }
}

async function showNotification(title, body) {
  if (!("Notification" in window) || !state.notificationsEnabled) return;
  if (document.visibilityState === 'visible') return;

  const safeTitle = typeof title === 'string' ? title.substring(0, 50) : 'New Message';
  const safeBody = typeof body === 'string' ? body.substring(0, 100) : '';

  try {
    if ('serviceWorker' in navigator) {
      const reg = await navigator.serviceWorker.ready;
      if (reg) {
        await reg.showNotification(safeTitle, { 
          body: safeBody, 
          icon: "icon.jpg", 
          badge: "icon.jpg",
          tag: 'konvo-message',
          renotify: true,
          requireInteraction: false
        });
        return;
      }
    }
    new Notification(safeTitle, { body: safeBody, icon: "icon.jpg" });
  } catch (e) {
    console.error('Notification error:', e);
  }
}

// ═══════════════════════════════════════════════════════════════════
// ADMIN MENU SETUP
// ═══════════════════════════════════════════════════════════════════

function setupAdminMenu() {
  const ul = contextMenu?.querySelector("ul");
  if (!ul || document.getElementById("menuPin")) return;

  menuPin = document.createElement("li");
  menuPin.id = "menuPin";
  menuPin.setAttribute("role", "menuitem");
  menuPin.setAttribute("tabindex", "-1");
  menuPin.textContent = "Pin Message 📌";
  menuPin.addEventListener("click", togglePinMessage);

  if (menuDelete) {
    ul.insertBefore(menuPin, menuDelete);
  }

  menuBan = document.createElement("li");
  menuBan.id = "menuBan";
  menuBan.className = "text-red-500 hover:text-red-400 font-bold border-t border-[#333] mt-1 pt-1";
  menuBan.setAttribute("role", "menuitem");
  menuBan.setAttribute("tabindex", "-1");
  menuBan.textContent = "Ban User 🚫";
  menuBan.addEventListener("click", toggleBanUser);

  ul.appendChild(menuBan);
}

async function togglePinMessage() {
  if (!state.currentContextMenuData || !state.db) return;

  const { id, isPinned, text } = state.currentContextMenuData;
  const isCurrentlyPinned = isPinned === "true";

  hideDropdownMenu();

  try {
    const batch = writeBatch(state.db);

    const msgRef = doc(state.db, state.currentPage, id);
    batch.update(msgRef, { isPinned: !isCurrentlyPinned });

    const pinRef = doc(state.db, "pinned_messages", id);

    if (isCurrentlyPinned) {
      batch.delete(pinRef);
    } else {
      batch.set(pinRef, {
        originalId: id,
        collection: state.currentPage,
        text: text?.substring(0, 200) || '',
        pinnedBy: state.currentUserId,
        timestamp: serverTimestamp()
      });
    }

    await batch.commit();
  } catch (e) {
    console.error('Pin error:', e);
    showToast("Failed to pin message. Check Admin permissions.", "error");
  }
}

async function toggleBanUser() {
  if (!state.currentContextMenuData || !state.db) return;

  const { userId, username } = state.currentContextMenuData;

  if (userId === state.currentUserId) {
    showToast("You cannot ban yourself.", "error");
    hideDropdownMenu();
    return;
  }

  hideDropdownMenu();

  let isBanned = false;
  try {
    const banDocRef = doc(state.db, "banned_users", userId);
    const banDocSnap = await getDoc(banDocRef);
    isBanned = banDocSnap.exists();
  } catch (e) {
    console.error("Error checking ban status:", e);
    showToast("Error checking ban status. Please try again.", "error");
    return;
  }

  const action = isBanned ? "UNBAN" : "BAN";
  const safeUsername = sanitizeText(username || 'this user');

  const confirmMessage = isBanned 
    ? `Unban ${safeUsername}? This will restore their access including their device and IP.`
    : `Ban ${safeUsername}? This will also ban their device fingerprint and IP address, preventing them from returning even with a new browser.`;

  if (!confirm(confirmMessage)) {
    return;
  }

  try {
    const batch = writeBatch(state.db);

    const userRef = doc(state.db, "users", userId);
    if (isBanned) {
      batch.update(userRef, { banned: false });
    } else {
      batch.set(userRef, { banned: true }, { merge: true });
    }

    const banRef = doc(state.db, "banned_users", userId);
    if (isBanned) {
      batch.delete(banRef);
    } else {
      batch.set(banRef, {
        bannedBy: state.currentUserId,
        timestamp: serverTimestamp(),
        reason: "Admin Action",
        username: username?.substring(0, 30) || 'Unknown'
      });
    }

    const devicesQuery = query(
      collection(state.db, "user_devices"),
      where("userId", "==", userId)
    );

    let devicesSnapshot;
    try {
      devicesSnapshot = await getDocs(devicesQuery);
    } catch (e) {
      console.warn("Could not fetch user devices:", e);
      devicesSnapshot = { docs: [] };
    }

    const processedFingerprints = new Set();
    const processedIPs = new Set();

    for (const deviceDoc of devicesSnapshot.docs) {
      const deviceData = deviceDoc.data();

      if (deviceData.fingerprint && !processedFingerprints.has(deviceData.fingerprint)) {
        processedFingerprints.add(deviceData.fingerprint);

        const fingerprintBanRef = doc(state.db, "banned_devices", deviceData.fingerprint);

        if (isBanned) {
          batch.delete(fingerprintBanRef);
        } else {
          batch.set(fingerprintBanRef, {
            fingerprint: deviceData.fingerprint,
            userId: userId,
            username: username?.substring(0, 30) || 'Unknown',
            bannedBy: state.currentUserId,
            timestamp: serverTimestamp(),
            reason: "Admin Action",
            userAgent: deviceData.userAgent || null,
            platform: deviceData.platform || null,
          });
        }
      }

      if (deviceData.ipHash && !processedIPs.has(deviceData.ipHash)) {
        processedIPs.add(deviceData.ipHash);
        const ipBanRef = doc(state.db, "banned_ips", deviceData.ipHash);

        if (isBanned) {
          batch.delete(ipBanRef);
        } else {
          batch.set(ipBanRef, {
            ipHash: deviceData.ipHash,
            userId: userId,
            username: username?.substring(0, 30) || 'Unknown',
            bannedBy: state.currentUserId,
            timestamp: serverTimestamp(),
            reason: "Admin Action",
          });
        }
      }
    }

    await batch.commit();

    if (state.userProfiles[userId]) {
      state.userProfiles[userId].banned = !isBanned;
    }

    const devicesCount = processedFingerprints.size;
    const ipsCount = processedIPs.size;

    showToast(
      isBanned 
        ? `✅ User UNBANNED. Removed ${devicesCount} device ban(s) and ${ipsCount} IP ban(s).`
        : `🚫 User BANNED. Added ${devicesCount} device ban(s) and ${ipsCount} IP ban(s).`, 
      "info"
    );

  } catch (e) {
    console.error('Ban/Unban error:', e);
    showToast(`Failed to ${action.toLowerCase()} user: ${e.message}`, "error");
  }
}

// ═══════════════════════════════════════════════════════════════════
// FIREBASE INITIALIZATION
// ═══════════════════════════════════════════════════════════════════

async function initFirebase() {
  const globalTimeout = setTimeout(() => {
    console.warn('Initialization timeout - showing app anyway');
    hideBanCheckOverlay();
  }, 15000);

  try {
    console.log('Initializing device identification...');
    state.deviceInfo = await initializeDeviceIdentification();

    state.app = initializeApp(firebaseConfig);

    try {
      state.db = initializeFirestore(state.app, {
        localCache: persistentLocalCache({
          tabManager: persistentMultipleTabManager()
        })
      });
    } catch (persistenceError) {
      console.warn('Persistence initialization failed, using default:', persistenceError);
      state.db = initializeFirestore(state.app, {});
    }

    state.auth = getAuth(state.app);

    onAuthStateChanged(state.auth, async (user) => {
      try {
        await handleAuthStateChange(user);
      } catch (error) {
        console.error('Auth state change error:', error);
        hideBanCheckOverlay();
      } finally {
        clearTimeout(globalTimeout);
      }
    });

  } catch (error) {
    console.error("Error initializing Firebase:", error);
    setTextSafely(loading, "Error: Could not initialize. Please refresh.");
    hideBanCheckOverlay();
    clearTimeout(globalTimeout);
    throw error;
  }
}

async function handleAuthStateChange(user) {
  if (user) {
    state.currentUserId = user.uid;
    console.log("Authenticated with UID:", state.currentUserId);

    try {
      await registerDevice(state.db, state.currentUserId, state.deviceInfo);
      console.log('Device registered successfully');
    } catch (regError) {
      console.warn('Device registration failed:', regError);
    }

    try {
      console.log('Checking device ban status...');
      const deviceBanCheck = await withTimeout(
        checkDeviceBan(state.db, state.deviceInfo),
        5000,
        { isBanned: false, reason: null }
      );

      if (deviceBanCheck.isBanned) {
        console.log('Device is banned:', deviceBanCheck.reason);
        state.isDeviceBanned = true;
        showDeviceBannedScreen(deviceBanCheck.reason);
        return;
      }
    } catch (banCheckError) {
      console.warn('Device ban check failed, continuing:', banCheckError);
    }

    state.confessionsCollection = collection(state.db, "confessions");
    state.chatCollection = collection(state.db, "chat");
    state.typingStatusCollection = collection(state.db, "typingStatus");

    registerServiceWorker();
    setupNotificationButton();
    setupAdminMenu();
    setupConnectionMonitor();
    listenForUserProfiles();
    listenForBanStatus();
    listenForDeviceBans();

    try {
      await checkAdminStatus();
    } catch (e) {
      console.error("Admin check failed:", e);
    }

    try {
      await loadUserProfile();
    } catch (e) {
      console.error("Profile load failed:", e);
    }

    hideBanCheckOverlay();
    initScrollObserver();
    showPage(state.currentPage);

    state.isInitialized = true;

  } else {
    try {
      await signInAnonymously(state.auth);
    } catch (e) {
      console.error("Anonymous auth failed:", e);
      setTextSafely(loading, "Error: Could not sign in. Please refresh.");
      hideBanCheckOverlay();
    }
  }
}

async function checkAdminStatus() {
  if (!state.currentUserId || !state.db) return;

  try {
    const adminDocRef = doc(state.db, "admins", state.currentUserId);
    const adminDocSnap = await getDoc(adminDocRef);

    state.isCurrentUserAdmin = adminDocSnap.exists();

    if (state.isCurrentUserAdmin) {
      console.log("Admin privileges active");
    }
  } catch (e) {
    console.error("Admin check error:", e);
    state.isCurrentUserAdmin = false;
  }
}

// ═══════════════════════════════════════════════════════════════════
// REALTIME LISTENERS
// ═══════════════════════════════════════════════════════════════════

function listenForPinnedMessages() {
  if (typeof unsubscribers.pinned === 'function') {
    unsubscribers.pinned();
    unsubscribers.pinned = () => {};
  }

  const q = query(
    collection(state.db, "pinned_messages"),
    orderBy("timestamp", "desc")
  );

  unsubscribers.pinned = onSnapshot(q, (snapshot) => {
    const matchingPin = snapshot.docs.find(doc => 
      doc.data().collection === state.currentPage
    );

    if (matchingPin && pinnedMessageBar && pinnedMessageText) {
      const data = matchingPin.data();
      pinnedMessageBar.classList.remove("hidden");
      pinnedMessageBar.style.display = "flex";
      setTextSafely(pinnedMessageText, data.text);

      pinnedMessageBar.onclick = () => {
        const escapedId = escapeSelector(data.originalId);
        const bubble = document.querySelector(`.message-bubble[data-id="${escapedId}"]`);
        if (bubble) {
          bubble.scrollIntoView({ behavior: "smooth", block: "center" });
          bubble.classList.add("ring-2", "ring-yellow-400");
          setTimeout(() => {
            bubble.classList.remove("ring-2", "ring-yellow-400");
          }, 2000);
        }
      };
    } else if (pinnedMessageBar) {
      pinnedMessageBar.classList.add("hidden");
      pinnedMessageBar.style.display = "none";
    }
  }, (error) => {
    console.warn("Pinned messages listener error:", error);
    if (pinnedMessageBar) {
      pinnedMessageBar.classList.add("hidden");
    }
  });
}

function listenForBanStatus() {
  if (typeof unsubscribers.banCheck === 'function') {
    unsubscribers.banCheck();
    unsubscribers.banCheck = () => {};
  }

  if (!state.currentUserId || !state.db) return;

  unsubscribers.banCheck = onSnapshot(
    doc(state.db, "banned_users", state.currentUserId), 
    (docSnap) => {
      if (docSnap.exists()) {
        if (!state.isBanned) {
          state.isBanned = true;
          state.userProfiles = {};
          cleanupNonBanListeners();
          showBannedScreen();
        }
      } else {
        if (state.isBanned) {
          state.isBanned = false;
          showUnbannedScreen();
        }
      }
    },
    (error) => {
      console.warn("Ban check error:", error);
    }
  );
}

function listenForDeviceBans() {
  if (typeof unsubscribers.deviceBanCheck === 'function') {
    unsubscribers.deviceBanCheck();
    unsubscribers.deviceBanCheck = () => {};
  }

  if (typeof unsubscribers.ipBanCheck === 'function') {
    unsubscribers.ipBanCheck();
    unsubscribers.ipBanCheck = () => {};
  }

  if (!state.db || !state.deviceInfo?.fingerprint) return;

  unsubscribers.deviceBanCheck = onSnapshot(
    doc(state.db, "banned_devices", state.deviceInfo.fingerprint), 
    (docSnap) => {
      if (docSnap.exists()) {
        if (!state.isDeviceBanned) {
          state.isDeviceBanned = true;
          cleanupNonBanListeners();
          showDeviceBannedScreen('Device fingerprint banned');
        }
      } else {
        if (state.isDeviceBanned) {
          checkFullUnbanStatus();
        }
      }
    },
    (error) => {
      console.warn("Device ban check error:", error);
    }
  );

  if (state.deviceInfo.ipHash) {
    unsubscribers.ipBanCheck = onSnapshot(
      doc(state.db, "banned_ips", state.deviceInfo.ipHash), 
      (docSnap) => {
        if (docSnap.exists()) {
          if (!state.isDeviceBanned) {
            state.isDeviceBanned = true;
            cleanupNonBanListeners();
            showDeviceBannedScreen('IP address banned');
          }
        } else {
          if (state.isDeviceBanned) {
            checkFullUnbanStatus();
          }
        }
      },
      (error) => {
        console.warn("IP ban check error:", error);
      }
    );
  }
}

// ═══════════════════════════════════════════════════════════════════
// BAN SCREENS
// ═══════════════════════════════════════════════════════════════════

function showUnbannedScreen() {
  const banOverlay = document.getElementById('banOverlayScreen');
  if (banOverlay) banOverlay.remove();

  const overlay = document.createElement('div');
  overlay.id = 'unbanOverlayScreen';
  overlay.style.cssText = `
    position: fixed;
    inset: 0;
    background-color: #0a0a0a;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    z-index: 99999;
    gap: 1rem;
  `;

  const h1 = document.createElement('h1');
  h1.style.cssText = 'font-size: 1.875rem; color: #22c55e; font-weight: bold;';
  h1.textContent = '✅ ACCESS RESTORED';

  const p = document.createElement('p');
  p.style.cssText = 'color: #888; font-size: 0.875rem; text-align: center; max-width: 300px;';
  p.textContent = 'Your ban has been lifted. Click below to continue using Konvo.';

  const btn = document.createElement('button');
  btn.style.cssText = `
    margin-top: 1.5rem;
    padding: 0.75rem 2rem;
    background-color: #22c55e;
    color: #000;
    border: none;
    border-radius: 8px;
    font-weight: bold;
    font-size: 1rem;
    cursor: pointer;
    transition: transform 0.2s, background-color 0.2s;
  `;
  btn.textContent = 'CONTINUE';
  btn.onmouseover = () => btn.style.backgroundColor = '#16a34a';
  btn.onmouseout = () => btn.style.backgroundColor = '#22c55e';
  btn.onclick = () => window.location.reload();

  overlay.appendChild(h1);
  overlay.appendChild(p);
  overlay.appendChild(btn);
  document.body.appendChild(overlay);
}

function showBannedScreen() {
  const appContainer = document.getElementById('app') || document.body;

  Array.from(appContainer.children).forEach(child => {
    if (child.id !== 'banOverlayScreen') {
      child.style.display = 'none';
    }
  });

  const existingOverlay = document.getElementById('banOverlayScreen');
  if (existingOverlay) existingOverlay.remove();

  const overlay = document.createElement('div');
  overlay.id = 'banOverlayScreen';
  overlay.className = 'banned-overlay';
  overlay.style.cssText = `
    position: fixed;
    inset: 0;
    background-color: #0a0a0a;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    z-index: 99999;
    gap: 1rem;
  `;

  const h1 = document.createElement('h1');
  h1.style.cssText = 'font-size: 1.875rem; color: #ef4444; font-weight: bold;';
  h1.textContent = '🚫 ACCESS DENIED';

  const p = document.createElement('p');
  p.style.cssText = 'color: #888; font-size: 0.875rem;';
  p.textContent = 'You have been banned from Konvo.';

  const p2 = document.createElement('p');
  p2.style.cssText = 'color: #555; font-size: 0.75rem; margin-top: 1rem;';
  p2.textContent = 'If you believe this is a mistake, please wait for admin review.';

  overlay.appendChild(h1);
  overlay.appendChild(p);
  overlay.appendChild(p2);
  document.body.appendChild(overlay);
}

// ═══════════════════════════════════════════════════════════════════
// SCROLL HANDLING
// ═══════════════════════════════════════════════════════════════════

function initScrollObserver() {
  const options = { 
    root: feedContainer, 
    rootMargin: "100px", 
    threshold: 0.1 
  };

  state.bottomObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      state.userIsAtBottom = entry.isIntersecting;
      updateScrollButton();
    });
  }, options);

  feedContainer?.addEventListener('scroll', () => {}, { passive: true });
}

function updateScrollButton() {
  if (!scrollToBottomBtn || !newMsgCount) return;

  if (state.userIsAtBottom) {
    scrollToBottomBtn.classList.add("hidden");
    scrollToBottomBtn.style.display = "";
    newMsgCount.classList.add("hidden");
    state.unreadMessages = 0;
  } else {
    scrollToBottomBtn.classList.remove("hidden");
    scrollToBottomBtn.style.display = "flex";

        if (state.unreadMessages > 0) {
      newMsgCount.classList.remove("hidden");
      setTextSafely(newMsgCount, 
        state.unreadMessages > 99 ? "99+" : String(state.unreadMessages)
      );
    } else {
      newMsgCount.classList.add("hidden");
    }
  }
}

function scrollToBottom() {
  if (!feedContainer) return;
  feedContainer.scrollTop = feedContainer.scrollHeight;
  state.userIsAtBottom = true;
  state.unreadMessages = 0;
  updateScrollButton();
}

// ═══════════════════════════════════════════════════════════════════
// USER PROFILE MANAGEMENT
// ═══════════════════════════════════════════════════════════════════

function requestUserProfile(userId) {
  if (!userId || typeof userId !== 'string') return;
  if (state.userProfiles[userId]) return;
  if (state.pendingProfileLoads.has(userId)) return;

  state.pendingProfileLoads.add(userId);

  if (state.profileLoadTimeout) {
    clearTimeout(state.profileLoadTimeout);
  }

  state.profileLoadTimeout = setTimeout(() => {
    loadPendingProfiles();
  }, 100);
}

async function loadPendingProfiles() {
  if (state.pendingProfileLoads.size === 0) return;
  if (!state.db) return;

  const userIds = Array.from(state.pendingProfileLoads);
  state.pendingProfileLoads.clear();

  const batchSize = 30;

  for (let i = 0; i < userIds.length; i += batchSize) {
    const batch = userIds.slice(i, i + batchSize);

    try {
      const q = query(
        collection(state.db, "users"),
        where("__name__", "in", batch)
      );

      const snapshot = await getDocs(q);

      snapshot.docs.forEach((docSnap) => {
        state.userProfiles[docSnap.id] = docSnap.data();
      });
    } catch (error) {
      console.error("Error loading user profiles:", error);

      for (const userId of batch) {
        try {
          const docRef = doc(state.db, "users", userId);
          const docSnap = await getDoc(docRef);
          if (docSnap.exists()) {
            state.userProfiles[docSnap.id] = docSnap.data();
          }
        } catch (e) {
          console.warn(`Failed to load profile for ${userId}:`, e);
        }
      }
    }
  }

  updateDisplayedUsernames();
}

function updateDisplayedUsernames() {
  document.querySelectorAll('.message-bubble').forEach((bubble) => {
    const userId = bubble.dataset.userId;
    if (!userId) return;

    const profile = state.userProfiles[userId];
    if (!profile) return;

    const username = profile.username || "Anonymous";

    const usernameEl = bubble.querySelector('.font-bold.text-sm.opacity-90');
    if (usernameEl && usernameEl.textContent !== username) {
      usernameEl.textContent = username;
    }

    const imgEl = bubble.querySelector('.chat-pfp');
    if (imgEl && profile.profilePhotoURL) {
      const currentSrc = imgEl.getAttribute('src');
      if (currentSrc !== profile.profilePhotoURL && isValidProfilePhotoURL(profile.profilePhotoURL)) {
        imgEl.src = profile.profilePhotoURL;
      }
    }
  });
}

function listenForUserProfiles() {
  if (typeof unsubscribers.userProfiles === 'function') {
    unsubscribers.userProfiles();
    unsubscribers.userProfiles = () => {};
  }

  const checkAndSetupListener = () => {
    const loadedUserIds = Object.keys(state.userProfiles);

    if (loadedUserIds.length === 0) {
      setTimeout(checkAndSetupListener, 2000);
      return;
    }

    const userIdsToWatch = loadedUserIds.slice(0, 30);

    try {
      const q = query(
        collection(state.db, "users"),
        where("__name__", "in", userIdsToWatch)
      );

      unsubscribers.userProfiles = onSnapshot(q, 
        (snapshot) => {
          snapshot.docChanges().forEach((change) => {
            if (change.type === 'modified' || change.type === 'added') {
              state.userProfiles[change.doc.id] = change.doc.data();
            }
          });
          updateDisplayedUsernames();
        },
        (error) => {
          console.error("User profiles listener error:", error);
        }
      );
    } catch (e) {
      console.error("Error setting up profile listener:", e);
    }
  };

  setTimeout(checkAndSetupListener, 1000);
}

async function loadUserProfile() {
  if (!state.db || !state.currentUserId) return;

  try {
    const userDoc = await getDoc(doc(state.db, "users", state.currentUserId));

    if (userDoc.exists()) {
      const data = userDoc.data();
      state.userProfiles[state.currentUserId] = data;

      if (data.banned) {
        showBannedScreen();
        throw new Error("User Banned");
      }

      state.currentUsername = data.username || "Anonymous";

      const pfp = data.profilePhotoURL;
      if (pfp && isValidProfilePhotoURL(pfp)) {
        state.currentProfilePhotoURL = pfp;
      } else {
        state.currentProfilePhotoURL = null;
      }
    }

    if (modalUsernameInput) {
      modalUsernameInput.value = state.currentUsername === "Anonymous" 
        ? "" 
        : state.currentUsername;
    }
  } catch (error) {
    console.error("Load profile error:", error);
    throw error;
  }
}

// ═══════════════════════════════════════════════════════════════════
// PROFILE MODAL HANDLING
// ═══════════════════════════════════════════════════════════════════

async function handleProfileSave() {
  if (!state.db || !state.currentUserId) {
    showToast("Not connected. Please refresh the page.", "error");
    return;
  }

  const inputVal = modalUsernameInput?.value?.trim();

  if (!inputVal) {
    showToast("Please enter a username.", "error");
    return;
  }

  if (!isValidUsername(inputVal)) {
    showToast("Invalid username. Use letters, numbers, underscores, hyphens, and spaces only (1-30 characters).", "error");
    if (modalUsernameInput) {
      modalUsernameInput.classList.add("error");
      setTimeout(() => modalUsernameInput.classList.remove("error"), 500);
    }
    return;
  }

  const resetButtonState = () => {
    if (modalSaveButton) {
      modalSaveButton.textContent = "Save";
      modalSaveButton.disabled = false;
      modalSaveButton.classList.remove("loading");
    }
    if (modalCloseButton) {
      modalCloseButton.disabled = false;
    }
    if (modalUsernameInput) {
      modalUsernameInput.disabled = false;
    }
  };

  if (modalSaveButton) {
    modalSaveButton.textContent = "CHECKING...";
    modalSaveButton.disabled = true;
    modalSaveButton.classList.add("loading");
  }
  if (modalCloseButton) {
    modalCloseButton.disabled = true;
  }
  if (modalUsernameInput) {
    modalUsernameInput.disabled = true;
  }

  try {
    console.log('Checking if username is available:', inputVal);

    const q = query(
      collection(state.db, "users"), 
      where("username", "==", inputVal)
    );

    const querySnapshot = await withTimeout(
      getDocs(q),
      10000,
      null
    );

    if (querySnapshot === null) {
      console.error('Username check timed out');
      showToast("Request timed out. Please try again.", "error");
      resetButtonState();
      return;
    }

    let isTaken = false;
    querySnapshot.forEach((docSnapshot) => {
      if (docSnapshot.id !== state.currentUserId) {
        isTaken = true;
      }
    });

    if (isTaken) {
      console.log('Username is taken');
      showToast("Username is already taken!", "error");
      resetButtonState();
      return;
    }

    console.log('Username available, saving profile...');

    if (modalSaveButton) {
      modalSaveButton.textContent = "SAVING...";
    }

    const newProfilePhotoURL = `https://ui-avatars.com/api/?name=${encodeURIComponent(inputVal)}&background=random&size=128`;

    await withTimeout(
      setDoc(doc(state.db, "users", state.currentUserId), {
        username: inputVal,
        profilePhotoURL: newProfilePhotoURL,
      }, { merge: true }),
      10000,
      null
    );

    console.log('Profile saved successfully');

    state.currentUsername = inputVal;
    state.currentProfilePhotoURL = newProfilePhotoURL;

    state.userProfiles[state.currentUserId] = {
      ...state.userProfiles[state.currentUserId],
      username: inputVal,
      profilePhotoURL: newProfilePhotoURL
    };

    showToast("Profile saved successfully!", "info");
    closeProfileModal();
    resetButtonState();

  } catch (error) {
    console.error("Error saving profile:", error);

    if (error.code === 'permission-denied') {
      showToast("Permission denied. You may be banned.", "error");
    } else if (error.code === 'unavailable') {
      showToast("Server unavailable. Please try again.", "error");
    } else {
      showToast("Error saving profile: " + (error.message || "Unknown error"), "error");
    }

    resetButtonState();
  }
}

function openProfileModal() {
  if (!modalUsernameInput || !profileModal) return;

  modalUsernameInput.value = state.currentUsername === "Anonymous" 
    ? "" 
    : state.currentUsername;

  profileModal.classList.add("is-open");
  profileModal.setAttribute("aria-hidden", "false");

  setTimeout(() => modalUsernameInput.focus(), 100);
}

function closeProfileModal() {
  if (!profileModal) return;

  profileModal.classList.remove("is-open");
  profileModal.setAttribute("aria-hidden", "true");
}

// ═══════════════════════════════════════════════════════════════════
// EDIT MODAL HANDLING
// ═══════════════════════════════════════════════════════════════════

function showEditModal(docId, collectionName, currentText) {
  if (!editModal || !modalEditTextArea) return;

  state.docToEditId = docId;
  state.collectionToEdit = collectionName;

  modalEditTextArea.value = currentText || '';

  editModal.classList.add("is-open");
  editModal.setAttribute("aria-hidden", "false");

  setTimeout(() => {
    modalEditTextArea.focus();
    modalEditTextArea.setSelectionRange(
      modalEditTextArea.value.length, 
      modalEditTextArea.value.length
    );
  }, 100);
}

function closeEditModal() {
  if (!editModal) return;

  editModal.classList.remove("is-open");
  editModal.setAttribute("aria-hidden", "true");

  state.docToEditId = null;
  state.collectionToEdit = null;
}

async function saveEdit() {
  const newText = modalEditTextArea.value.trim();

  if (!isValidMessageText(newText)) {
    showToast(`Message must be 1-${MESSAGE_MAX_LENGTH} characters.`, "error");
    return;
  }

  if (!state.docToEditId || !state.db) return;

  editModalSaveButton.textContent = "SAVING...";
  editModalSaveButton.disabled = true;
  editModalCancelButton.disabled = true;
  editModalSaveButton.classList.add("loading");

  try {
    await updateDoc(doc(state.db, state.collectionToEdit, state.docToEditId), {
      text: newText,
      edited: true
    });

    closeEditModal();
  } catch (e) {
    console.error('Edit error:', e);
    showToast("Error: You can only edit your own messages.", "error");
  } finally {
    editModalSaveButton.textContent = "SAVE";
    editModalSaveButton.disabled = false;
    editModalCancelButton.disabled = false;
    editModalSaveButton.classList.remove("loading");
  }
}

// ═══════════════════════════════════════════════════════════════════
// CONFIRM MODAL HANDLING
// ═══════════════════════════════════════════════════════════════════

function showConfirmModal(text, isMine, docId) {
  if (!confirmModal || !confirmModalActionContainer) return;

  setTextSafely(confirmModalText, text);

  confirmModalActionContainer.innerHTML = '';

  const isAdmin = state.isCurrentUserAdmin;

  if (isMine || isAdmin) {
    const btnForMe = document.createElement('button');
    btnForMe.type = 'button';
    btnForMe.className = "flex-1 px-4 py-2 rounded-lg font-bold text-sm border border-white text-white hover:bg-white hover:text-black transition";
    btnForMe.textContent = "FOR ME";
    btnForMe.onclick = async () => {
      closeConfirmModal();
      try {
        await updateDoc(doc(state.db, state.currentPage, docId), { 
          hiddenFor: arrayUnion(state.currentUserId) 
        });
      } catch (e) {
        console.error('Hide error:', e);
      }
    };

    const btnEveryone = document.createElement('button');
    btnEveryone.type = 'button';
    btnEveryone.className = "flex-1 px-4 py-2 rounded-lg font-bold text-sm bg-red-600 text-white hover:bg-red-500 border border-red-600 transition";
    btnEveryone.textContent = isAdmin && !isMine ? "NUKE (ADMIN)" : "EVERYONE";
    btnEveryone.onclick = async () => {
      closeConfirmModal();
      try {
        await deleteDoc(doc(state.db, state.currentPage, docId));
      } catch (e) {
        console.error('Delete error:', e);
        showToast("Permission denied.", "error");
      }
    };

    confirmModalActionContainer.appendChild(btnForMe);
    confirmModalActionContainer.appendChild(btnEveryone);
  } else {
    const btnForMe = document.createElement('button');
    btnForMe.type = 'button';
    btnForMe.className = "flex-1 px-4 py-2 rounded-lg font-bold text-sm bg-red-600 text-white hover:bg-red-500 transition";
    btnForMe.textContent = "HIDE";
    btnForMe.onclick = async () => {
      closeConfirmModal();
      try {
        await updateDoc(doc(state.db, state.currentPage, docId), { 
          hiddenFor: arrayUnion(state.currentUserId) 
        });
      } catch (e) {
        console.error("Hide failed:", e);
      }
    };

    confirmModalActionContainer.appendChild(btnForMe);
  }

  confirmModal.classList.add("is-open");
  confirmModal.setAttribute("aria-hidden", "false");
}

function closeConfirmModal() {
  if (!confirmModal) return;

  confirmModal.classList.remove("is-open");
  confirmModal.setAttribute("aria-hidden", "true");
}

// ═══════════════════════════════════════════════════════════════════
// REACTIONS HANDLING
// ═══════════════════════════════════════════════════════════════════

async function toggleReaction(docId, collectionName, reactionType, hasReacted) {
  if (!state.db || !state.currentUserId) return;

  if (!Object.prototype.hasOwnProperty.call(REACTION_TYPES, reactionType)) {
    return;
  }

  const escapedId = escapeSelector(docId);
  const bubble = document.querySelector(`.message-bubble[data-id="${escapedId}"]`);

  if (bubble) {
    updateReactionUI(bubble, reactionType, !hasReacted, collectionName);
  }

  const docRef = doc(state.db, collectionName, docId);

  try {
    if (hasReacted) {
      await updateDoc(docRef, {
        [`reactions.${reactionType}`]: arrayRemove(state.currentUserId)
      });
    } else {
      await updateDoc(docRef, {
        [`reactions.${reactionType}`]: arrayUnion(state.currentUserId)
      });
    }

    console.log('Reaction synced:', reactionType, hasReacted ? 'removed' : 'added');
  } catch (error) {
    console.error("Reaction error:", error);

    if (bubble) {
      updateReactionUI(bubble, reactionType, hasReacted, collectionName);
    }

    if (error.code === 'permission-denied') {
      showToast("Unable to add reaction.", "error");
    }
  }
}

function updateReactionUI(bubble, reactionType, isAdding, collectionName) {
  if (!bubble) return;

  let chipsContainer = bubble.querySelector('.reaction-chips-container');

  if (!chipsContainer) {
    chipsContainer = document.createElement('div');
    chipsContainer.className = 'reaction-chips-container';
    bubble.appendChild(chipsContainer);
  }

  let existingChip = null;
  chipsContainer.querySelectorAll('.reaction-chip').forEach(chip => {
    const emoji = chip.querySelector('span')?.textContent;
    if (emoji === REACTION_TYPES[reactionType]) {
      existingChip = chip;
    }
  });

  if (isAdding) {
    if (existingChip) {
      const countSpan = existingChip.querySelectorAll('span')[1];
      if (countSpan) {
        const currentCount = parseInt(countSpan.textContent.trim()) || 0;
        countSpan.textContent = ` ${currentCount + 1}`;
      }
      existingChip.classList.add('user-reacted');
    } else {
      const chip = document.createElement('div');
      chip.className = 'reaction-chip user-reacted';
      chip.style.animation = 'modalZoom 0.2s ease-out';

      const emojiSpan = document.createElement('span');
      emojiSpan.textContent = REACTION_TYPES[reactionType];

      const countSpan = document.createElement('span');
      countSpan.textContent = ' 1';

      chip.appendChild(emojiSpan);
      chip.appendChild(countSpan);

      chip.onclick = (e) => {
        e.stopPropagation();
        toggleReaction(bubble.dataset.id, collectionName, reactionType, true);
      };

      chipsContainer.appendChild(chip);
    }

    bubble.classList.add('has-reactions');
  } else {
    if (existingChip) {
      const countSpan = existingChip.querySelectorAll('span')[1];
      if (countSpan) {
        const currentCount = parseInt(countSpan.textContent.trim()) || 0;
        if (currentCount <= 1) {
          existingChip.remove();
          if (chipsContainer.children.length === 0) {
            chipsContainer.remove();
            bubble.classList.remove('has-reactions');
          }
        } else {
          countSpan.textContent = ` ${currentCount - 1}`;
          existingChip.classList.remove('user-reacted');
        }
      }
    }
  }
}

// ═══════════════════════════════════════════════════════════════════
// CONTEXT MENU (DROPDOWN) HANDLING
// ═══════════════════════════════════════════════════════════════════

function showDropdownMenu(event, data) {
  event.stopPropagation();

  if (!contextMenu) {
    console.warn('Context menu element not found');
    return;
  }

  if (contextMenu.classList.contains("is-open") && 
      state.currentContextMenuData?.id === data.id) {
    hideDropdownMenu();
    return;
  }

  state.currentContextMenuData = { ...data };

  const now = Date.now();
  const messageTime = parseInt(data.timestamp, 10);
  const isRecent = isNaN(messageTime) ? true : (now - messageTime < 900000);

  const isMine = data.isMine === "true";
  const isAdmin = state.isCurrentUserAdmin;

  if (menuEdit) {
    menuEdit.style.display = isRecent && isMine ? "block" : "none";
  }

  if (menuDelete) {
    menuDelete.style.display = "block";
  }

  if (menuPin) {
    menuPin.style.display = isAdmin ? "block" : "none";
    menuPin.textContent = data.isPinned === "true" 
      ? "Unpin Message" 
      : "Pin Message 📌";
  }

  if (menuBan) {
    menuBan.style.display = (isAdmin && !isMine) ? "block" : "none";

    if (isAdmin && !isMine && data.userId) {
      (async () => {
        try {
          const banDocRef = doc(state.db, "banned_users", data.userId);
          const banDocSnap = await getDoc(banDocRef);
          const isBanned = banDocSnap.exists();

          if (menuBan) {
            menuBan.textContent = isBanned ? "Unban User ✅" : "Ban User 🚫";
            menuBan.className = isBanned
              ? "text-green-500 hover:text-green-400 font-bold border-t border-[#333] mt-1 pt-1"
              : "text-red-500 hover:text-red-400 font-bold border-t border-[#333] mt-1 pt-1";
          }
        } catch (e) {
          console.warn("Could not check ban status for menu:", e);
        }
      })();
    }
  }

  const rect = event.currentTarget.getBoundingClientRect();
  const menuWidth = 150;

  let left = isMine ? rect.right - menuWidth : rect.left;

  if (left < 10) left = 10;
  if (left + menuWidth > window.innerWidth - 10) {
    left = window.innerWidth - menuWidth - 10;
  }

  contextMenu.style.top = `${rect.bottom + 2}px`;
  contextMenu.style.left = `${left}px`;

  contextMenu.classList.add("is-open");
}

function hideDropdownMenu() {
  if (contextMenu) {
    contextMenu.classList.remove("is-open");
  }
}

// ═══════════════════════════════════════════════════════════════════
// SELECTION MODE
// ═══════════════════════════════════════════════════════════════════

function handleMessageClick(bubble) {
  if (!state.isSelectionMode) return;

  const docId = bubble.dataset.id;

  if (state.selectedMessages.has(docId)) {
    state.selectedMessages.delete(docId);
    bubble.classList.remove("selected-message");
  } else {
    state.selectedMessages.add(docId);
    bubble.classList.add("selected-message");
  }

  updateSelectionBar();
}

function enterSelectionMode() {
  state.isSelectionMode = true;
  document.body.classList.add("selection-mode");

  if (selectionBar) {
    selectionBar.classList.remove("hidden");
    selectionBar.style.display = "flex";
  }

  if (chatForm) chatForm.classList.add("hidden");
  if (confessionForm) confessionForm.classList.add("hidden");

  if (state.currentContextMenuData) {
    const docId = state.currentContextMenuData.id;
    state.selectedMessages.add(docId);

    const escapedId = escapeSelector(docId);
    const bubble = document.querySelector(`.message-bubble[data-id="${escapedId}"]`);
    if (bubble) {
      bubble.classList.add("selected-message");
    }
  }

  updateSelectionBar();
}

function exitSelectionMode() {
  state.isSelectionMode = false;
  document.body.classList.remove("selection-mode");

  if (selectionBar) {
    selectionBar.classList.add("hidden");
  }

  state.selectedMessages.clear();

  if (state.currentPage === "chat") {
    if (chatForm) {
      chatForm.classList.remove("hidden");
      chatForm.classList.add("flex");
    }
  } else {
    if (confessionForm) {
      confessionForm.classList.remove("hidden");
      confessionForm.classList.add("flex");
    }
  }

  document.querySelectorAll(".selected-message").forEach(el => {
    el.classList.remove("selected-message");
  });
}

function updateSelectionBar() {
  const count = state.selectedMessages.size;
  setTextSafely(selectionCount, `${count} selected`);

  if (count === 0 && state.isSelectionMode) {
    exitSelectionMode();
  }
}

async function handleMultiDelete() {
  const count = state.selectedMessages.size;
  if (count === 0) return;

  let allMine = true;
  state.selectedMessages.forEach(id => {
    const escapedId = escapeSelector(id);
    const bubble = document.querySelector(`.message-bubble[data-id="${escapedId}"]`);
    if (bubble && bubble.dataset.isMine !== "true") {
      allMine = false;
    }
  });

  const isAdmin = state.isCurrentUserAdmin;
  const canDeleteEveryone = isAdmin || allMine;

  setTextSafely(confirmModalText, `Delete ${count} message${count > 1 ? 's' : ''}?`);

  if (confirmModalActionContainer) {
    confirmModalActionContainer.innerHTML = '';

    const btnForMe = document.createElement('button');
    btnForMe.type = 'button';
    btnForMe.className = "flex-1 px-4 py-2 rounded-lg font-bold text-sm border border-white text-white hover:bg-white hover:text-black transition";
    btnForMe.textContent = "FOR ME";
    btnForMe.onclick = async () => {
      closeConfirmModal();

      const batch = writeBatch(state.db);
      state.selectedMessages.forEach((docId) => {
        const docRef = doc(state.db, state.currentPage, docId);
        batch.update(docRef, { hiddenFor: arrayUnion(state.currentUserId) });
      });

      try {
        await batch.commit();
      } catch (e) {
        console.error('Batch hide error:', e);
        showToast("Failed to hide messages.", "error");
      }

      exitSelectionMode();
    };

    confirmModalActionContainer.appendChild(btnForMe);

    if (canDeleteEveryone) {
      const btnEveryone = document.createElement('button');
      btnEveryone.type = 'button';
      btnEveryone.className = "flex-1 px-4 py-2 rounded-lg font-bold text-sm bg-red-600 text-white hover:bg-red-500 border border-red-600 transition";
      btnEveryone.textContent = "EVERYONE";
      btnEveryone.onclick = async () => {
        closeConfirmModal();

        const batch = writeBatch(state.db);
        state.selectedMessages.forEach((docId) => {
          const docRef = doc(state.db, state.currentPage, docId);
          batch.delete(docRef);
        });

        try {
          await batch.commit();
        } catch (e) {
          console.error('Batch delete error:', e);
          showToast("Failed to delete messages.", "error");
        }

        exitSelectionMode();
      };

      confirmModalActionContainer.appendChild(btnEveryone);
    }
  }

  if (confirmModal) {
    confirmModal.classList.add("is-open");
    confirmModal.setAttribute("aria-hidden", "false");
  }
}

// ═══════════════════════════════════════════════════════════════════
// PAGE NAVIGATION
// ═══════════════════════════════════════════════════════════════════

function showPage(page) {
  if (page !== 'chat' && page !== 'confessions') {
    page = 'chat';
  }

  state.currentPage = page;

  if (state.isSelectionMode) exitSelectionMode();
  cancelReplyMode();

  document.querySelectorAll(".reaction-picker").forEach(p => p.remove());

  if (typeof unsubscribers.confessions === 'function') {
    unsubscribers.confessions();
    unsubscribers.confessions = () => {};
  }

  if (typeof unsubscribers.chat === 'function') {
    unsubscribers.chat();
    unsubscribers.chat = () => {};
  }

  if (typeof unsubscribers.typingStatus === 'function') {
    unsubscribers.typingStatus();
    unsubscribers.typingStatus = () => {};
  }

  if (typingIndicator) typingIndicator.innerHTML = "&nbsp;";

  state.unreadMessages = 0;
  if (newMsgCount) newMsgCount.classList.add("hidden");
  if (scrollToBottomBtn) {
    scrollToBottomBtn.classList.add("hidden");
    scrollToBottomBtn.style.display = "";
  }

  listenForPinnedMessages();

  if (page === "confessions") {
    navConfessions?.classList.add("active");
    navConfessions?.setAttribute("aria-pressed", "true");
    navChat?.classList.remove("active");
    navChat?.setAttribute("aria-pressed", "false");

    if (confessionForm) {
      confessionForm.classList.add("flex");
      confessionForm.classList.remove("hidden");
    }
    if (chatForm) {
      chatForm.classList.add("hidden");
      chatForm.classList.remove("flex");
    }

    if (typingIndicator) typingIndicator.classList.add("hidden");

    listenForConfessions();
  } else {
    navChat?.classList.add("active");
    navChat?.setAttribute("aria-pressed", "true");
    navConfessions?.classList.remove("active");
    navConfessions?.setAttribute("aria-pressed", "false");

    if (chatForm) {
      chatForm.classList.add("flex");
      chatForm.classList.remove("hidden");
    }
    if (confessionForm) {
      confessionForm.classList.add("hidden");
      confessionForm.classList.remove("flex");
    }

    if (typingIndicator) typingIndicator.classList.remove("hidden");

    listenForChat();
    listenForTyping();
  }
}

// ═══════════════════════════════════════════════════════════════════
// FEED RENDERING
// ═══════════════════════════════════════════════════════════════════

function safeRenderFeed(docs, type, snapshot, isRerender, isFirstSnapshot = false) {
  try {
    renderFeed(docs, type, snapshot, isRerender, isFirstSnapshot);
  } catch (error) {
    console.error('Render error:', error);

    if (feedContainer) {
      feedContainer.innerHTML = '';

      const errorDiv = document.createElement("div");
      errorDiv.className = "text-center p-4 text-red-500";
      errorDiv.textContent = "Error rendering messages. Please refresh.";

      const retryBtn = document.createElement("button");
      retryBtn.className = "mt-2 px-4 py-2 bg-white text-black rounded";
      retryBtn.textContent = "Retry";
      retryBtn.onclick = () => showPage(state.currentPage);

      feedContainer.appendChild(errorDiv);
      feedContainer.appendChild(retryBtn);
    }
  }
}

function listenForConfessions(isRerender = false) {
  if (isRerender) {
    safeRenderFeed(state.lastConfessionDocs, "confessions", null, true);
    return;
  }

  if (typeof unsubscribers.chat === 'function') {
    unsubscribers.chat();
    unsubscribers.chat = () => {};
  }

  if (feedContainer) {
    feedContainer.innerHTML = '';
    const loadingDiv = document.createElement('div');
    loadingDiv.id = 'loading';
    loadingDiv.className = 'text-center p-4 text-[#888888] text-sm';
    loadingDiv.textContent = 'LOADING CONFESSIONS...';
    feedContainer.appendChild(loadingDiv);
  }

  let isFirstSnapshot = true;

  unsubscribers.confessions = onSnapshot(
    query(state.confessionsCollection, orderBy("timestamp", "asc")),
    (snapshot) => {
      state.lastConfessionDocs = snapshot.docs;
      safeRenderFeed(state.lastConfessionDocs, "confessions", snapshot, false, isFirstSnapshot);
      isFirstSnapshot = false;
    },
    (error) => {
      console.error('Confessions error:', error);
      if (feedContainer) {
        feedContainer.innerHTML = '';
        const errorDiv = document.createElement("div");
        errorDiv.className = "text-center p-4 text-red-500";
        errorDiv.textContent = "Error loading confessions: " + error.message;
        feedContainer.appendChild(errorDiv);
      }
    }
  );
}

function listenForChat(isRerender = false) {
  if (isRerender) {
    safeRenderFeed(state.lastChatDocs, "chat", null, true);
    return;
  }

  if (typeof unsubscribers.confessions === 'function') {
    unsubscribers.confessions();
    unsubscribers.confessions = () => {};
  }

  if (feedContainer) {
    feedContainer.innerHTML = '';
    const loadingDiv = document.createElement('div');
    loadingDiv.id = 'loading';
    loadingDiv.className = 'text-center p-4 text-[#888888] text-sm';
    loadingDiv.textContent = 'LOADING CHAT...';
    feedContainer.appendChild(loadingDiv);
  }

  let isFirstSnapshot = true;

  unsubscribers.chat = onSnapshot(
    query(state.chatCollection, orderBy("timestamp", "asc")),
    (snapshot) => {
      state.lastChatDocs = snapshot.docs;
      safeRenderFeed(state.lastChatDocs, "chat", snapshot, false, isFirstSnapshot);
      isFirstSnapshot = false;
    },
    (error) => {
      console.error('Chat error:', error);
      if (feedContainer) {
        feedContainer.innerHTML = '';
        const errorDiv = document.createElement("div");
        errorDiv.className = "text-center p-4 text-red-500";
        errorDiv.textContent = "Error loading chat: " + error.message;
        feedContainer.appendChild(errorDiv);
      }
    }
  );
}

function listenForTyping() {
  if (typeof unsubscribers.typingStatus === 'function') {
    unsubscribers.typingStatus();
    unsubscribers.typingStatus = () => {};
  }

  unsubscribers.typingStatus = onSnapshot(
    state.typingStatusCollection, 
    (snapshot) => {
      const now = Date.now();
      const typingUsers = [];

      snapshot.docs.forEach((docSnap) => {
        const data = docSnap.data();
        const oduserId = docSnap.id;

        if (oduserId === state.currentUserId) return;

        if (data.isTyping && data.timestamp) {
          const timeSinceTyping = now - data.timestamp;

          if (timeSinceTyping < TYPING_STALE_THRESHOLD) {
            const username = state.userProfiles[oduserId]?.username || "Someone";
            typingUsers.push(username);
          }
        }
      });

      if (typingIndicator) {
        if (typingUsers.length === 0) {
          typingIndicator.innerHTML = "&nbsp;";
        } else if (typingUsers.length === 1) {
          setTextSafely(typingIndicator, `${typingUsers[0]} is typing...`);
        } else if (typingUsers.length === 2) {
          setTextSafely(typingIndicator, `${typingUsers[0]} and ${typingUsers[1]} are typing...`);
        } else {
          setTextSafely(typingIndicator, `${typingUsers.length} people are typing...`);
        }
      }
    },
    (error) => {
      console.warn("Typing listener error:", error);
      if (typingIndicator) {
        typingIndicator.innerHTML = "&nbsp;";
      }
    }
  );
}

const updateTypingStatus = debounce(async (isTyping) => {
  if (!state.db || !state.currentUserId) return;

  if (state.typingTimeout) {
    clearTimeout(state.typingTimeout);
    state.typingTimeout = null;
  }

  try {
    const typingDocRef = doc(state.db, "typingStatus", state.currentUserId);
    await setDoc(typingDocRef, { 
      isTyping: isTyping, 
      timestamp: Date.now() 
    });

    if (isTyping) {
      state.typingTimeout = setTimeout(() => {
        updateTypingStatus(false);
      }, TYPING_TIMEOUT);
    }
  } catch (e) {
    // Silently fail typing status updates
  }
}, 300);

function renderFeed(docs, type, snapshot, isRerender, isFirstSnapshot = false) {
  if (!feedContainer) return;

  document.querySelectorAll(".reaction-picker").forEach(p => p.remove());

  if (!isRerender && snapshot) {
    snapshot.docChanges().forEach((change) => {
      if (change.type === "added") {
        const data = change.doc.data();
        const msgTime = data.timestamp ? data.timestamp.toMillis() : 0;
        const isNewMessage = msgTime > appStartTime;
        const isHidden = data.hiddenFor?.includes(state.currentUserId);

        if (isNewMessage && 
            (document.visibilityState === "hidden" || state.currentPage !== type) && 
            data.userId !== state.currentUserId && 
            !isHidden) {
          showNotification(
            type === "chat" ? "New Chat" : "New Confession", 
            data.text?.substring(0, 100) || "New message"
          );
        }
      }
    });
  }

  const prevScrollTop = feedContainer.scrollTop;
  const wasAtBottom = state.userIsAtBottom;

  feedContainer.innerHTML = "";

  if (docs.length === 0) {
    const emptyDiv = document.createElement("div");
    emptyDiv.id = "loading";
    emptyDiv.className = "text-center p-4 text-[#888888] text-sm";
    emptyDiv.textContent = `NO ${type.toUpperCase()} YET. BE THE FIRST!`;
    feedContainer.appendChild(emptyDiv);
    return;
  }

  let lastUserId = null;
  let lastDateString = null;

  docs.forEach((docInstance) => {
    const data = docInstance.data();

    if (data.hiddenFor?.includes(state.currentUserId)) {
      return;
    }

    const text = data.text || "...";
    const messageDateObj = data.timestamp ? data.timestamp.toDate() : new Date();
    const messageDateStr = messageDateObj.toDateString();

    const docUserId = data.userId;

    if (docUserId && !state.userProfiles[docUserId]) {
      requestUserProfile(docUserId);
    }

    if (data.replyTo?.userId && !state.userProfiles[data.replyTo.userId]) {
      requestUserProfile(data.replyTo.userId);
    }

    if (lastDateString !== messageDateStr) {
      const sepDiv = document.createElement('div');
      sepDiv.className = 'date-separator';

      const sepSpan = document.createElement('span');
      sepSpan.textContent = getDateHeader(messageDateObj);
      sepDiv.appendChild(sepSpan);

      feedContainer.appendChild(sepDiv);
      lastDateString = messageDateStr;
      lastUserId = null;
    }

    const profile = state.userProfiles[docUserId] || {};
    const username = profile.username || "Anonymous";
    const firstChar = (username[0] || "?").toUpperCase();
    const photoURL = profile.profilePhotoURL || `https://ui-avatars.com/api/?name=${encodeURIComponent(firstChar)}&background=random&size=64`;

    const isMine = state.currentUserId && docUserId === state.currentUserId;
    const isConsecutive = docUserId && docUserId === lastUserId;
    lastUserId = docUserId;

    const userColor = getUserColor(docUserId);

    const alignWrapper = document.createElement("div");
    alignWrapper.className = `flex w-full ${isMine ? "justify-end" : "justify-start"}`;

    const row = document.createElement("div");
    row.className = "message-wrapper";

    const bubble = document.createElement("div");
    bubble.className = `message-bubble rounded-lg max-w-xs sm:max-w-md md:max-w-lg ${isMine ? "my-message" : ""}`;

    if (data.isPinned) {
      bubble.classList.add("pinned");
    }

    bubble.dataset.id = docInstance.id;
    bubble.dataset.text = text;
    bubble.dataset.isMine = String(isMine);
    bubble.dataset.userId = docUserId || '';
    bubble.dataset.username = username;
    bubble.dataset.isPinned = String(data.isPinned || false);
    bubble.dataset.timestamp = data.timestamp ? String(data.timestamp.toMillis()) : String(Date.now());

    if (!isMine) {
  bubble.style.borderLeft = `3px solid ${userColor}`;
  bubble.style.background = `linear-gradient(90deg, ${userColor}10, transparent)`;
} else {
  // Sent messages - mirror the received bubble styling
  bubble.style.borderRight = `3px solid ${userColor}`;
  bubble.style.background = `linear-gradient(270deg, ${userColor}10, transparent)`;
}
    if (state.isSelectionMode && state.selectedMessages.has(docInstance.id)) {
      bubble.classList.add("selected-message");
    }

    bubble.addEventListener('click', (e) => {
      if (state.isSelectionMode) {
        e.preventDefault();
        e.stopPropagation();
        handleMessageClick(bubble);
      }
    });

    const kebabBtn = document.createElement("button");
    kebabBtn.type = "button";
    kebabBtn.className = "kebab-btn";
    kebabBtn.setAttribute("aria-label", "Message options");
    kebabBtn.appendChild(createKebabIcon());

    kebabBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      showDropdownMenu(e, bubble.dataset);
    });

    if (!isConsecutive) {
      const headerElement = document.createElement("div");
      headerElement.className = `flex items-center gap-1.5 mb-1 ${isMine ? "justify-end" : "justify-start"}`;

      const imgElement = document.createElement("img");
      imgElement.src = photoURL;
      imgElement.alt = "";
      imgElement.className = `chat-pfp ${isMine ? "order-2" : "order-1"}`;
      imgElement.loading = "lazy";
      imgElement.draggable = false;

      if (!isMine) imgElement.style.borderColor = userColor;

      imgElement.onerror = function() {
        this.src = `https://ui-avatars.com/api/?name=${encodeURIComponent(username)}&background=random&size=64`;
      };

      const usernameElement = document.createElement("div");
      usernameElement.className = `font-bold text-sm opacity-90 ${isMine ? "order-1 text-right" : "order-2 text-left"}`;
      usernameElement.textContent = username;

      if (!isMine) usernameElement.style.color = userColor;

      headerElement.appendChild(imgElement);
      headerElement.appendChild(usernameElement);

      bubble.appendChild(headerElement);
    }

    if (data.replyTo) {
      const replyPreview = document.createElement("div");
      replyPreview.className = "reply-preview";

      const replyAuthorEl = document.createElement("div");
      replyAuthorEl.className = "reply-author";
      replyAuthorEl.textContent = state.userProfiles[data.replyTo.userId]?.username || "Anonymous";

      if (!isMine) {
        replyPreview.style.borderLeftColor = userColor;
        replyAuthorEl.style.color = userColor;
      }

      const replyTextEl = document.createElement("div");
      replyTextEl.className = "reply-text";
      replyTextEl.textContent = data.replyTo.text;

      replyPreview.appendChild(replyAuthorEl);
      replyPreview.appendChild(replyTextEl);

      replyPreview.addEventListener("click", (e) => {
        e.stopPropagation();
        const escapedId = escapeSelector(data.replyTo.messageId);
        const originalBubble = document.querySelector(`.message-bubble[data-id="${escapedId}"]`);

        if (originalBubble) {
          originalBubble.scrollIntoView({ behavior: "smooth", block: "center" });
          originalBubble.style.backgroundColor = "rgba(255, 255, 255, 0.1)";

          setTimeout(() => {
            originalBubble.style.backgroundColor = "";
          }, 1000);
        }
      });

      bubble.appendChild(replyPreview);
    }

    const textElement = document.createElement("p");
    textElement.className = "text-left";

    if (data.isPinned) {
      const pinIcon = document.createElement("span");
      pinIcon.className = "text-amber-400 mr-1";
      pinIcon.setAttribute("aria-hidden", "true");
      pinIcon.textContent = "📌";
      textElement.appendChild(pinIcon);
    }

    textElement.appendChild(document.createTextNode(text));
    bubble.appendChild(textElement);

    const footerDiv = document.createElement("div");
    footerDiv.className = "bubble-footer";
    footerDiv.style.justifyContent = isMine ? "flex-end" : "flex-start";

    const timeElement = document.createElement("span");
    timeElement.className = "inner-timestamp";
    timeElement.dataset.ts = data.timestamp ? String(data.timestamp.toMillis()) : String(Date.now());

    let timeText = formatMessageTime(messageDateObj);
    if (data.edited) timeText += " (edited)";
    timeElement.textContent = timeText;

    footerDiv.appendChild(timeElement);
    bubble.appendChild(footerDiv);

    const docReactions = data.reactions || {};

    const chipsContainer = document.createElement("div");
    chipsContainer.className = "reaction-chips-container";

    let hasChips = false;

    Object.keys(REACTION_TYPES).forEach(rtype => {
      const userIds = docReactions[rtype] || [];

      if (userIds.length > 0) {
        hasChips = true;

        const chip = document.createElement("div");
        chip.className = "reaction-chip";

        const hasReacted = userIds.includes(state.currentUserId);
        if (hasReacted) chip.classList.add("user-reacted");

        const emojiSpan = document.createElement("span");
        emojiSpan.textContent = REACTION_TYPES[rtype];

        const countSpan = document.createElement("span");
        countSpan.textContent = ` ${userIds.length}`;

        chip.appendChild(emojiSpan);
        chip.appendChild(countSpan);

        chip.onclick = (e) => {
          e.stopPropagation();
          toggleReaction(docInstance.id, type, rtype, hasReacted);
        };

        chipsContainer.appendChild(chip);
      }
    });

    if (hasChips) {
      bubble.appendChild(chipsContainer);
      bubble.classList.add("has-reactions");
    }

    const replyBtn = document.createElement("button");
    replyBtn.type = "button";
    replyBtn.className = "side-action-btn";
    replyBtn.setAttribute("aria-label", "Reply to message");
    replyBtn.textContent = "↩";

    replyBtn.onclick = (e) => {
      e.stopPropagation();
      startReplyMode(bubble.dataset);
    };

    const reactBtn = document.createElement("button");
    reactBtn.type = "button";
    reactBtn.className = "side-action-btn";
    reactBtn.setAttribute("aria-label", "Add reaction");
    reactBtn.textContent = "♡";

    const picker = document.createElement("div");
    picker.className = "reaction-picker hidden";
    picker.setAttribute("role", "menu");

    Object.entries(REACTION_TYPES).forEach(([rtype, emoji]) => {
      const opt = document.createElement("span");
      opt.className = "reaction-option";
      opt.setAttribute("role", "menuitem");
      opt.textContent = emoji;

      opt.onclick = (e) => {
        e.stopPropagation();
        const hasReacted = (docReactions[rtype] || []).includes(state.currentUserId);
        toggleReaction(docInstance.id, type, rtype, hasReacted);
        picker.classList.add("hidden");
        picker.remove();
      };

      picker.appendChild(opt);
    });

    reactBtn.onclick = (e) => {
      e.stopPropagation();

      document.querySelectorAll(".reaction-picker").forEach(p => {
        p.classList.add("hidden");
        p.remove();
      });

      const rect = reactBtn.getBoundingClientRect();
      picker.style.top = `${rect.top - 60}px`;

      if (window.innerWidth < 640) {
        picker.style.left = "50%";
        picker.style.transform = "translateX(-50%)";
      } else {
        picker.style.left = `${rect.left}px`;
      }

      picker.classList.remove("hidden");
      document.body.appendChild(picker);
    };

    const bubbleWrapper = document.createElement("div");
    bubbleWrapper.className = `bubble-wrapper ${isMine ? "my-bubble-wrapper" : ""} ${isConsecutive ? "mt-0.5" : "mt-2"}`;

    bubbleWrapper.appendChild(kebabBtn);
    bubbleWrapper.appendChild(bubble);

    if (isMine) {
      row.appendChild(reactBtn);
      row.appendChild(replyBtn);
      row.appendChild(bubbleWrapper);
    } else {
      row.appendChild(bubbleWrapper);
      row.appendChild(replyBtn);
      row.appendChild(reactBtn);
    }

    alignWrapper.appendChild(row);
    feedContainer.appendChild(alignWrapper);
  });

  const scrollAnchor = document.createElement("div");
  scrollAnchor.id = "scrollAnchor";
  scrollAnchor.style.height = "4px";
  scrollAnchor.style.width = "100%";
  scrollAnchor.style.flexShrink = "0";
  feedContainer.appendChild(scrollAnchor);

  if (state.bottomObserver) {
    state.bottomObserver.disconnect();
    state.bottomObserver.observe(scrollAnchor);
  }

  const hasNewMessages = snapshot && 
    snapshot.docChanges().some(change => change.type === 'added');

  if (isFirstSnapshot && docs.length > 0) {
    feedContainer.style.scrollBehavior = "auto";
    scrollToBottom();

    requestAnimationFrame(() => {
      scrollToBottom();
      feedContainer.style.scrollBehavior = "smooth";
    });
  } else if (hasNewMessages) {
    const lastDoc = docs[docs.length - 1];
    const isOwnMessage = lastDoc && lastDoc.data().userId === state.currentUserId;

    if (isOwnMessage || wasAtBottom) {
      scrollToBottom();
    } else {
      state.unreadMessages++;
      updateScrollButton();
    }
  } else {
    feedContainer.scrollTop = prevScrollTop;
  }
}

// ═══════════════════════════════════════════════════════════════════
// MESSAGE POSTING
// ═══════════════════════════════════════════════════════════════════

async function postMessage(collectionRef, input) {
  if (!state.db || !state.currentUserId) {
    showToast("Not connected. Please refresh.", "error");
    return;
  }

  if (state.currentUsername === "Anonymous") {
    showToast("Please set a username first!", "error");
    openProfileModal();
    return;
  }

  if (state.isDeviceBanned) {
    showToast("Your device has been banned.", "error");
    return;
  }

  if (state.isBanned) {
    showToast("You have been banned.", "error");
    return;
  }

  const spamCheck = checkSpamStatus();

  if (!spamCheck.allowed) {
    if (spamCheck.shouldBan) {
      await autoBanForSpam();
      return;
    }
  }

  if (spamCheck.warning) {
    showSpamWarning(spamCheck.warning);
  }

  const validation = validateMessageBeforePost(input.value);

  if (!validation.valid) {
    showToast(validation.error, "error");
    // Keep focus on input even on validation error
    input.focus({ preventScroll: true });
    return;
  }

  const text = validation.text;

  const isChat = collectionRef === state.chatCollection;

  const submitBtn = isChat ? 
    document.getElementById('chatButton') : 
    document.getElementById('confessionButton');

  // Store reference to input for refocusing later
  const inputToRefocus = input;

  const resetUI = () => {
    if (input) {
      input.disabled = false;
    }
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.classList.remove('loading');
      submitBtn.textContent = isChat ? 'SEND ✈️' : 'POST ✍️';
    }
  };

  // Don't disable input - just disable the button to prevent double-submit
  // This helps keep the keyboard open
  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.classList.add('loading');
    submitBtn.textContent = 'SENDING...';
  }

  try {
    console.log('Posting message...');

    const messageData = {
      text: text,
      timestamp: serverTimestamp(),
      userId: state.currentUserId,
    };

    if (state.replyToMessage) {
      messageData.replyTo = {
        messageId: state.replyToMessage.id,
        userId: state.replyToMessage.userId,
        text: (state.replyToMessage.text || '').substring(0, 500)
      };
    }

    const addResult = await withTimeout(
      addDoc(collectionRef, messageData),
      15000,
      null
    );

    if (addResult === null) {
      throw new Error('Message send timed out');
    }

    console.log('Message posted successfully:', addResult.id);

    recordMessage();

    // Clear input value
    if (input) {
      input.value = "";
    }

    cancelReplyMode();
    updateTypingStatus(false);
    scrollToBottom();

    const counter = isChat ? chatCharCount : confessionCharCount;
    if (counter) {
      updateCharacterCounter(input, counter);
    }

    console.log('Message flow completed');

    resetUI();
    
    // CRITICAL: Refocus input to prevent keyboard from closing on mobile
    // Using requestAnimationFrame ensures this happens after all DOM updates
    requestAnimationFrame(() => {
      if (inputToRefocus) {
        // preventScroll: true prevents the page from jumping
        inputToRefocus.focus({ preventScroll: true });
      }
    });

  } catch (error) {
    console.error('Post error:', error);

    if (error.code === 'permission-denied') {
      showToast("Permission denied. Please wait a moment and try again.", "error");
    } else if (error.message === 'Message send timed out') {
      showToast("Message timed out. Please check your connection.", "error");
    } else if (error.code === 'unavailable') {
      showToast("Server unavailable. Please try again.", "error");
    } else {
      showToast("Failed to send message. Please try again.", "error");
    }

    resetUI();
    
    // Refocus even on error
    requestAnimationFrame(() => {
      if (inputToRefocus) {
        inputToRefocus.focus({ preventScroll: true });
      }
    });
  }
}

// ═══════════════════════════════════════════════════════════════════
// REPLY MODE
// ═══════════════════════════════════════════════════════════════════

function startReplyMode(messageData) {
  const repliedUserId = messageData.userId || 
    (messageData.isMine === "true" ? state.currentUserId : null);

  state.replyToMessage = {
    id: messageData.id,
    userId: repliedUserId,
    text: messageData.text
  };

  const repliedUsername = state.userProfiles[repliedUserId]?.username || "Anonymous";

  setTextSafely(replyAuthor, `Replying to ${repliedUsername}`);
  setTextSafely(replyText, state.replyToMessage.text);

  if (replyBar) {
    replyBar.classList.add("show");
  }

  const input = state.currentPage === "chat" ? chatInput : confessionInput;
  if (input) input.focus();
}

function cancelReplyMode() {
  state.replyToMessage = null;

  if (replyBar) {
    replyBar.classList.remove("show");
  }
}

// ═══════════════════════════════════════════════════════════════════
// EVENT LISTENERS
// ═══════════════════════════════════════════════════════════════════

// Prevent keyboard flickering - desktop only fix
// Mobile will work naturally, and we refocus after send in postMessage()
if (window.matchMedia('(hover: hover)').matches) {
  document.getElementById('chatButton')?.addEventListener('mousedown', (e) => {
    e.preventDefault();
  }, { passive: false });

  document.getElementById('confessionButton')?.addEventListener('mousedown', (e) => {
    e.preventDefault();
  }, { passive: false });
}

// Close reaction pickers and context menu when clicking outside
document.addEventListener("click", (e) => {
  if (!e.target.closest(".side-action-btn") && !e.target.closest(".reaction-picker")) {
    document.querySelectorAll(".reaction-picker").forEach(p => {
      p.classList.add("hidden");
      p.remove();
    });
  }

  if (!contextMenu?.contains(e.target) && !e.target.closest(".kebab-btn")) {
    hideDropdownMenu();
  }
});

// Update timestamps every minute
setInterval(() => {
  document.querySelectorAll('.inner-timestamp').forEach(el => {
    const ts = parseInt(el.dataset.ts, 10);
    if (ts > 0) {
      const isEdited = el.textContent.includes("(edited)");
      el.textContent = formatMessageTime(new Date(ts)) + (isEdited ? " (edited)" : "");
    }
  });
}, 60000);

// Scroll button
scrollToBottomBtn?.addEventListener("click", scrollToBottom);

// Form submissions
confessionForm?.addEventListener("submit", (e) => {
  e.preventDefault();
  e.stopPropagation();
  postMessage(state.confessionsCollection, confessionInput);
});

chatForm?.addEventListener("submit", (e) => {
  e.preventDefault();
  e.stopPropagation();
  postMessage(state.chatCollection, chatInput);
});

// Navigation
navConfessions?.addEventListener("click", () => showPage("confessions"));
navChat?.addEventListener("click", () => showPage("chat"));

navConfessions?.addEventListener("keydown", (e) => {
  if (e.key === "Enter" || e.key === " ") {
    e.preventDefault();
    showPage("confessions");
  }
});

navChat?.addEventListener("keydown", (e) => {
  if (e.key === "Enter" || e.key === " ") {
    e.preventDefault();
    showPage("chat");
  }
});

// Profile modal
profileButton?.addEventListener("click", openProfileModal);
modalCloseButton?.addEventListener("click", closeProfileModal);
modalSaveButton?.addEventListener("click", handleProfileSave);

// Edit modal
editModalCancelButton?.addEventListener("click", closeEditModal);
editModalSaveButton?.addEventListener("click", saveEdit);

// Confirm modal
confirmModalNoButton?.addEventListener("click", closeConfirmModal);

// Context menu actions
menuEdit?.addEventListener("click", () => {
  if (state.currentContextMenuData) {
    showEditModal(
      state.currentContextMenuData.id, 
      state.currentPage, 
      state.currentContextMenuData.text
    );
  }
  hideDropdownMenu();
});

menuDelete?.addEventListener("click", () => {
  if (state.currentContextMenuData) {
    const isMine = state.currentContextMenuData.isMine === "true";
    showConfirmModal(
      isMine ? "Delete this message?" : "Hide this message?", 
      isMine, 
      state.currentContextMenuData.id
    );
  }
  hideDropdownMenu();
});

menuSelect?.addEventListener("click", () => {
  enterSelectionMode();
  hideDropdownMenu();
});

// Selection mode
selectionCancel?.addEventListener("click", exitSelectionMode);
selectionDelete?.addEventListener("click", handleMultiDelete);

// Reply bar
cancelReply?.addEventListener("click", cancelReplyMode);

// Input event handlers
confessionInput?.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    postMessage(state.confessionsCollection, confessionInput);
  } else {
    updateTypingStatus(true);
  }
});

chatInput?.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    postMessage(state.chatCollection, chatInput);
  } else {
    updateTypingStatus(true);
  }
});

chatInput?.addEventListener("input", () => {
  updateTypingStatus(true);
  updateCharacterCounter(chatInput, chatCharCount);
});

confessionInput?.addEventListener("input", () => {
  updateTypingStatus(true);
  updateCharacterCounter(confessionInput, confessionCharCount);
});

// Keyboard shortcuts
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    if (profileModal?.classList.contains("is-open")) {
      closeProfileModal();
    } else if (editModal?.classList.contains("is-open")) {
      closeEditModal();
    } else if (confirmModal?.classList.contains("is-open")) {
      closeConfirmModal();
    } else if (contextMenu?.classList.contains("is-open")) {
      hideDropdownMenu();
    } else if (state.isSelectionMode) {
      exitSelectionMode();
    } else if (state.replyToMessage) {
      cancelReplyMode();
    }
  }
});

// Visibility change handler
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") {
    if (state.userIsAtBottom) {
      state.unreadMessages = 0;
      updateScrollButton();
    }
  }
});

// Before unload - clear typing status
window.addEventListener("beforeunload", () => {
  if (state.db && state.currentUserId) {
    updateTypingStatus(false);
  }
});

// Cleanup on page unload
window.addEventListener('unload', () => {
  cleanupAllListeners();
});

// ═══════════════════════════════════════════════════════════════════
// INITIALIZE APP
// ═══════════════════════════════════════════════════════════════════

initFirebase().catch(err => {
  console.error("Failed to initialize app:", err);
  setTextSafely(loading, "Error: Failed to initialize. Please refresh the page.");
  hideBanCheckOverlay();
});