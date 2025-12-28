'use strict';

// ============================================================
// KONVO - ANONYMOUS CHAT APPLICATION
// Version: 3.0 (Security Hardened)
// 
// Security Fixes Applied:
// - Issue #4: Removed client-side IP detection (server-side only)
// - Issue #6: Improved fallback fingerprint with more entropy
// - Issue #15: Added reCAPTCHA v3 integration
// - Issue #20: Sanitized all error messages
// - Issue #22: Sanitized notification content
// - Issue #23: Moved message sending to Cloud Functions
// ============================================================

// ============================
// MOBILE VIEWPORT SETUP
// ============================
(function setupMobileViewport() {
  let pendingUpdate = false;
  
  const apply = () => {
    if (pendingUpdate) return;
    pendingUpdate = true;
    
    requestAnimationFrame(() => {
      const viewport = window.visualViewport;
      const height = viewport?.height || window.innerHeight;
      const offsetTop = viewport?.offsetTop || 0;
      
      document.documentElement.style.setProperty('--app-height', `${height}px`);
      document.documentElement.style.setProperty('--viewport-offset', `${offsetTop}px`);
      
      if (document.body) {
        document.body.style.height = `${height}px`;
        document.body.style.maxHeight = `${height}px`;
      }
      
      if (typeof state !== 'undefined' && state?.userIsAtBottom && typeof feedContainer !== 'undefined' && feedContainer) {
        feedContainer.scrollTop = feedContainer.scrollHeight;
      }
      
      pendingUpdate = false;
    });
  };
  
  apply();
  
  let resizeTimeout;
  const debouncedApply = () => {
    clearTimeout(resizeTimeout);
    resizeTimeout = setTimeout(apply, 50);
  };
  
  window.addEventListener('resize', debouncedApply, { passive: true });
  
  if (window.visualViewport) {
    window.visualViewport.addEventListener('resize', apply, { passive: true });
    window.visualViewport.addEventListener('scroll', apply, { passive: true });
  }
  
  window.addEventListener('orientationchange', () => {
    setTimeout(apply, 100);
  }, { passive: true });
})();

// ============================
// FIREBASE IMPORTS
// ============================
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
  connectFirestoreEmulator,
} from "https://www.gstatic.com/firebasejs/9.22.1/firebase-firestore.js";
import {
  getFunctions,
  httpsCallable,
  connectFunctionsEmulator,
} from "https://www.gstatic.com/firebasejs/9.22.1/firebase-functions.js";

// ============================
// CONFIGURATION
// ============================
const firebaseConfig = {
  apiKey: "AIzaSyDlijum_4JJ0V4eeE_AZS-T-ROGfby9o7Q",
  authDomain: "konvo-endgame.firebaseapp.com",
  projectId: "konvo-endgame",
  storageBucket: "konvo-endgame.firebasestorage.app",
  messagingSenderId: "297152484978",
  appId: "1:297152484978:web:d6a2907445c6c431cb14eb"
};

// reCAPTCHA Configuration (Issue #15)
const RECAPTCHA_SITE_KEY = ''; // Add your reCAPTCHA v3 site key here
const RECAPTCHA_ENABLED = RECAPTCHA_SITE_KEY.length > 0;

// Use emulators in development (set to false for production)
const USE_EMULATORS = false;

// ============================
// CONSTANTS
// ============================
const MESSAGE_MAX_LENGTH = 500;
const USERNAME_MAX_LENGTH = 30;
const TYPING_TIMEOUT = 3000;
const TYPING_STALE_THRESHOLD = 5000;

// Client-side rate limiting (backup - server is authoritative)
const CLIENT_RATE_LIMITS = Object.freeze({
  MESSAGE_COOLDOWN_MS: 1000,
  REACTION_COOLDOWN_MS: 500,
  TYPING_COOLDOWN_MS: 300,
});

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

// Generic error messages (Issue #20)
const ERROR_MESSAGES = Object.freeze({
  GENERIC: "Something went wrong. Please try again.",
  NETWORK: "Connection issue. Please check your network.",
  BANNED: "Access denied.",
  RATE_LIMIT: "Please slow down.",
  AUTH: "Please sign in again.",
  PROFILE_REQUIRED: "Please set up your profile first.",
  INVALID_INPUT: "Invalid input. Please try again.",
});

// ============================
// DOM ELEMENTS
// ============================
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

// ============================
// APPLICATION STATE
// ============================
const appStartTime = Date.now();

const state = {
  // Firebase instances
  app: null,
  db: null,
  auth: null,
  functions: null,
  
  // Cloud Functions references
  cloudFunctions: {
    sendMessage: null,
    registerDevice: null,
    updateReaction: null,
    updateTypingStatus: null,
    updateProfile: null,
    checkBanStatus: null,
  },
  
  // User state
  currentUserId: null,
  currentUsername: "Anonymous",
  currentProfilePhotoURL: null,
  isCurrentUserAdmin: false,
  
  // Device state
  deviceInfo: {
    fingerprint: null,
    isIdentified: false,
  },
  
  // Ban state
  isBanned: false,
  isDeviceBanned: false,
  
  // Cache
  userProfiles: {},
  lastConfessionDocs: [],
  lastChatDocs: [],
  pendingProfileLoads: new Set(),
  profileLoadTimeout: null,
  
  // Collections
  confessionsCollection: null,
  chatCollection: null,
  typingStatusCollection: null,
  
  // UI state
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
  
  // Rate limiting (client-side backup)
  lastMessageTime: 0,
  lastReactionTime: 0,
  lastTypingTime: 0,
};

// ============================
// LISTENER MANAGEMENT
// ============================
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

// ============================
// UTILITY FUNCTIONS
// ============================

/**
 * Sanitize text for display (XSS prevention)
 */
function sanitizeText(text) {
  if (typeof text !== 'string') return '';
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;')
    .replace(/`/g, '&#x60;');
}

/**
 * Sanitize text for notifications (Issue #22)
 */
function sanitizeNotificationText(text, maxLength = 100) {
  if (typeof text !== 'string') return '';
  
  // Remove control characters
  let sanitized = text.replace(/[\x00-\x1F\x7F]/g, '');
  
  // Remove potential script injection attempts
  sanitized = sanitized.replace(/<[^>]*>/g, '');
  
  // Truncate
  if (sanitized.length > maxLength) {
    sanitized = sanitized.substring(0, maxLength - 3) + '...';
  }
  
  return sanitized;
}

/**
 * Set text content safely
 */
function setTextSafely(element, text) {
  if (element && element instanceof HTMLElement) {
    element.textContent = text || '';
  }
}

/**
 * Get generic error message (Issue #20)
 */
function getGenericErrorMessage(error) {
  if (!error) return ERROR_MESSAGES.GENERIC;
  
  const code = error.code || '';
  
  // Map error codes to generic messages
  if (code.includes('unauthenticated') || code.includes('auth')) {
    return ERROR_MESSAGES.AUTH;
  }
  if (code.includes('permission-denied') || code.includes('banned')) {
    return ERROR_MESSAGES.BANNED;
  }
  if (code.includes('resource-exhausted') || code.includes('rate')) {
    return ERROR_MESSAGES.RATE_LIMIT;
  }
  if (code.includes('invalid-argument')) {
    return ERROR_MESSAGES.INVALID_INPUT;
  }
  if (code.includes('unavailable') || code.includes('network')) {
    return ERROR_MESSAGES.NETWORK;
  }
  if (code.includes('failed-precondition') && error.message?.includes('profile')) {
    return ERROR_MESSAGES.PROFILE_REQUIRED;
  }
  
  return ERROR_MESSAGES.GENERIC;
}

/**
 * Debounce function
 */
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

/**
 * Throttle function
 */
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

/**
 * Promise with timeout
 */
function withTimeout(promise, ms, fallbackValue = null) {
  return Promise.race([
    promise,
    new Promise((resolve) => setTimeout(() => resolve(fallbackValue), ms))
  ]);
}

/**
 * Escape CSS selector
 */
function escapeSelector(selector) {
  if (typeof selector !== 'string') return '';
  return CSS.escape(selector);
}

/**
 * Get user color from user ID
 */
function getUserColor(userId) {
  if (!userId || typeof userId !== 'string') return USER_COLORS[0];
  let hash = 0;
  for (let i = 0; i < userId.length; i++) {
    hash = userId.charCodeAt(i) + ((hash << 5) - hash);
  }
  const index = Math.abs(hash % USER_COLORS.length);
  return USER_COLORS[index];
}

/**
 * Format message time
 */
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

/**
 * Get date header
 */
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

// ============================
// VALIDATION FUNCTIONS
// ============================

/**
 * Validate username
 */
function isValidUsername(username) {
  if (typeof username !== 'string') return false;
  const trimmed = username.trim();
  if (trimmed.length === 0 || trimmed.length > USERNAME_MAX_LENGTH) return false;
  
  const reserved = ['anonymous', 'admin', 'moderator', 'system', 'konvo', 'mod', 'support', 'staff', 'official', 'root', 'owner', 'bot', 'help'];
  const lowerUsername = trimmed.toLowerCase();
  
  for (const word of reserved) {
    if (lowerUsername === word || lowerUsername.includes(word)) {
      return false;
    }
  }
  
  const usernameRegex = /^[A-Za-z0-9_\- ]+$/;
  return usernameRegex.test(trimmed);
}

/**
 * Validate message text
 */
function isValidMessageText(text) {
  if (typeof text !== 'string') return false;
  const trimmed = text.trim();
  if (trimmed.length === 0 || trimmed.length > MESSAGE_MAX_LENGTH) return false;
  const controlCharRegex = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/;
  return !controlCharRegex.test(trimmed);
}

/**
 * Validate message before posting
 */
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
  const controlCharRegex = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/;
  if (controlCharRegex.test(trimmed)) {
    return { valid: false, error: "Message contains invalid characters" };
  }
  return { valid: true, text: trimmed };
}

/**
 * Validate profile photo URL
 */
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

// ============================
// DEVICE FINGERPRINTING (Issue #6 - Improved)
// ============================
const FINGERPRINT_STORAGE_KEY = 'konvo_device_fp';

/**
 * Generate cryptographically secure random string
 */
function generateSecureRandomString(length) {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let result = '';
  
  try {
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    for (let i = 0; i < length; i++) {
      result += chars[array[i] % chars.length];
    }
    return result;
  } catch (e) {
    // Fallback with multiple entropy sources (Issue #6)
    const entropy = [
      Date.now().toString(36),
      Math.random().toString(36).substring(2),
      performance.now().toString(36),
      (typeof screen !== 'undefined' ? screen.width * screen.height : 0).toString(36),
    ].join('');
    
    for (let i = 0; i < length; i++) {
      const index = (entropy.charCodeAt(i % entropy.length) + Math.random() * 256) % chars.length;
      result += chars[Math.floor(index)];
    }
    return result;
  }
}

/**
 * Generate device fingerprint (Issue #6 - Enhanced entropy)
 */
async function generateDeviceFingerprint() {
  // Try to load saved fingerprint first
  try {
    const savedFingerprint = localStorage.getItem(FINGERPRINT_STORAGE_KEY);
    if (savedFingerprint && savedFingerprint.length >= 16) {
      state.deviceInfo.fingerprint = savedFingerprint;
      return savedFingerprint;
    }
  } catch (e) {}
  
  // Try FingerprintJS
  try {
    if (typeof FingerprintJS !== 'undefined') {
      const fp = await withTimeout(FingerprintJS.load(), 5000, null);
      if (fp) {
        const result = await withTimeout(fp.get(), 5000, null);
        if (result?.visitorId) {
          saveFingerprint(result.visitorId);
          state.deviceInfo.fingerprint = result.visitorId;
          return result.visitorId;
        }
      }
    }
  } catch (error) {
    console.warn('FingerprintJS failed, using fallback');
  }
  
  // Enhanced fallback (Issue #6)
  return createEnhancedFallbackFingerprint();
}

/**
 * Create enhanced fallback fingerprint with more entropy (Issue #6)
 */
function createEnhancedFallbackFingerprint() {
  // Check for saved fingerprint
  try {
    const savedFingerprint = localStorage.getItem(FINGERPRINT_STORAGE_KEY);
    if (savedFingerprint && savedFingerprint.length >= 16) {
      state.deviceInfo.fingerprint = savedFingerprint;
      return savedFingerprint;
    }
  } catch (e) {}
  
  // Collect device characteristics
  const components = [
    navigator.userAgent,
    navigator.language,
    navigator.languages?.join(',') || '',
    screen.width + 'x' + screen.height,
    screen.colorDepth,
    screen.pixelDepth,
    new Date().getTimezoneOffset(),
    navigator.hardwareConcurrency || 'unknown',
    navigator.deviceMemory || 'unknown',
    navigator.platform,
    navigator.maxTouchPoints || 0,
    navigator.cookieEnabled,
    typeof window.indexedDB !== 'undefined',
    typeof window.localStorage !== 'undefined',
    typeof window.sessionStorage !== 'undefined',
    typeof window.WebSocket !== 'undefined',
    typeof window.Worker !== 'undefined',
    Intl.DateTimeFormat().resolvedOptions().timeZone,
  ];
  
  // Create hash from components
  let hash = 0;
  const str = components.join('|||');
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  
  // Add cryptographically secure random component (Issue #6)
  const randomPart = generateSecureRandomString(16);
  
  // Add timestamp component for uniqueness
  const timePart = Date.now().toString(36);
  
  const fallbackId = 'fp_' + Math.abs(hash).toString(36) + '_' + randomPart + '_' + timePart;
  
  saveFingerprint(fallbackId);
  state.deviceInfo.fingerprint = fallbackId;
  
  return fallbackId;
}

/**
 * Save fingerprint to storage
 */
function saveFingerprint(fingerprint) {
  try {
    localStorage.setItem(FINGERPRINT_STORAGE_KEY, fingerprint);
  } catch (e) {}
}

// ============================
// RECAPTCHA INTEGRATION (Issue #15)
// ============================

let recaptchaReady = false;
let recaptchaLoadPromise = null;

/**
 * Load reCAPTCHA script
 */
function loadRecaptchaScript() {
  if (!RECAPTCHA_ENABLED) {
    return Promise.resolve(false);
  }
  
  if (recaptchaLoadPromise) {
    return recaptchaLoadPromise;
  }
  
  recaptchaLoadPromise = new Promise((resolve) => {
    // Check if already loaded
    if (typeof grecaptcha !== 'undefined' && grecaptcha.ready) {
      recaptchaReady = true;
      resolve(true);
      return;
    }
    
    const script = document.createElement('script');
    script.src = `https://www.google.com/recaptcha/api.js?render=${RECAPTCHA_SITE_KEY}`;
    script.async = true;
    script.defer = true;
    
    script.onload = () => {
      if (typeof grecaptcha !== 'undefined') {
        grecaptcha.ready(() => {
          recaptchaReady = true;
          resolve(true);
        });
      } else {
        resolve(false);
      }
    };
    
    script.onerror = () => {
      console.warn('Failed to load reCAPTCHA');
      resolve(false);
    };
    
    document.head.appendChild(script);
  });
  
  return recaptchaLoadPromise;
}

/**
 * Get reCAPTCHA token for an action
 */
async function getRecaptchaToken(action) {
  if (!RECAPTCHA_ENABLED || !recaptchaReady) {
    return null;
  }
  
  try {
    const token = await grecaptcha.execute(RECAPTCHA_SITE_KEY, { action });
    return token;
  } catch (error) {
    console.warn('Failed to get reCAPTCHA token');
    return null;
  }
}

// ============================
// TOAST NOTIFICATIONS
// ============================

/**
 * Show toast message
 */
function showToast(message, type = 'info') {
  // Sanitize message
  const safeMessage = sanitizeText(message);
  
  if (type === 'error') {
    // Use alert for errors (more visible)
    alert(safeMessage);
  } else if (type === 'info') {
    const existingToast = document.getElementById('info-toast');
    if (existingToast) existingToast.remove();
    
    const toast = document.createElement('div');
    toast.id = 'info-toast';
    toast.style.cssText = `
      position: fixed;
      bottom: 100px;
      left: 50%;
      transform: translateX(-50%);
      background: #22c55e;
      color: white;
      padding: 12px 24px;
      border-radius: 8px;
      font-size: 14px;
      font-weight: 500;
      z-index: 10000;
      box-shadow: 0 4px 15px rgba(34, 197, 94, 0.4);
      max-width: 90%;
      text-align: center;
    `;
    toast.textContent = safeMessage;
    document.body.appendChild(toast);
    
    setTimeout(() => {
      if (toast.parentNode) {
        toast.style.opacity = '0';
        toast.style.transition = 'opacity 0.3s';
        setTimeout(() => toast.remove(), 300);
      }
    }, 3000);
  }
}

// ============================
// SVG ICON CREATORS
// ============================

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

// ============================
// BAN SCREENS
// ============================

function hideBanCheckOverlay() {
  const overlay = document.getElementById('banCheckOverlay');
  if (overlay) {
    overlay.classList.add('hidden');
    setTimeout(() => {
      overlay.style.display = 'none';
    }, 300);
  }
}

function showBannedScreen(reason = 'Access denied') {
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
    gap: 0.75rem;
    padding: 1.5rem;
    text-align: center;
  `;
  
  const emoji = document.createElement('div');
  emoji.style.cssText = 'font-size: 4rem; margin-bottom: 0.5rem;';
  emoji.textContent = '🚫';
  
  const h1 = document.createElement('h1');
  h1.style.cssText = 'font-size: 1.875rem; color: #ef4444; font-weight: bold; margin: 0;';
  h1.textContent = 'ACCESS DENIED';
  
  const p1 = document.createElement('p');
  p1.style.cssText = 'color: #888; font-size: 0.9rem; margin: 0;';
  p1.textContent = 'You have been banned from Konvo.';
  
  const p2 = document.createElement('p');
  p2.style.cssText = 'color: #555; font-size: 0.75rem; margin-top: 1rem;';
  p2.textContent = 'If you believe this is a mistake, please wait for admin review.';
  
  overlay.appendChild(emoji);
  overlay.appendChild(h1);
  overlay.appendChild(p1);
  overlay.appendChild(p2);
  
  document.body.appendChild(overlay);
  document.body.classList.add('device-banned');
}

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

// ============================
// CHARACTER COUNTER
// ============================

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

// ============================
// FIREBASE INITIALIZATION
// ============================

async function initFirebase() {
  const globalTimeout = setTimeout(() => {
    hideBanCheckOverlay();
  }, 15000);
  
  try {
    // Generate fingerprint first
    state.deviceInfo.fingerprint = await generateDeviceFingerprint();
    state.deviceInfo.isIdentified = !!state.deviceInfo.fingerprint;
    
    // Load reCAPTCHA (Issue #15)
    if (RECAPTCHA_ENABLED) {
      loadRecaptchaScript().catch(() => {});
    }
    
    // Initialize Firebase
    state.app = initializeApp(firebaseConfig);
    
    // Initialize Firestore with persistence
    try {
      state.db = initializeFirestore(state.app, {
        localCache: persistentLocalCache({
          tabManager: persistentMultipleTabManager()
        })
      });
    } catch (persistenceError) {
      state.db = initializeFirestore(state.app, {});
    }
    
    state.auth = getAuth(state.app);
    state.functions = getFunctions(state.app, 'asia-south1');
    
    // Connect to emulators in development
    if (USE_EMULATORS) {
      connectFirestoreEmulator(state.db, 'localhost', 8080);
      connectFunctionsEmulator(state.functions, 'localhost', 5001);
    }
    
    // Initialize Cloud Function references
    state.cloudFunctions = {
      sendMessage: httpsCallable(state.functions, 'sendMessage'),
      registerDevice: httpsCallable(state.functions, 'registerDevice'),
      updateReaction: httpsCallable(state.functions, 'updateReaction'),
      updateTypingStatus: httpsCallable(state.functions, 'updateTypingStatus'),
      updateProfile: httpsCallable(state.functions, 'updateProfile'),
      checkBanStatus: httpsCallable(state.functions, 'checkBanStatus'),
    };
    
    // Set up auth state listener
    onAuthStateChanged(state.auth, async (user) => {
      try {
        await handleAuthStateChange(user);
      } catch (error) {
        console.error('Auth state change error');
        hideBanCheckOverlay();
      } finally {
        clearTimeout(globalTimeout);
      }
    });
    
  } catch (error) {
    console.error('Firebase initialization failed');
    setTextSafely(loading, "Error: Could not initialize. Please refresh.");
    hideBanCheckOverlay();
    clearTimeout(globalTimeout);
    throw error;
  }
}

async function handleAuthStateChange(user) {
  if (user) {
    state.currentUserId = user.uid;
    
    // Check ban status via Cloud Function (Issue #4 - server-side IP check)
    try {
      const banResult = await withTimeout(
        state.cloudFunctions.checkBanStatus({
          fingerprint: state.deviceInfo.fingerprint
        }),
        10000,
        null
      );
      
      if (banResult?.data?.banned) {
        state.isBanned = true;
        state.isDeviceBanned = banResult.data.type === 'device' || banResult.data.type === 'ip';
        showBannedScreen();
        return;
      }
    } catch (error) {
      console.warn('Ban check failed, continuing');
    }
    
    // Register device via Cloud Function (Issue #4, #11)
    try {
      await withTimeout(
        state.cloudFunctions.registerDevice({
          fingerprint: state.deviceInfo.fingerprint,
          userAgent: navigator.userAgent,
          language: navigator.language,
          timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
          screenResolution: `${screen.width}x${screen.height}`,
          platform: navigator.platform,
        }),
        10000,
        null
      );
    } catch (error) {
      // Non-critical, continue
      console.warn('Device registration failed');
    }
    
    // Initialize collections
    state.confessionsCollection = collection(state.db, "confessions");
    state.chatCollection = collection(state.db, "chat");
    state.typingStatusCollection = collection(state.db, "typingStatus");
    
    // Set up app
    registerServiceWorker();
    setupNotificationButton();
    setupAdminMenu();
    setupConnectionMonitor();
    listenForUserProfiles();
    listenForBanStatus();
    
    try {
      await checkAdminStatus();
    } catch (e) {}
    
    try {
      await loadUserProfile();
    } catch (e) {}
    
    hideBanCheckOverlay();
    initScrollObserver();
    showPage(state.currentPage);
    state.isInitialized = true;
    
  } else {
    try {
      await signInAnonymously(state.auth);
    } catch (e) {
      setTextSafely(loading, "Error: Could not sign in. Please refresh.");
      hideBanCheckOverlay();
    }
  }
}

// ============================
// SERVICE WORKER
// ============================

function registerServiceWorker() {
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('sw.js', { scope: '/' })
      .then(reg => {
        reg.addEventListener('updatefound', () => {
          const newWorker = reg.installing;
          if (newWorker) {
            newWorker.addEventListener('statechange', () => {});
          }
        });
      })
      .catch(err => {});
  }
}

// ============================
// CONNECTION MONITOR
// ============================

function setupConnectionMonitor() {
  window.addEventListener('online', () => {
    if (state.isInitialized) {
      showPage(state.currentPage);
    }
  });
  
  window.addEventListener('offline', () => {
    showToast("You're offline. Messages will sync when connected.", "info");
  });
}

// ============================
// NOTIFICATIONS (Issue #22 - Sanitized)
// ============================

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
    } catch (err) {}
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

/**
 * Show notification with sanitized content (Issue #22)
 */
async function showNotification(title, body) {
  if (!("Notification" in window) || !state.notificationsEnabled) return;
  if (document.visibilityState === 'visible') return;
  
  // Sanitize notification content (Issue #22)
  const safeTitle = sanitizeNotificationText(title, 50);
  const safeBody = sanitizeNotificationText(body, 100);
  
  try {
    if ('serviceWorker' in navigator) {
      const reg = await navigator.serviceWorker.ready;
      if (reg) {
        await reg.showNotification(safeTitle || 'New Message', {
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
    new Notification(safeTitle || 'New Message', { body: safeBody, icon: "icon.jpg" });
  } catch (e) {}
}

// ============================
// ADMIN FEATURES
// ============================

async function checkAdminStatus() {
  if (!state.currentUserId || !state.db) return;
  
  try {
    const adminDocRef = doc(state.db, "admins", state.currentUserId);
    const adminDocSnap = await getDoc(adminDocRef);
    state.isCurrentUserAdmin = adminDocSnap.exists();
  } catch (e) {
    state.isCurrentUserAdmin = false;
  }
}

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
    showToast(ERROR_MESSAGES.GENERIC, "error");
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
    showToast(ERROR_MESSAGES.GENERIC, "error");
    return;
  }
  
  const action = isBanned ? "UNBAN" : "BAN";
  const safeUsername = sanitizeText(username || 'this user');
  const confirmMessage = isBanned
    ? `Unban ${safeUsername}?`
    : `Ban ${safeUsername}? This will also ban their device and IP.`;
  
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
    
    // Get user's devices and ban them too
    if (!isBanned) {
      const devicesQuery = query(
        collection(state.db, "user_devices"),
        where("userId", "==", userId)
      );
      
      const devicesSnapshot = await getDocs(devicesQuery);
      
      const processedFingerprints = new Set();
      const processedIPs = new Set();
      
      for (const deviceDoc of devicesSnapshot.docs) {
        const deviceData = deviceDoc.data();
        
        if (deviceData.fingerprint && !processedFingerprints.has(deviceData.fingerprint)) {
          processedFingerprints.add(deviceData.fingerprint);
          const fingerprintBanRef = doc(state.db, "banned_devices", deviceData.fingerprint);
          batch.set(fingerprintBanRef, {
            fingerprint: deviceData.fingerprint,
            userId: userId,
            username: username?.substring(0, 30) || 'Unknown',
            bannedBy: state.currentUserId,
            timestamp: serverTimestamp(),
            reason: "Admin Action",
          });
        }
        
        if (deviceData.ipHash && !processedIPs.has(deviceData.ipHash)) {
          processedIPs.add(deviceData.ipHash);
          const ipBanRef = doc(state.db, "banned_ips", deviceData.ipHash);
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
    } else {
      // Unban - remove device and IP bans
      const devicesQuery = query(
        collection(state.db, "user_devices"),
        where("userId", "==", userId)
      );
      
      const devicesSnapshot = await getDocs(devicesQuery);
      
      for (const deviceDoc of devicesSnapshot.docs) {
        const deviceData = deviceDoc.data();
        
        if (deviceData.fingerprint) {
          const fingerprintBanRef = doc(state.db, "banned_devices", deviceData.fingerprint);
          batch.delete(fingerprintBanRef);
        }
        
        if (deviceData.ipHash) {
          const ipBanRef = doc(state.db, "banned_ips", deviceData.ipHash);
          batch.delete(ipBanRef);
        }
      }
    }
    
    await batch.commit();
    
    if (state.userProfiles[userId]) {
      state.userProfiles[userId].banned = !isBanned;
    }
    
    showToast(isBanned ? 'User unbanned.' : 'User banned.', "info");
  } catch (e) {
    showToast(ERROR_MESSAGES.GENERIC, "error");
  }
}

// ============================
// USER PROFILE
// ============================

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
    throw error;
  }
}

/**
 * Handle profile save via Cloud Function (Issue #15, #23)
 */
async function handleProfileSave() {
  if (!state.currentUserId) {
    showToast(ERROR_MESSAGES.AUTH, "error");
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
    modalSaveButton.textContent = "SAVING...";
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
    // Get reCAPTCHA token (Issue #15)
    const recaptchaToken = await getRecaptchaToken('update_profile');
    
    // Use Cloud Function for profile update (Issue #23)
    const result = await state.cloudFunctions.updateProfile({
      username: inputVal,
      recaptchaToken: recaptchaToken,
    });
    
    if (result.data?.success) {
      state.currentUsername = result.data.username;
      state.currentProfilePhotoURL = result.data.profilePhotoURL;
      
      state.userProfiles[state.currentUserId] = {
        ...state.userProfiles[state.currentUserId],
        username: result.data.username,
        profilePhotoURL: result.data.profilePhotoURL
      };
      
      showToast("Profile saved successfully!", "info");
      closeProfileModal();
    } else {
      throw new Error('Profile update failed');
    }
    
    resetButtonState();
  } catch (error) {
    // Generic error message (Issue #20)
    const message = getGenericErrorMessage(error);
    
    // Special case for username taken
    if (error.code === 'already-exists') {
      showToast("Username is already taken!", "error");
    } else {
      showToast(message, "error");
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

// ============================
// MESSAGE EDITING
// ============================

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
  const newText = modalEditTextArea?.value?.trim();
  
  if (!isValidMessageText(newText)) {
    showToast(`Message must be 1-${MESSAGE_MAX_LENGTH} characters.`, "error");
    return;
  }
  
  if (!state.docToEditId || !state.db) return;
  
  if (editModalSaveButton) {
    editModalSaveButton.textContent = "SAVING...";
    editModalSaveButton.disabled = true;
    editModalSaveButton.classList.add("loading");
  }
  if (editModalCancelButton) {
    editModalCancelButton.disabled = true;
  }
  
  try {
    await updateDoc(doc(state.db, state.collectionToEdit, state.docToEditId), {
      text: newText,
      edited: true
    });
    closeEditModal();
  } catch (e) {
    showToast(ERROR_MESSAGES.GENERIC, "error");
  } finally {
    if (editModalSaveButton) {
      editModalSaveButton.textContent = "SAVE";
      editModalSaveButton.disabled = false;
      editModalSaveButton.classList.remove("loading");
    }
    if (editModalCancelButton) {
      editModalCancelButton.disabled = false;
    }
  }
}

// ============================
// CONFIRM MODAL
// ============================

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
      } catch (e) {}
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
        showToast(ERROR_MESSAGES.GENERIC, "error");
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
      } catch (e) {}
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

// ============================
// REACTIONS (Via Cloud Function - Issue #8)
// ============================

/**
 * Toggle reaction via Cloud Function (Issue #8)
 */
async function toggleReaction(docId, collectionName, reactionType, hasReacted) {
  if (!state.currentUserId) return;
  
  if (!Object.prototype.hasOwnProperty.call(REACTION_TYPES, reactionType)) {
    return;
  }
  
  // Client-side rate limit check (backup)
  const now = Date.now();
  if (now - state.lastReactionTime < CLIENT_RATE_LIMITS.REACTION_COOLDOWN_MS) {
    return; // Silently ignore
  }
  
  // Optimistic UI update
  const escapedId = escapeSelector(docId);
  const bubble = document.querySelector(`.message-bubble[data-id="${escapedId}"]`);
  if (bubble) {
    updateReactionUI(bubble, reactionType, !hasReacted, collectionName);
  }
  
  state.lastReactionTime = now;
  
  try {
    // Use Cloud Function for reaction (Issue #8)
    await state.cloudFunctions.updateReaction({
      messageId: docId,
      collection: collectionName,
      reactionType: reactionType,
      action: hasReacted ? 'remove' : 'add'
    });
  } catch (error) {
    // Revert optimistic update on failure
    if (bubble) {
      updateReactionUI(bubble, reactionType, hasReacted, collectionName);
    }
    
    if (error.code === 'resource-exhausted') {
      // Don't show error for rate limit
    } else {
      console.warn('Reaction update failed');
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

// ============================
// CONTEXT MENU
// ============================

function showDropdownMenu(event, data) {
  event.stopPropagation();
  
  if (!contextMenu) return;
  
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

// ============================
// SELECTION MODE
// ============================

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
        showToast(ERROR_MESSAGES.GENERIC, "error");
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
          showToast(ERROR_MESSAGES.GENERIC, "error");
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

// ============================
// PAGE NAVIGATION
// ============================

function showPage(page) {
  if (page !== 'chat' && page !== 'confessions') {
    page = 'chat';
  }
  
  state.currentPage = page;
  
  if (state.isSelectionMode) exitSelectionMode();
  cancelReplyMode();
  
  document.querySelectorAll(".reaction-picker").forEach(p => p.remove());
  
  // Cleanup existing listeners
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

// ============================
// BAN STATUS LISTENERS
// ============================

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
      console.warn('Ban check listener error');
    }
  );
  
  // Listen for device ban
  if (state.deviceInfo.fingerprint) {
    unsubscribers.deviceBanCheck = onSnapshot(
      doc(state.db, "banned_devices", state.deviceInfo.fingerprint),
      (docSnap) => {
        if (docSnap.exists()) {
          if (!state.isDeviceBanned) {
            state.isDeviceBanned = true;
            cleanupNonBanListeners();
            showBannedScreen();
          }
        }
      },
      (error) => {}
    );
  }
}

function cleanupNonBanListeners() {
  const banListenerKeys = ['banCheck', 'deviceBanCheck', 'ipBanCheck'];
  
  Object.entries(unsubscribers).forEach(([key, unsub]) => {
    if (banListenerKeys.includes(key)) return;
    if (typeof unsub === 'function') {
      try {
        unsub();
        unsubscribers[key] = () => {};
      } catch (e) {}
    }
  });
}

function cleanupAllListeners() {
  Object.entries(unsubscribers).forEach(([key, unsub]) => {
    if (typeof unsub === 'function') {
      try {
        unsub();
        unsubscribers[key] = () => {};
      } catch (e) {}
    }
  });
}

// ============================
// PINNED MESSAGES
// ============================

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
    if (pinnedMessageBar) {
      pinnedMessageBar.classList.add("hidden");
    }
  });
}

// ============================
// USER PROFILES
// ============================

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
      // Fallback to individual fetches
      for (const userId of batch) {
        try {
          const docRef = doc(state.db, "users", userId);
          const docSnap = await getDoc(docRef);
          if (docSnap.exists()) {
            state.userProfiles[docSnap.id] = docSnap.data();
          }
        } catch (e) {}
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
        (error) => {}
      );
    } catch (e) {}
  };
  
  setTimeout(checkAndSetupListener, 1000);
}

// ============================
// SCROLL OBSERVER
// ============================

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

// ============================
// TYPING STATUS (Via Cloud Function - Issue #12)
// ============================

const updateTypingStatus = debounce(async (isTyping) => {
  if (!state.currentUserId) return;
  
  // Client-side rate limit
  const now = Date.now();
  if (now - state.lastTypingTime < CLIENT_RATE_LIMITS.TYPING_COOLDOWN_MS) {
    return;
  }
  state.lastTypingTime = now;
  
  if (state.typingTimeout) {
    clearTimeout(state.typingTimeout);
    state.typingTimeout = null;
  }
  
  try {
    // Use Cloud Function for typing status (Issue #12)
    await state.cloudFunctions.updateTypingStatus({
      isTyping: isTyping
    });
    
    if (isTyping) {
      state.typingTimeout = setTimeout(() => {
        updateTypingStatus(false);
      }, TYPING_TIMEOUT);
    }
  } catch (e) {
    // Silently fail for typing updates
  }
}, 300);

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
      if (typingIndicator) {
        typingIndicator.innerHTML = "&nbsp;";
      }
    }
  );
}

// ============================
// MESSAGE LISTENERS
// ============================

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
      if (feedContainer) {
        feedContainer.innerHTML = '';
        const errorDiv = document.createElement("div");
        errorDiv.className = "text-center p-4 text-red-500";
        errorDiv.textContent = "Error loading confessions. Please refresh.";
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
      if (feedContainer) {
        feedContainer.innerHTML = '';
        const errorDiv = document.createElement("div");
        errorDiv.className = "text-center p-4 text-red-500";
        errorDiv.textContent = "Error loading chat. Please refresh.";
        feedContainer.appendChild(errorDiv);
      }
    }
  );
}

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

// ============================
// FEED RENDERER
// ============================

function renderFeed(docs, type, snapshot, isRerender, isFirstSnapshot = false) {
  if (!feedContainer) return;
  
  document.querySelectorAll(".reaction-picker").forEach(p => p.remove());
  
  // Handle notifications for new messages
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
          // Sanitized notification (Issue #22)
          showNotification(
            type === "chat" ? "New Chat" : "New Confession",
            sanitizeNotificationText(data.text, 100)
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
    
    // Date separator
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
    
    // Create message structure
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
    
    // Apply user color
    if (!isMine) {
      bubble.style.borderLeft = `3px solid ${userColor}`;
      bubble.style.background = `linear-gradient(90deg, ${userColor}10, transparent)`;
    } else {
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
    
    // Kebab menu button
    const kebabBtn = document.createElement("button");
    kebabBtn.type = "button";
    kebabBtn.className = "kebab-btn";
    kebabBtn.setAttribute("aria-label", "Message options");
    kebabBtn.appendChild(createKebabIcon());
    kebabBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      showDropdownMenu(e, bubble.dataset);
    });
    
    // Message header (avatar + username)
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
    
    // Reply preview
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
    
    // Message text
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
    
    // Message footer (timestamp)
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
    
    // Reactions
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
    
    // Reply button
    const replyBtn = document.createElement("button");
    replyBtn.type = "button";
    replyBtn.className = "side-action-btn";
    replyBtn.setAttribute("aria-label", "Reply to message");
    replyBtn.textContent = "↩";
    replyBtn.onclick = (e) => {
      e.stopPropagation();
      startReplyMode(bubble.dataset);
    };
    
    // React button
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
    
    // Assemble message row
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
  
  // Scroll anchor
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
  
  // Handle scrolling
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

// ============================
// REPLY MODE
// ============================

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

// ============================
// MESSAGE POSTING (Via Cloud Function - Issue #23)
// ============================

/**
 * Post message via Cloud Function (Issue #23)
 */
async function postMessage(collectionName, input) {
  if (!state.currentUserId) {
    showToast(ERROR_MESSAGES.AUTH, "error");
    return;
  }
  
  if (state.currentUsername === "Anonymous") {
    showToast("Please set a username first!", "error");
    openProfileModal();
    return;
  }
  
  if (state.isBanned || state.isDeviceBanned) {
    showToast(ERROR_MESSAGES.BANNED, "error");
    return;
  }
  
  // Client-side rate limit check (backup)
  const now = Date.now();
  if (now - state.lastMessageTime < CLIENT_RATE_LIMITS.MESSAGE_COOLDOWN_MS) {
    const waitTime = Math.ceil((CLIENT_RATE_LIMITS.MESSAGE_COOLDOWN_MS - (now - state.lastMessageTime)) / 1000);
    showToast(`Please wait ${waitTime} second${waitTime > 1 ? 's' : ''}...`, "error");
    return;
  }
  
  const validation = validateMessageBeforePost(input.value);
  if (!validation.valid) {
    showToast(validation.error, "error");
    input.focus({ preventScroll: true });
    return;
  }
  
  const text = validation.text;
  const isChat = collectionName === 'chat';
  
  const submitBtn = isChat ?
    document.getElementById('chatButton') :
    document.getElementById('confessionButton');
  
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
  
  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.classList.add('loading');
    submitBtn.textContent = 'SENDING...';
  }
  
  try {
    // Get reCAPTCHA token (Issue #15)
    const recaptchaToken = await getRecaptchaToken('send_message');
    
    // Prepare message data
    const messageData = {
      text: text,
      collection: collectionName,
      recaptchaToken: recaptchaToken,
      fingerprint: state.deviceInfo.fingerprint,
    };
    
    // Add reply data if present
    if (state.replyToMessage) {
      messageData.replyTo = {
        messageId: state.replyToMessage.id,
        userId: state.replyToMessage.userId,
        text: (state.replyToMessage.text || '').substring(0, 200)
      };
    }
    
    // Send via Cloud Function (Issue #23)
    const result = await state.cloudFunctions.sendMessage(messageData);
    
    if (result.data?.success) {
      state.lastMessageTime = Date.now();
      
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
      
      resetUI();
      
      requestAnimationFrame(() => {
        if (inputToRefocus) {
          inputToRefocus.focus({ preventScroll: true });
        }
      });
    } else {
      throw new Error('Message send failed');
    }
    
  } catch (error) {
    // Generic error message (Issue #20)
    const message = getGenericErrorMessage(error);
    showToast(message, "error");
    
    resetUI();
    
    requestAnimationFrame(() => {
      if (inputToRefocus) {
        inputToRefocus.focus({ preventScroll: true });
      }
    });
  }
}

// ============================
// EVENT LISTENERS
// ============================

// Prevent button mousedown from stealing focus
if (window.matchMedia('(hover: hover)').matches) {
  document.getElementById('chatButton')?.addEventListener('mousedown', (e) => {
    e.preventDefault();
  }, { passive: false });
  
  document.getElementById('confessionButton')?.addEventListener('mousedown', (e) => {
    e.preventDefault();
  }, { passive: false });
}

// Click outside handlers
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

// Update timestamps periodically
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
  postMessage("confessions", confessionInput);
});

chatForm?.addEventListener("submit", (e) => {
  e.preventDefault();
  e.stopPropagation();
  postMessage("chat", chatInput);
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

// Reply
cancelReply?.addEventListener("click", cancelReplyMode);

// Input handlers
confessionInput?.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    postMessage("confessions", confessionInput);
  } else {
    updateTypingStatus(true);
  }
});

chatInput?.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    postMessage("chat", chatInput);
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

// Visibility change
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") {
    if (state.userIsAtBottom) {
      state.unreadMessages = 0;
      updateScrollButton();
    }
  }
});

// Page unload
window.addEventListener("beforeunload", () => {
  if (state.currentUserId) {
    updateTypingStatus(false);
  }
});

window.addEventListener('unload', () => {
  cleanupAllListeners();
});

// ============================
// INITIALIZE APPLICATION
// ============================

initFirebase().catch(err => {
  console.error('Initialization failed');
  setTextSafely(loading, "Error: Failed to initialize. Please refresh the page.");
  hideBanCheckOverlay();
});