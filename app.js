// ============================================================
// KONVO - ANONYMOUS CHAT APPLICATION
// Version: 2.3 (Character Counter + On-Demand Profile Loading)
// ============================================================
'use strict';

// ============================================================
// VIEWPORT HEIGHT FIX (MOBILE + INSTALLED PWA)
// ============================================================
// On iOS/Android (especially in standalone/PWA mode), the on-screen keyboard can shrink the
// *visual* viewport without reliable support for CSS viewport units. This keeps the chat input
// from being pushed below the visible area (requiring scroll to type).
(function setupAppHeight() {
  const apply = () => {
    const h = window.visualViewport?.height || window.innerHeight;
    document.documentElement.style.setProperty('--app-height', `${h}px`);
    // Inline style beats Tailwind height utilities on <body>
    if (document.body) document.body.style.height = `${h}px`;
  };

  apply();

  // Update on rotation/resize and keyboard open/close
  window.addEventListener('resize', apply);
  window.visualViewport?.addEventListener('resize', apply);
  window.visualViewport?.addEventListener('scroll', apply);
})();

import { initializeApp } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-app.js";
import { initializeAppCheck, ReCaptchaEnterpriseProvider } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-app-check.js";
import {
  getAuth,
  signInAnonymously,
  onAuthStateChanged,
} from "https://www.gstatic.com/firebasejs/11.6.1/firebase-auth.js";
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
  limit,
  updateDoc,
  deleteDoc,
  writeBatch,
  arrayUnion,
  arrayRemove,
} from "https://www.gstatic.com/firebasejs/11.6.1/firebase-firestore.js";

// ============================================================
// SECURITY UTILITIES
// ============================================================

/**
 * Sanitize text to prevent XSS attacks
 * @param {string} text - Raw text input
 * @returns {string} - Sanitized text
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
 * Validate username format
 * @param {string} username - Username to validate
 * @returns {boolean} - Whether username is valid
 */
function isValidUsername(username) {
  if (typeof username !== 'string') return false;
  const trimmed = username.trim();
  if (trimmed.length === 0 || trimmed.length > 30) return false;
  
  // Reserved usernames check
  const reserved = ['anonymous', 'admin', 'moderator', 'system', 'konvo', 'mod'];
  const lowerUsername = trimmed.toLowerCase();
  if (reserved.some(r => lowerUsername === r || lowerUsername.includes(r))) {
    return false;
  }
  
  // Only allow alphanumeric, spaces, underscores, hyphens
  const usernameRegex = /^[A-Za-z0-9_\- ]+$/;
  return usernameRegex.test(trimmed);
}

/**
 * Validate message text
 * @param {string} text - Message text to validate
 * @returns {boolean} - Whether text is valid
 */
function isValidMessageText(text) {
  if (typeof text !== 'string') return false;
  const trimmed = text.trim();
  if (trimmed.length === 0 || trimmed.length > MESSAGE_MAX_LENGTH) return false;
  
  // Check for null bytes and control characters
  const controlCharRegex = /[\x00-\x08\x0B\x0C\x0E-\x1F]/;
  return !controlCharRegex.test(trimmed);
}

/**
 * Validate URL for profile photos
 * @param {string} url - URL to validate
 * @returns {boolean} - Whether URL is valid
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

/**
 * Enhanced message validation before posting
 * @param {string} text - Message text to validate
 * @returns {Object} - Validation result with valid flag and error/text
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
  
  // Check for control characters
  const controlCharRegex = /[\x00-\x08\x0B\x0C\x0E-\x1F]/;
  if (controlCharRegex.test(trimmed)) {
    return { valid: false, error: "Message contains invalid characters" };
  }
  
  return { valid: true, text: trimmed };
}

/**
 * Safely set element text content (prevents XSS)
 * @param {HTMLElement|null} element - Target element
 * @param {string} text - Text content
 */
function setTextSafely(element, text) {
  if (element && element instanceof HTMLElement) {
    element.textContent = text || '';
  }
}

/**
 * Safely create text node (prevents XSS)
 * @param {string} text - Text content
 * @returns {Text} - Text node
 */
function createSafeTextNode(text) {
  return document.createTextNode(text || '');
}

/**
 * Debounce function for performance
 * @param {Function} func - Function to debounce
 * @param {number} wait - Wait time in ms
 * @returns {Function} - Debounced function
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
 * Throttle function for performance
 * @param {Function} func - Function to throttle
 * @param {number} limit - Limit time in ms
 * @returns {Function} - Throttled function
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
 * Escape CSS selector to prevent injection
 * @param {string} selector - Selector to escape
 * @returns {string} - Escaped selector
 */
function escapeSelector(selector) {
  if (typeof selector !== 'string') return '';
  return CSS.escape(selector);
}

// ============================================================
// SVG ICON CREATORS (XSS-Safe)
// ============================================================

/**
 * Create notification bell icon (enabled state)
 * @returns {SVGElement}
 */
function createEnabledBellIcon() {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("width", "18");
  svg.setAttribute("height", "18");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "currentColor");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "2");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("aria-hidden", "true");

  const path1 = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path1.setAttribute("d", "M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9");
  
  const path2 = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path2.setAttribute("d", "M13.73 21a2 2 0 0 1-3.46 0");

  svg.appendChild(path1);
  svg.appendChild(path2);
  return svg;
}

/**
 * Create notification bell icon (disabled state)
 * @returns {SVGElement}
 */
function createDisabledBellIcon() {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
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
    "M13.73 21a2 2 0 0 1-3.46 0",
    "M18.63 13A17.89 17.89 0 0 1 18 8",
    "M6.26 6.26A5.86 5.86 0 0 0 6 8c0 7-3 9-3 9h14",
    "M18 8a6 6 0 0 0-9.33-5"
  ];

  paths.forEach(d => {
    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
    path.setAttribute("d", d);
    svg.appendChild(path);
  });

  const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
  line.setAttribute("x1", "1");
  line.setAttribute("y1", "1");
  line.setAttribute("x2", "23");
  line.setAttribute("y2", "23");
  svg.appendChild(line);

  return svg;
}

/**
 * Create kebab menu icon
 * @returns {SVGElement}
 */
function createKebabIcon() {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("width", "14");
  svg.setAttribute("height", "14");
  svg.setAttribute("fill", "currentColor");
  svg.setAttribute("viewBox", "0 0 16 16");
  svg.setAttribute("aria-hidden", "true");

  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("d", "M9.5 13a1.5 1.5 0 1 1-3 0 1.5 1.5 0 0 1 3 0zm0-5a1.5 1.5 0 1 1-3 0 1.5 1.5 0 0 1 3 0zm0-5a1.5 1.5 0 1 1-3 0 1.5 1.5 0 0 1 3 0z");
  
  svg.appendChild(path);
  return svg;
}

// ============================================================
// FIREBASE CONFIGURATION
// ============================================================
const firebaseConfig = {
  apiKey: "AIzaSyDOiYfkCf3Y1Fq7625HimKsm3wYwjBWoxc",
  authDomain: "konvo-d357d.firebaseapp.com",
  projectId: "konvo-d357d",
  storageBucket: "konvo-d357d.firebasestorage.app",
  messagingSenderId: "924631278394",
  appId: "1:924631278394:web:84b8642b5366d869926603"
};

// App start time for determining new messages
const appStartTime = Date.now();

// ============================================================
// DOM ELEMENTS
// ============================================================
const elements = {
  // Containers
  feedContainer: document.getElementById("feedContainer"),
  loading: document.getElementById("loading"),
  
  // Navigation
  navConfessions: document.getElementById("navConfessions"),
  navChat: document.getElementById("navChat"),
  
  // Forms
  confessionForm: document.getElementById("confessionForm"),
  confessionInput: document.getElementById("confessionInput"),
  chatForm: document.getElementById("chatForm"),
  chatInput: document.getElementById("chatInput"),
  
  // Character Counters (NEW)
  chatCharCount: document.getElementById("chatCharCount"),
  confessionCharCount: document.getElementById("confessionCharCount"),
  
  // Typing & Pinned
  typingIndicator: document.getElementById("typingIndicator"),
  pinnedMessageBar: document.getElementById("pinnedMessageBar"),
  pinnedMessageText: document.getElementById("pinnedMessageText"),
  
  // Scroll
  scrollToBottomBtn: document.getElementById("scrollToBottomBtn"),
  newMsgCount: document.getElementById("newMsgCount"),
  
  // Profile Modal
  profileButton: document.getElementById("profileButton"),
  notificationButton: document.getElementById("notificationButton"),
  profileModal: document.getElementById("profileModal"),
  modalCloseButton: document.getElementById("modalCloseButton"),
  modalSaveButton: document.getElementById("modalSaveButton"),
  modalUsernameInput: document.getElementById("modalUsernameInput"),
  
  // Edit Modal
  editModal: document.getElementById("editModal"),
  modalEditTextArea: document.getElementById("modalEditTextArea"),
  editModalCancelButton: document.getElementById("editModalCancelButton"),
  editModalSaveButton: document.getElementById("editModalSaveButton"),
  
  // Confirm Modal
  confirmModal: document.getElementById("confirmModal"),
  confirmModalText: document.getElementById("confirmModalText"),
  confirmModalNoButton: document.getElementById("confirmModalNoButton"),
  confirmModalActionContainer: document.getElementById("confirmModalActionContainer"),
  
  // Context Menu
  contextMenu: document.getElementById("contextMenu"),
  menuEdit: document.getElementById("menuEdit"),
  menuDelete: document.getElementById("menuDelete"),
  menuSelect: document.getElementById("menuSelect"),
  
  // Selection Bar
  selectionBar: document.getElementById("selectionBar"),
  selectionCount: document.getElementById("selectionCount"),
  selectionCancel: document.getElementById("selectionCancel"),
  selectionDelete: document.getElementById("selectionDelete"),
  
  // Reply Bar
  replyBar: document.getElementById("replyBar"),
  replyAuthor: document.getElementById("replyAuthor"),
  replyText: document.getElementById("replyText"),
  cancelReply: document.getElementById("cancelReply"),
};

// Destructure for convenience
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

// Dynamic menu items (created at runtime)
let menuPin = null;
let menuBan = null;

// ============================================================
// STATE MANAGEMENT
// ============================================================
const state = {
  // Firebase instances
  app: null,
  db: null,
  auth: null,
  
  // User state
  currentUserId: null,
  currentUsername: "Anonymous",
  currentProfilePhotoURL: null,
  isCurrentUserAdmin: false,
  
  // Data caches
  userProfiles: {},
  lastConfessionDocs: [],
  lastChatDocs: [],
  
  // Profile loading state (NEW - for on-demand loading)
  pendingProfileLoads: new Set(),
  profileLoadTimeout: null,
  
  // Collections
  confessionsCollection: null,
  chatCollection: null,
  typingStatusCollection: null,
  
  // Current page
  currentPage: "chat",
  
  // UI state
  isSelectionMode: false,
  selectedMessages: new Set(),
  currentContextMenuData: null,
  replyToMessage: null,
  notificationsEnabled: false,
  
  // Scroll state
  unreadMessages: 0,
  userIsAtBottom: true,
  bottomObserver: null,
  
  // Edit state
  docToEditId: null,
  collectionToEdit: null,
  
  // Typing state
  typingTimeout: null,
  
  // Flags
  isInitialized: false,
  isBanned: false,
};

// Rate limit tracking
const rateLimitState = {
  lastMessageTime: 0,
  isRateLimited: false
};

// Unsubscribe functions
const unsubscribers = {
  confessions: () => {},
  chat: () => {},
  userProfiles: () => {},
  typingStatus: () => {},
  pinned: () => {},
  banCheck: () => {},
};

// ============================================================
// CONSTANTS
// ============================================================

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
const RATE_LIMIT_MS = 2000;
const TYPING_STALE_THRESHOLD = 5000;

// ============================================================
// UTILITY FUNCTIONS
// ============================================================

/**
 * Generate consistent color for user ID
 * @param {string} userId - User ID
 * @returns {string} - Hex color
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
 * Format message timestamp
 * @param {Date} date - Message date
 * @returns {string} - Formatted time string
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
 * Get date header text
 * @param {Date} date - Date to format
 * @returns {string} - Header text
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

/**
 * Show toast/alert message
 * @param {string} message - Message to show
 * @param {string} type - Type of message (error, success, info)
 */
function showToast(message, type = 'info') {
  console.log(`[${type.toUpperCase()}]:`, message);
  if (type === 'error') {
    alert(message);
  }
}

/**
 * Create action container for confirm modal if needed
 * @returns {HTMLElement|null}
 */
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

/**
 * Clean up all Firebase listeners
 */
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

/**
 * Update character counter for an input (NEW)
 * @param {HTMLTextAreaElement} input - The textarea element
 * @param {HTMLElement} counter - The counter element
 */
function updateCharacterCounter(input, counter) {
  if (!input || !counter) return;
  
  const currentLength = input.value.length;
  const maxLength = MESSAGE_MAX_LENGTH;
  
  // Update text
  counter.textContent = `${currentLength}/${maxLength}`;
  
  // Show counter if there's content
  if (currentLength > 0) {
    counter.classList.add('visible');
  } else {
    counter.classList.remove('visible');
  }
  
  // Remove all state classes first
  counter.classList.remove('warning', 'danger', 'limit');
  
  // Add appropriate state class
  if (currentLength >= maxLength) {
    counter.classList.add('limit');
  } else if (currentLength >= maxLength * 0.95) {
    // 95%+ = danger
    counter.classList.add('danger');
  } else if (currentLength >= maxLength * 0.8) {
    // 80%+ = warning
    counter.classList.add('warning');
  }
}

// ============================================================
// SERVICE WORKER REGISTRATION
// ============================================================

/**
 * Register service worker for PWA capabilities
 */
function registerServiceWorker() {
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('sw.js', { scope: '/' })
      .then(reg => {
        console.log('SW registered:', reg.scope);
        
        // Check for updates
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

// ============================================================
// CONNECTION MONITORING
// ============================================================

/**
 * Setup connection status monitoring
 */
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

// ============================================================
// NOTIFICATION FUNCTIONS
// ============================================================

/**
 * Setup notification button and permissions
 */
function setupNotificationButton() {
  if (!notificationButton) return;
  
  notificationButton.addEventListener("click", handleNotificationClick);
  
  // Check existing permission
  if ("Notification" in window && Notification.permission === "granted") {
    state.notificationsEnabled = true;
  }
  
  updateNotificationIcon();
}

/**
 * Handle notification button click
 * @param {Event} e - Click event
 */
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

/**
 * Update notification button icon based on state
 */
function updateNotificationIcon() {
  if (!notificationButton) return;
  
  // Clear existing content safely
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
 * Show a notification
 * @param {string} title - Notification title
 * @param {string} body - Notification body
 */
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

// ============================================================
// ADMIN FUNCTIONS
// ============================================================

/**
 * Setup admin-specific menu items
 */
function setupAdminMenu() {
  const ul = contextMenu?.querySelector("ul");
  if (!ul || document.getElementById("menuPin")) return;

  // Create Pin menu item
  menuPin = document.createElement("li");
  menuPin.id = "menuPin";
  menuPin.setAttribute("role", "menuitem");
  menuPin.setAttribute("tabindex", "-1");
  menuPin.textContent = "Pin Message 📌";
  menuPin.addEventListener("click", togglePinMessage);
  
  if (menuDelete) {
    ul.insertBefore(menuPin, menuDelete);
  }

  // Create Ban menu item
  menuBan = document.createElement("li");
  menuBan.id = "menuBan";
  menuBan.className = "text-red-500 hover:text-red-400 font-bold border-t border-[#333] mt-1 pt-1";
  menuBan.setAttribute("role", "menuitem");
  menuBan.setAttribute("tabindex", "-1");
  menuBan.textContent = "Ban User 🚫";
  menuBan.addEventListener("click", toggleBanUser);
  ul.appendChild(menuBan);
}

/**
 * Toggle pin status of a message
 */
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

/**
 * Toggle ban status of a user
 */
async function toggleBanUser() {
  if (!state.currentContextMenuData || !state.db) return;
  
  const { userId, username } = state.currentContextMenuData;
  
  if (userId === state.currentUserId) {
    showToast("You cannot ban yourself.", "error");
    hideDropdownMenu();
    return;
  }

  const userProfile = state.userProfiles[userId] || {};
  const isBanned = userProfile.banned === true;
  const action = isBanned ? "UNBAN" : "BAN";
  const safeUsername = sanitizeText(username || 'this user');

  if (confirm(`Are you sure you want to ${action} ${safeUsername}?`)) {
    hideDropdownMenu();
    
    try {
      const batch = writeBatch(state.db);
      const userRef = doc(state.db, "users", userId);
      
      batch.set(userRef, { banned: !isBanned }, { merge: true });
      
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
      
      await batch.commit();
      showToast(`User has been ${isBanned ? "UNBANNED" : "BANNED"}.`, "info");
      
    } catch (e) {
      console.error('Ban error:', e);
      showToast(`Failed to ${action} user.`, "error");
    }
  } else {
    hideDropdownMenu();
  }
}

// ============================================================
// FIREBASE INITIALIZATION
// ============================================================

/**
 * Initialize Firebase and authentication
 */
async function initFirebase() {
  try {
    state.app = initializeApp(firebaseConfig);

    try {
      initializeAppCheck(state.app, {
        provider: new ReCaptchaEnterpriseProvider('6Ldv2yYsAAAAAJhp5E6hovquodb8WoS9thyDA6hE'),
        isTokenAutoRefreshEnabled: true
      });
    } catch (appCheckError) {
      console.warn('App Check initialization failed:', appCheckError);
    }

    // Use modern persistence API
    try {
      state.db = initializeFirestore(state.app, {
        localCache: persistentLocalCache({
          tabManager: persistentMultipleTabManager()
        })
      });
    } catch (persistenceError) {
      // Fallback if persistence fails
      console.warn('Persistence initialization failed, using default:', persistenceError);
      state.db = initializeFirestore(state.app, {});
    }

    state.auth = getAuth(state.app);
    onAuthStateChanged(state.auth, handleAuthStateChange);

  } catch (error) {
    console.error("Error initializing Firebase:", error);
    setTextSafely(loading, "Error: Could not initialize. Please refresh.");
    throw error;
  }
}

/**
 * Handle authentication state changes
 * @param {Object|null} user - Firebase user object
 */
async function handleAuthStateChange(user) {
  if (user) {
    state.currentUserId = user.uid;
    console.log("Authenticated with UID:", state.currentUserId);

    state.confessionsCollection = collection(state.db, "confessions");
    state.chatCollection = collection(state.db, "chat");
    state.typingStatusCollection = collection(state.db, "typingStatus");

    registerServiceWorker();
    setupNotificationButton();
    setupAdminMenu();
    setupConnectionMonitor();

    listenForUserProfiles();
    listenForBanStatus();

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

    initScrollObserver();
    showPage(state.currentPage);
    state.isInitialized = true;
    
  } else {
    try {
      await signInAnonymously(state.auth);
    } catch (e) {
      console.error("Anonymous auth failed:", e);
      setTextSafely(loading, "Error: Could not sign in. Please refresh.");
    }
  }
}

/**
 * Check if current user is an admin
 */
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

// ============================================================
// PINNED MESSAGES
// ============================================================

/**
 * Listen for pinned messages in current collection
 */
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

// ============================================================
// BAN STATUS
// ============================================================

/**
 * Listen for ban status changes
 */
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
        state.isBanned = true;
        state.userProfiles = {};
        
        cleanupAllListeners();
        showBannedScreen();
      }
    },
    (error) => {
      console.warn("Ban check error:", error);
    }
  );
}

/**
 * Show banned user screen
 */
function showBannedScreen() {
  document.body.innerHTML = '';
  document.body.className = 'banned-overlay';
  
  const h1 = document.createElement('h1');
  h1.className = "text-3xl";
  h1.textContent = "🚫 ACCESS DENIED";
  
  const p = document.createElement('p');
  p.textContent = "You have been banned from Konvo.";
  
  document.body.appendChild(h1);
  document.body.appendChild(p);
}

// ============================================================
// SCROLL OBSERVER
// ============================================================

/**
 * Initialize intersection observer for scroll tracking
 */
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

  // Add passive scroll listener for smoother scrolling
  feedContainer?.addEventListener('scroll', () => {
    // Additional scroll-based logic if needed
  }, { passive: true });
}

/**
 * Update scroll to bottom button visibility
 */
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

/**
 * Scroll to bottom of feed
 */
function scrollToBottom() {
  if (!feedContainer) return;
  
  feedContainer.scrollTop = feedContainer.scrollHeight;
  state.userIsAtBottom = true;
  state.unreadMessages = 0;
  updateScrollButton();
}

// ============================================================
// USER PROFILES (UPDATED - On-Demand Loading)
// ============================================================

/**
 * Request a user profile to be loaded (batched for efficiency)
 * @param {string} userId - User ID to load
 */
function requestUserProfile(userId) {
  if (!userId || typeof userId !== 'string') return;
  
  // Skip if already loaded
  if (state.userProfiles[userId]) return;
  
  // Skip if already pending
  if (state.pendingProfileLoads.has(userId)) return;
  
  // Add to pending queue
  state.pendingProfileLoads.add(userId);
  
  // Debounce the actual loading (wait 100ms to batch requests)
  if (state.profileLoadTimeout) {
    clearTimeout(state.profileLoadTimeout);
  }
  
  state.profileLoadTimeout = setTimeout(() => {
    loadPendingProfiles();
  }, 100);
}

/**
 * Load all pending user profiles in a batch
 */
async function loadPendingProfiles() {
  if (state.pendingProfileLoads.size === 0) return;
  if (!state.db) return;
  
  // Get the pending user IDs and clear the queue
  const userIds = Array.from(state.pendingProfileLoads);
  state.pendingProfileLoads.clear();
  
  // Firestore "in" queries are limited to 30 items
  // So we need to batch them
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
      
      // On error, try loading individually
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
  
  // After loading, re-render to show the names
  updateDisplayedUsernames();
}

/**
 * Update displayed usernames after profiles are loaded
 */
function updateDisplayedUsernames() {
  // Find all message bubbles and update their displayed usernames
  document.querySelectorAll('.message-bubble').forEach((bubble) => {
    const userId = bubble.dataset.userId;
    if (!userId) return;
    
    const profile = state.userProfiles[userId];
    if (!profile) return;
    
    const username = profile.username || "Anonymous";
    
    // Find the username element within this bubble
    const usernameEl = bubble.querySelector('.font-bold.text-sm.opacity-90');
    if (usernameEl && usernameEl.textContent !== username) {
      usernameEl.textContent = username;
    }
    
    // Also update the profile photo if needed
    const imgEl = bubble.querySelector('.chat-pfp');
    if (imgEl && profile.profilePhotoURL) {
      const currentSrc = imgEl.getAttribute('src');
      if (currentSrc !== profile.profilePhotoURL && isValidProfilePhotoURL(profile.profilePhotoURL)) {
        imgEl.src = profile.profilePhotoURL;
      }
    }
  });
}

/**
 * Listen for user profile changes (only for profiles we've already loaded)
 * This keeps cached profiles up-to-date without loading all users
 */
function listenForUserProfiles() {
  if (typeof unsubscribers.userProfiles === 'function') {
    unsubscribers.userProfiles();
    unsubscribers.userProfiles = () => {};
  }

  // Only set up listener if we have some profiles loaded
  // This listener will update profiles we already have
  const checkAndSetupListener = () => {
    const loadedUserIds = Object.keys(state.userProfiles);
    
    if (loadedUserIds.length === 0) {
      // No profiles loaded yet, check again later
      setTimeout(checkAndSetupListener, 2000);
      return;
    }
    
    // Limit to first 30 users (Firestore "in" query limit)
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
          
          // Update displayed usernames when profiles change
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
  
  // Start checking after a short delay
  setTimeout(checkAndSetupListener, 1000);
}

/**
 * Load current user's profile
 */
async function loadUserProfile() {
  if (!state.db || !state.currentUserId) return;
  
  try {
    const userDoc = await getDoc(doc(state.db, "users", state.currentUserId));
    
    if (userDoc.exists()) {
      const data = userDoc.data();
      
      // Cache the profile
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

/**
 * Handle profile save
 */
async function handleProfileSave() {
  if (!state.db || !state.currentUserId) return;
  
  const inputVal = modalUsernameInput.value.trim();
  
  if (!isValidUsername(inputVal)) {
    showToast("Invalid username. Use letters, numbers, underscores, hyphens, and spaces only (1-30 characters).", "error");
    modalUsernameInput.classList.add("error");
    setTimeout(() => modalUsernameInput.classList.remove("error"), 500);
    return;
  }
  
  // Disable all modal buttons during save
  modalSaveButton.textContent = "CHECKING...";
  modalSaveButton.disabled = true;
  modalCloseButton.disabled = true;
  modalUsernameInput.disabled = true;
  modalSaveButton.classList.add("loading");
  
  try {
    const q = query(
      collection(state.db, "users"), 
      where("username", "==", inputVal)
    );
    const querySnapshot = await getDocs(q);
    
    let isTaken = false;
    querySnapshot.forEach((docSnapshot) => {
      if (docSnapshot.id !== state.currentUserId) {
        isTaken = true;
      }
    });
    
    if (isTaken) {
      showToast("Username is already taken!", "error");
      return;
    }
    
    modalSaveButton.textContent = "SAVING...";
    
    const firstLetter = inputVal.charAt(0).toUpperCase();
    const newProfilePhotoURL = `https://placehold.co/32x32/000000/ffffff?text=${encodeURIComponent(firstLetter)}`;
    
    await setDoc(doc(state.db, "users", state.currentUserId), {
      username: inputVal,
      profilePhotoURL: newProfilePhotoURL,
    }, { merge: true });
    
    state.currentUsername = inputVal;
    state.currentProfilePhotoURL = newProfilePhotoURL;
    
    // Update cached profile
    state.userProfiles[state.currentUserId] = {
      ...state.userProfiles[state.currentUserId],
      username: inputVal,
      profilePhotoURL: newProfilePhotoURL
    };
    
    closeProfileModal();
    
  } catch (error) {
    console.error("Error saving profile:", error);
    showToast("Error saving profile. Please try again.", "error");
  } finally {
    modalSaveButton.textContent = "SAVE";
    modalSaveButton.disabled = false;
    modalCloseButton.disabled = false;
    modalUsernameInput.disabled = false;
    modalSaveButton.classList.remove("loading");
  }
}

// ============================================================
// MODAL FUNCTIONS
// ============================================================

/**
 * Open profile modal
 */
function openProfileModal() {
  if (!modalUsernameInput || !profileModal) return;
  
  modalUsernameInput.value = state.currentUsername === "Anonymous" 
    ? "" 
    : state.currentUsername;
  
  profileModal.classList.add("is-open");
  profileModal.setAttribute("aria-hidden", "false");
  
  setTimeout(() => modalUsernameInput.focus(), 100);
}

/**
 * Close profile modal
 */
function closeProfileModal() {
  if (!profileModal) return;
  
  profileModal.classList.remove("is-open");
  profileModal.setAttribute("aria-hidden", "true");
}

/**
 * Show edit message modal
 * @param {string} docId - Document ID
 * @param {string} collectionName - Collection name
 * @param {string} currentText - Current message text
 */
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

/**
 * Close edit modal
 */
function closeEditModal() {
  if (!editModal) return;
  
  editModal.classList.remove("is-open");
  editModal.setAttribute("aria-hidden", "true");
  state.docToEditId = null;
  state.collectionToEdit = null;
}

/**
 * Save edited message
 */
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

/**
 * Show confirmation modal
 * @param {string} text - Confirmation text
 * @param {boolean} isMine - Whether message belongs to current user
 * @param {string} docId - Document ID
 */
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

/**
 * Close confirmation modal
 */
function closeConfirmModal() {
  if (!confirmModal) return;
  
  confirmModal.classList.remove("is-open");
  confirmModal.setAttribute("aria-hidden", "true");
}

// ============================================================
// REACTIONS
// ============================================================

/**
 * Toggle reaction on a message
 * @param {string} docId - Document ID
 * @param {string} collectionName - Collection name
 * @param {string} reactionType - Type of reaction
 * @param {boolean} hasReacted - Whether user already reacted
 */
async function toggleReaction(docId, collectionName, reactionType, hasReacted) {
  if (!state.db || !state.currentUserId) return;
  
  if (!Object.prototype.hasOwnProperty.call(REACTION_TYPES, reactionType)) {
    return;
  }
  
  const docRef = doc(state.db, collectionName, docId);
  const reactionField = `reactions.${reactionType}`;
  
  try {
    if (hasReacted) {
      await updateDoc(docRef, { 
        [reactionField]: arrayRemove(state.currentUserId) 
      });
    } else {
      await updateDoc(docRef, { 
        [reactionField]: arrayUnion(state.currentUserId) 
      });
    }
  } catch (error) {
    console.error("Error toggling reaction:", error);
  }
}

// ============================================================
// CONTEXT MENU
// ============================================================

/**
 * Show dropdown context menu
 * @param {Event} event - Click event
 * @param {Object} data - Message data
 */
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
    const userProfile = state.userProfiles[data.userId] || {};
    const isBanned = userProfile.banned === true;
    menuBan.textContent = isBanned ? "Unban User ✅" : "Ban User 🚫";
    menuBan.className = isBanned
      ? "text-green-500 hover:text-green-400 font-bold border-t border-[#333] mt-1 pt-1"
      : "text-red-500 hover:text-red-400 font-bold border-t border-[#333] mt-1 pt-1";
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

/**
 * Hide dropdown menu
 */
function hideDropdownMenu() {
  if (contextMenu) {
    contextMenu.classList.remove("is-open");
  }
}

// ============================================================
// SELECTION MODE
// ============================================================

/**
 * Handle message click in selection mode
 * @param {HTMLElement} bubble - Message bubble element
 */
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

/**
 * Enter selection mode
 */
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

/**
 * Exit selection mode
 */
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

/**
 * Update selection bar count
 */
function updateSelectionBar() {
  const count = state.selectedMessages.size;
  setTextSafely(selectionCount, `${count} selected`);
  
  if (count === 0 && state.isSelectionMode) {
    exitSelectionMode();
  }
}

/**
 * Handle multi-message delete
 */
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

// ============================================================
// PAGE NAVIGATION
// ============================================================

/**
 * Show specified page (chat or confessions)
 * @param {string} page - Page name
 */
function showPage(page) {
  if (page !== 'chat' && page !== 'confessions') {
    page = 'chat';
  }
  
  state.currentPage = page;
  
  if (state.isSelectionMode) exitSelectionMode();
  cancelReplyMode();
  
  // Clean up reaction pickers on page change
  document.querySelectorAll(".reaction-picker").forEach(p => p.remove());
  
  // Properly clean up listeners
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

// ============================================================
// REAL-TIME LISTENERS
// ============================================================

/**
 * Safe wrapper for renderFeed with error handling
 * @param {Array} docs - Firestore documents
 * @param {string} type - Collection type
 * @param {Object} snapshot - Firestore snapshot
 * @param {boolean} isRerender - Whether this is a re-render
 * @param {boolean} isFirstSnapshot - Whether this is the first snapshot
 */
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

/**
 * Listen for confessions
 * @param {boolean} isRerender - Whether this is a re-render
 */
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

/**
 * Listen for chat messages
 * @param {boolean} isRerender - Whether this is a re-render
 */
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

/**
 * Listen for typing status with improved stale detection
 */
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
        const userId = docSnap.id;
        
        // Skip self
        if (userId === state.currentUserId) return;
        
        // Check if still typing and not stale
        if (data.isTyping && data.timestamp) {
          const timeSinceTyping = now - data.timestamp;
          
          if (timeSinceTyping < TYPING_STALE_THRESHOLD) {
            const username = state.userProfiles[userId]?.username || "Someone";
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

/**
 * Update typing status
 * @param {boolean} isTyping - Whether user is typing
 */
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
    // Silent fail for typing status
  }
}, 300);

// ============================================================
// RENDER FEED
// ============================================================

/**
 * Render message feed
 * @param {Array} docs - Firestore documents
 * @param {string} type - Collection type
 * @param {Object} snapshot - Firestore snapshot
 * @param {boolean} isRerender - Whether this is a re-render
 * @param {boolean} isFirstSnapshot - Whether this is the first snapshot
 */
function renderFeed(docs, type, snapshot, isRerender, isFirstSnapshot = false) {
  if (!feedContainer) return;
  
  // Clean up any floating reaction pickers
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
    
    // Skip hidden messages
    if (data.hiddenFor?.includes(state.currentUserId)) {
      return;
    }

    const text = data.text || "...";
    const messageDateObj = data.timestamp ? data.timestamp.toDate() : new Date();
    const messageDateStr = messageDateObj.toDateString();

    // Request user profile if not loaded (NEW - on-demand loading)
    const docUserId = data.userId;
    if (docUserId && !state.userProfiles[docUserId]) {
      requestUserProfile(docUserId);
    }
    
    // Also request profile for reply author if exists
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
    const photoURL = profile.profilePhotoURL || 
      `https://placehold.co/32x32/000000/ffffff?text=${encodeURIComponent(firstChar)}`;
    
    const isMine = state.currentUserId && docUserId === state.currentUserId;
    const isConsecutive = docUserId && docUserId === lastUserId;
    lastUserId = docUserId;
    
    const userColor = getUserColor(docUserId);

    // Create message structure
    const alignWrapper = document.createElement("div");
    alignWrapper.className = `flex w-full ${isMine ? "justify-end" : "justify-start"}`;
    
    const row = document.createElement("div");
    row.className = "message-wrapper";

    // Create bubble
    const bubble = document.createElement("div");
    // NOTE: Top spacing is applied to the wrapper so the kebab button (positioned relative to wrapper)
    // aligns with the bubble's top edge on mobile.
    bubble.className = `message-bubble rounded-lg max-w-xs sm:max-w-md md:max-w-lg ${isMine ? "my-message" : ""}`;
    
    // Pinned styling
    if (data.isPinned) {
      bubble.classList.add("pinned");
    }
    
    // Dataset attributes
    bubble.dataset.id = docInstance.id;
    bubble.dataset.text = text;
    bubble.dataset.isMine = String(isMine);
    bubble.dataset.userId = docUserId || '';
    bubble.dataset.username = username;
    bubble.dataset.isPinned = String(data.isPinned || false);
    bubble.dataset.timestamp = data.timestamp ? String(data.timestamp.toMillis()) : String(Date.now());
    
    // Styling for other users
    if (!isMine) {
      bubble.style.borderLeft = `3px solid ${userColor}`;
      bubble.style.background = `linear-gradient(90deg, ${userColor}10, transparent)`;
    }
    
    // Selection mode styling
    if (state.isSelectionMode && state.selectedMessages.has(docInstance.id)) {
      bubble.classList.add("selected-message");
    }
    
    // Click handler for selection
    bubble.addEventListener('click', (e) => {
      if (state.isSelectionMode) {
        e.preventDefault();
        e.stopPropagation();
        handleMessageClick(bubble);
      }
    });

    // Kebab menu button - positioned outside bubble at top corner
    const kebabBtn = document.createElement("button");
    kebabBtn.type = "button";
    kebabBtn.className = "kebab-btn";
    kebabBtn.setAttribute("aria-label", "Message options");
    kebabBtn.appendChild(createKebabIcon());
    kebabBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      showDropdownMenu(e, bubble.dataset);
    });

    // Header with avatar and username (if not consecutive)
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
        this.src = `https://placehold.co/32x32/000000/ffffff?text=${encodeURIComponent(firstChar)}`;
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

    // Footer with timestamp
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

    // Reaction chips
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

    // Action buttons (bottom) - Reply
    const replyBtn = document.createElement("button");
    replyBtn.type = "button";
    replyBtn.className = "side-action-btn";
    replyBtn.setAttribute("aria-label", "Reply to message");
    replyBtn.textContent = "↩";
    replyBtn.onclick = (e) => {
      e.stopPropagation();
      startReplyMode(bubble.dataset);
    };

    // Action buttons (bottom) - React
    const reactBtn = document.createElement("button");
    reactBtn.type = "button";
    reactBtn.className = "side-action-btn";
    reactBtn.setAttribute("aria-label", "Add reaction");
    reactBtn.textContent = "♡";

    // Reaction picker
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

    // Bubble wrapper for positioning kebab outside
    const bubbleWrapper = document.createElement("div");
    bubbleWrapper.className = `bubble-wrapper ${isMine ? "my-bubble-wrapper" : ""} ${isConsecutive ? "mt-0.5" : "mt-2"}`;
    bubbleWrapper.appendChild(kebabBtn);
    bubbleWrapper.appendChild(bubble);

    // Assemble row based on message ownership
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
  
  // Scroll anchor for observer
  const scrollAnchor = document.createElement("div");
  scrollAnchor.id = "scrollAnchor";
  scrollAnchor.style.height = "1px";
  scrollAnchor.style.width = "100%";
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

// ============================================================
// MESSAGE POSTING
// ============================================================

/**
 * Post a message
 * @param {Object} collectionRef - Firestore collection reference
 * @param {HTMLTextAreaElement} input - Input element
 */
async function postMessage(collectionRef, input) {
  if (state.currentUsername === "Anonymous") {
    showToast("Please set a username first!", "error");
    openProfileModal();
    return;
  }
  
  if (state.db && state.currentUserId) {
    try {
      const banRef = doc(state.db, "banned_users", state.currentUserId);
      const banSnap = await getDoc(banRef);
      if (banSnap.exists()) {
        showToast("You have been banned from posting.", "error");
        input.value = "";
        return;
      }
    } catch (e) {
      console.warn("Ban check error:", e);
    }
  }
  
  // Validate message with enhanced validation
  const validation = validateMessageBeforePost(input.value);
  if (!validation.valid) {
    showToast(validation.error, "error");
    return;
  }
  
  const text = validation.text;
  
  if (!state.db) return;
  
  // Client-side rate limit check
  const now = Date.now();
  if (now - rateLimitState.lastMessageTime < RATE_LIMIT_MS) {
    const remainingTime = Math.ceil((RATE_LIMIT_MS - (now - rateLimitState.lastMessageTime)) / 1000);
    showToast(`Please wait ${remainingTime} second${remainingTime > 1 ? 's' : ''} before sending another message.`, "error");
    return;
  }
  
  input.disabled = true;
  
  // Add visual loading state
  const submitBtn = collectionRef === state.chatCollection ? 
    document.getElementById('chatButton') : 
    document.getElementById('confessionButton');
    
  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.classList.add('loading');
    const originalText = submitBtn.textContent;
    submitBtn.textContent = 'SENDING...';
  }
  
  try {
    const messageData = {
      text: text,
      timestamp: serverTimestamp(),
      userId: state.currentUserId,
    };
    
    if (state.replyToMessage) {
      messageData.replyTo = {
        messageId: state.replyToMessage.id,
        userId: state.replyToMessage.userId,
        text: state.replyToMessage.text?.substring(0, 500) || ''
      };
    }
    
    await addDoc(collectionRef, messageData);

    await setDoc(doc(state.db, "users", state.currentUserId), {
      lastMessageAt: serverTimestamp()
    }, { merge: true });

    rateLimitState.lastMessageTime = Date.now();
    
    input.value = "";
    cancelReplyMode();
    updateTypingStatus(false);
    scrollToBottom();
    
    // Reset character counter (NEW)
    const counter = input === chatInput ? chatCharCount : confessionCharCount;
    updateCharacterCounter(input, counter);
    
  } catch (e) {
    console.error('Post error:', e);
    if (e.code === 'permission-denied') {
      showToast("Please wait a moment before sending another message.", "error");
      rateLimitState.lastMessageTime = Date.now();
    } else {
      showToast("Failed to send message. Please try again.", "error");
    }
  
  } finally {
    input.disabled = false;
    input.focus();
    
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.classList.remove('loading');
      submitBtn.textContent = collectionRef === state.chatCollection ? 'SEND' : 'POST';
    }
  }
}

// ============================================================
// REPLY MODE
// ============================================================

/**
 * Start reply mode
 * @param {Object} messageData - Message data object
 */
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

/**
 * Cancel reply mode
 */
function cancelReplyMode() {
  state.replyToMessage = null;
  
  if (replyBar) {
    replyBar.classList.remove("show");
  }
}

// ============================================================
// EVENT LISTENERS
// ============================================================

// Global click handler for closing menus
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
  postMessage(state.confessionsCollection, confessionInput);
});

chatForm?.addEventListener("submit", (e) => {
  e.preventDefault();
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

// Modal buttons
profileButton?.addEventListener("click", openProfileModal);
modalCloseButton?.addEventListener("click", closeProfileModal);
modalSaveButton?.addEventListener("click", handleProfileSave);
editModalCancelButton?.addEventListener("click", closeEditModal);
editModalSaveButton?.addEventListener("click", saveEdit);
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

// Selection bar
selectionCancel?.addEventListener("click", exitSelectionMode);
selectionDelete?.addEventListener("click", handleMultiDelete);
cancelReply?.addEventListener("click", cancelReplyMode);

// Input handlers with character counter (UPDATED)
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

// Input event listeners with character counter (UPDATED)
chatInput?.addEventListener("input", () => {
  updateTypingStatus(true);
  updateCharacterCounter(chatInput, chatCharCount);
});

confessionInput?.addEventListener("input", () => {
  updateTypingStatus(true);
  updateCharacterCounter(confessionInput, confessionCharCount);
});

// Escape key handler
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

// Handle visibility change
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") {
    if (state.userIsAtBottom) {
      state.unreadMessages = 0;
      updateScrollButton();
    }
  }
});

// Handle beforeunload
window.addEventListener("beforeunload", () => {
  if (state.db && state.currentUserId) {
    updateTypingStatus(false);
  }
});

// Handle page unload - cleanup listeners
window.addEventListener('unload', () => {
  cleanupAllListeners();
});

// ============================================================
// INITIALIZE APPLICATION
// ============================================================

initFirebase().catch(err => {
  console.error("Failed to initialize app:", err);
  setTextSafely(loading, "Error: Failed to initialize. Please refresh the page.");
});