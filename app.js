import { initializeApp } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-app.js";
// *** ADDED: App Check Import ***
import { initializeAppCheck, ReCaptchaEnterpriseProvider } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-app-check.js";
import {
  getAuth,
  signInAnonymously,
  onAuthStateChanged,
} from "https://www.gstatic.com/firebasejs/11.6.1/firebase-auth.js";
import {
  getFirestore,
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

// *** FIREBASE CONFIGURATION ***
// SECURITY NOTE: These keys are intentionally public (required for client-side Firebase).
// Actual security is enforced by Firebase Security Rules on the server.
// Ensure your Firestore Security Rules restrict read/write access appropriately.
// The reCAPTCHA site key below is also public by design; keep your SECRET key server-side only.
const firebaseConfig = {
    apiKey: "AIzaSyDOiYfkCf3Y1Fq7625HimKsm3wYwjBWoxc",
    authDomain: "konvo-d357d.firebaseapp.com",
    projectId: "konvo-d357d",
    storageBucket: "konvo-d357d.firebasestorage.app",
    messagingSenderId: "924631278394",
    appId: "1:924631278394:web:84b8642b5366d869926603"
  };

const appStartTime = Date.now();

// DOM elements
const feedContainer = document.getElementById("feedContainer");
const loading = document.getElementById("loading");
const navConfessions = document.getElementById("navConfessions");
const navChat = document.getElementById("navChat");
const confessionForm = document.getElementById("confessionForm");
const confessionInput = document.getElementById("confessionInput");
const chatForm = document.getElementById("chatForm");
const chatInput = document.getElementById("chatInput");
const typingIndicator = document.getElementById("typingIndicator");

const pinnedMessageBar = document.getElementById("pinnedMessageBar");
const pinnedMessageText = document.getElementById("pinnedMessageText");
const scrollToBottomBtn = document.getElementById("scrollToBottomBtn");
const newMsgCount = document.getElementById("newMsgCount");

const profileButton = document.getElementById("profileButton");
const profileModal = document.getElementById("profileModal");
const modalCloseButton = document.getElementById("modalCloseButton");
const modalSaveButton = document.getElementById("modalSaveButton");
const modalUsernameInput = document.getElementById("modalUsernameInput");

const editModal = document.getElementById("editModal");
const modalEditTextArea = document.getElementById("modalEditTextArea");
const editModalCancelButton = document.getElementById("editModalCancelButton");
const editModalSaveButton = document.getElementById("editModalSaveButton");

const confirmModal = document.getElementById("confirmModal");
const confirmModalText = document.getElementById("confirmModalText");
const confirmModalNoButton = document.getElementById("confirmModalNoButton");
const confirmModalActionContainer = document.getElementById("confirmModalActionContainer") || createActionContainer();

const contextMenu = document.getElementById("contextMenu");
const menuEdit = document.getElementById("menuEdit");
const menuDelete = document.getElementById("menuDelete");
const menuSelect = document.getElementById("menuSelect");

let menuPin = null;
let menuBan = null;

const selectionBar = document.getElementById("selectionBar");
const selectionCount = document.getElementById("selectionCount");
const selectionCancel = document.getElementById("selectionCancel");
const selectionDelete = document.getElementById("selectionDelete");

const replyBar = document.getElementById("replyBar");
const replyAuthor = document.getElementById("replyAuthor");
const replyText = document.getElementById("replyText");
const cancelReply = document.getElementById("cancelReply");

// State
let app, db, auth;
let currentUserId = null;
let currentUsername = "Anonymous";
let currentProfilePhotoURL = null;
let isCurrentUserAdmin = false; 

let userProfiles = {};
let confessionsCollection;
let chatCollection;
let typingStatusCollection;

let unsubscribeConfessions = () => { };
let unsubscribeChat = () => { };
let unsubscribeUserProfiles = () => { };
let unsubscribeTypingStatus = () => { };
let unsubscribePinned = () => { };
let unsubscribeBanCheck = () => { };

let currentPage = "chat";
let typingTimeout = null;

let docToEditId = null;
let collectionToEdit = null;

let isSelectionMode = false;
let selectedMessages = new Set();
let currentContextMenuData = null;

let replyToMessage = null;
let notificationsEnabled = false;

let unreadMessages = 0;
let userIsAtBottom = true;
let bottomObserver = null;

const REACTION_TYPES = {
  thumbsup: "👍",
  laugh: "😂",
  surprised: "😮",
  heart: "❤️",
  skull: "💀"
};

const USER_COLORS = [
  "#ff79c6", "#8be9fd", "#50fa7b", "#bd93f9", "#ffb86c",
  "#f1fa8c", "#ff5555", "#00e5ff", "#fab1a0", "#a29bfe",
  "#55efc4", "#fdcb6e", "#e17055", "#d63031", "#e84393",
  "#0984e3", "#00b894"
];

function getUserColor(userId) {
  let hash = 0;
  for (let i = 0; i < userId.length; i++) {
    hash = userId.charCodeAt(i) + ((hash << 5) - hash);
  }
  const index = Math.abs(hash % USER_COLORS.length);
  return USER_COLORS[index];
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
  return null;
}

function registerServiceWorker() {
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('sw.js').catch(console.error);
  }
}

function setupNotificationButton() {
  const notifBtn = document.getElementById("notificationButton");
  if (!notifBtn) return;
  notifBtn.addEventListener("click", handleNotificationClick);
  if ("Notification" in window && Notification.permission === "granted") {
    notificationsEnabled = true;
  }
  updateNotificationIcon();
}

async function handleNotificationClick(e) {
  e.preventDefault();
  e.stopPropagation();
  if (!("Notification" in window)) return;
  if (Notification.permission === "granted") {
    notificationsEnabled = !notificationsEnabled;
    updateNotificationIcon();
  } else {
    const permission = await Notification.requestPermission();
    if (permission === "granted") {
      notificationsEnabled = true;
      updateNotificationIcon();
    }
  }
}

function updateNotificationIcon() {
  const btn = document.getElementById("notificationButton");
  if (!btn) return;
  if (notificationsEnabled) {
    btn.classList.add("text-yellow-400");
    btn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="currentColor" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"></path><path d="M13.73 21a2 2 0 0 1-3.46 0"></path></svg>`;
  } else {
    btn.classList.remove("text-yellow-400");
    btn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M13.73 21a2 2 0 0 1-3.46 0"></path><path d="M18.63 13A17.89 17.89 0 0 1 18 8"></path><path d="M6.26 6.26A5.86 5.86 0 0 0 6 8c0 7-3 9-3 9h14"></path><path d="M18 8a6 6 0 0 0-9.33-5"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>`;
  }
}

async function showNotification(title, body) {
  if (!("Notification" in window) || !notificationsEnabled) return;
  const cleanBody = body.length > 50 ? body.substring(0, 50) + "..." : body;
  try {
    if ('serviceWorker' in navigator) {
      const reg = await navigator.serviceWorker.ready;
      if (reg) { reg.showNotification(title, { body: cleanBody, icon: "icon.jpg" }); return; }
    }
    new Notification(title, { body: cleanBody, icon: "icon.jpg" });
  } catch (e) { console.error(e); }
}

function setupAdminMenu() {
  const ul = contextMenu.querySelector("ul");
  if (!ul || document.getElementById("menuPin")) return;
  
  menuPin = document.createElement("li");
  menuPin.id = "menuPin";
  menuPin.className = "hover:bg-[#262626]";
  menuPin.textContent = "Pin Message";
  menuPin.addEventListener("click", togglePinMessage);
  ul.insertBefore(menuPin, menuDelete);

  menuBan = document.createElement("li");
  menuBan.id = "menuBan";
  menuBan.className = "text-red-500 hover:text-red-400 font-bold border-t border-[#333] mt-1 pt-1";
  menuBan.textContent = "Ban User 🚫"; 
  menuBan.addEventListener("click", toggleBanUser);
  ul.appendChild(menuBan);
}

async function togglePinMessage() {
  if (!currentContextMenuData || !db) return;
  const { id, isPinned, text } = currentContextMenuData;
  const isCurrentlyPinned = isPinned === "true";
  hideDropdownMenu();
  try {
    const batch = writeBatch(db);
    const msgRef = doc(db, currentPage, id);
    batch.update(msgRef, { isPinned: !isCurrentlyPinned });
    const pinRef = doc(db, "pinned_messages", id);
    if (isCurrentlyPinned) { batch.delete(pinRef); } 
    else { batch.set(pinRef, { originalId: id, collection: currentPage, text: text, pinnedBy: currentUserId, timestamp: serverTimestamp() }); }
    await batch.commit();
  } catch (e) { console.error(e); alert("Failed to pin. Check Admin permissions."); }
}

async function toggleBanUser() {
  if (!currentContextMenuData || !db) return;
  const { userId, username } = currentContextMenuData;
  if (userId === currentUserId) { alert("You cannot ban yourself."); return; }

  const userProfile = userProfiles[userId] || {};
  const isBanned = userProfile.banned === true;
  const action = isBanned ? "UNBAN" : "BAN";

  if (confirm(`Are you sure you want to ${action} ${username}?`)) {
    hideDropdownMenu();
    try {
      const batch = writeBatch(db);
      const userRef = doc(db, "users", userId);
      batch.set(userRef, { banned: !isBanned }, { merge: true });
      const banRef = doc(db, "banned_users", userId);
      if (isBanned) { batch.delete(banRef); } 
      else { batch.set(banRef, { bannedBy: currentUserId, timestamp: serverTimestamp(), reason: "Admin Action", username: username }); }
      await batch.commit();
      alert(`User ${username} has been ${isBanned ? "UNBANNED" : "BANNED"}.`);
    } catch (e) { alert(`Failed to ${action} user.`); console.error(e); }
  } else { hideDropdownMenu(); }
}

// *** INIT FIREBASE & AUTH ***
async function initFirebase() {
  try {
    app = initializeApp(firebaseConfig);
    
    // *** ADDED: Initialize App Check with Enterprise Key ***
    // This connects your app to the reCAPTCHA key you created
    const appCheck = initializeAppCheck(app, {
      provider: new ReCaptchaEnterpriseProvider('6Ldv2yYsAAAAAJhp5E6hovquodb8WoS9thyDA6hE'),
      isTokenAutoRefreshEnabled: true
    });
    // *******************************************************

    db = getFirestore(app);
    auth = getAuth(app);

    onAuthStateChanged(auth, async (user) => {
      if (user) {
        currentUserId = user.uid;
        console.log("Logged in UID:", currentUserId);
        
        confessionsCollection = collection(db, "confessions");
        chatCollection = collection(db, "chat");
        typingStatusCollection = collection(db, "typingStatus");

        registerServiceWorker();
        setupNotificationButton();
        setupAdminMenu();
        
        listenForUserProfiles();
        listenForBanStatus(); 
        
        try { await checkAdminStatus(); } catch(e) { console.error("Admin check failed:", e); }
        try { await loadUserProfile(); } catch(e) { console.error("Profile load failed:", e); }

        initScrollObserver();
        showPage(currentPage); 
      } else {
        try {
            await signInAnonymously(auth);
        } catch(e) {
            console.error("Auth Failed:", e);
            loading.textContent = "Error: Could not sign in. Enable Anonymous Auth in Firebase Console.";
        }
      }
    });

  } catch (error) {
    console.error("Error initializing:", error);
    loading.textContent = "Error: Refresh page.";
  }
}

// SECURITY NOTE: This client-side admin check is for UI purposes only (defense-in-depth).
// Actual admin permissions MUST be enforced in Firebase Security Rules.
// Never trust client-side isCurrentUserAdmin for sensitive operations.
async function checkAdminStatus() {
  if (!currentUserId || !db) return;
  const adminDocRef = doc(db, "admins", currentUserId);
  const adminDocSnap = await getDoc(adminDocRef);
  if (adminDocSnap.exists()) { isCurrentUserAdmin = true; console.log("Admin Active"); } 
  else { isCurrentUserAdmin = false; }
}

// *** FIXED PINNED LISTENER (Client-Side Filtering) ***
function listenForPinnedMessages() {
  if (unsubscribePinned) unsubscribePinned();
  
  // We query ALL pins (sorted by newest) and filter in JS.
  // This avoids the "Missing Index" error completely.
  const q = query(
      collection(db, "pinned_messages"), 
      orderBy("timestamp", "desc")
  );

  unsubscribePinned = onSnapshot(q, (snapshot) => {
    // Find the first pin that belongs to the CURRENT page (chat vs confessions)
    const matchingPin = snapshot.docs.find(doc => doc.data().collection === currentPage);

    if (matchingPin) {
      const data = matchingPin.data();
      pinnedMessageBar.classList.remove("hidden");
      pinnedMessageText.textContent = data.text;
      
      pinnedMessageBar.onclick = () => {
        const bubble = document.querySelector(`.message-bubble[data-id="${data.originalId}"]`);
        if (bubble) { 
            bubble.scrollIntoView({ behavior: "smooth", block: "center" }); 
            bubble.classList.add("ring-2", "ring-yellow-400"); 
            setTimeout(() => bubble.classList.remove("ring-2", "ring-yellow-400"), 2000); 
        }
      };
    } else { 
      pinnedMessageBar.classList.add("hidden"); 
    }
  }, (error) => {
      console.log("Pinned fetch warning:", error);
  });
}

// SECURITY NOTE: This client-side ban check is for UX only (defense-in-depth).
// Actual ban enforcement MUST be in Firebase Security Rules to block write/read access.
// A determined attacker can bypass this client-side check via DevTools.
function listenForBanStatus() {
  if (unsubscribeBanCheck) unsubscribeBanCheck();
  unsubscribeBanCheck = onSnapshot(doc(db, "banned_users", currentUserId), (docSnap) => {
    if (docSnap.exists()) {
      document.body.innerHTML = `<div class="flex flex-col items-center justify-center h-screen bg-black text-red-600 font-bold gap-4"><h1 class="text-3xl">🚫 ACCESS DENIED</h1><p>You have been banned.</p></div>`;
    }
  });
}

function initScrollObserver() {
  const options = { root: feedContainer, rootMargin: "100px", threshold: 0.1 };
  bottomObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      userIsAtBottom = entry.isIntersecting;
      updateScrollButton();
    });
  }, options);
}

function updateScrollButton() {
  if (userIsAtBottom) {
    scrollToBottomBtn.classList.add("hidden");
    scrollToBottomBtn.style.display = "";
    newMsgCount.classList.add("hidden");
    unreadMessages = 0;
  } else {
    scrollToBottomBtn.classList.remove("hidden");
    scrollToBottomBtn.style.display = "flex";
    if (unreadMessages > 0) {
      newMsgCount.classList.remove("hidden");
      newMsgCount.textContent = unreadMessages > 99 ? "99+" : unreadMessages;
    } else {
      newMsgCount.classList.add("hidden");
    }
  }
}

function listenForUserProfiles() {
  unsubscribeUserProfiles = onSnapshot(collection(db, "users"), (snapshot) => {
    snapshot.docs.forEach((docSnap) => { userProfiles[docSnap.id] = docSnap.data(); });
  });
}

async function loadUserProfile() {
  if (!db || !currentUserId) return;
  const userDoc = await getDoc(doc(db, "users", currentUserId));
  if (userDoc.exists()) {
    const data = userDoc.data();
    currentUsername = data.username || "Anonymous";
    let pfp = data.profilePhotoURL;
    currentProfilePhotoURL = (pfp && pfp.startsWith("http")) ? pfp : null;
    if (data.banned) { document.body.innerHTML = "<div class='flex items-center justify-center h-screen text-red-500 font-bold'>YOU HAVE BEEN BANNED</div>"; throw new Error("User Banned"); }
  }
  modalUsernameInput.value = currentUsername === "Anonymous" ? "" : currentUsername;
}

async function handleProfileSave() {
  if (!db || !currentUserId) return;
  modalSaveButton.textContent = "CHECKING..."; modalSaveButton.disabled = true;
  const inputVal = modalUsernameInput.value.trim();
  if (!inputVal || inputVal.toLowerCase() === "anonymous") { alert("Invalid username."); modalSaveButton.textContent = "SAVE"; modalSaveButton.disabled = false; return; }
  try {
    const q = query(collection(db, "users"), where("username", "==", inputVal));
    const querySnapshot = await getDocs(q);
    let isTaken = false;
    querySnapshot.forEach((doc) => { if (doc.id !== currentUserId) isTaken = true; });
    if (isTaken) { alert("Username taken!"); modalSaveButton.textContent = "SAVE"; modalSaveButton.disabled = false; return; }
    modalSaveButton.textContent = "SAVING...";
    const firstLetter = inputVal.charAt(0).toUpperCase();
    const newProfilePhotoURL = `https://placehold.co/32x32/000000/ffffff?text=${firstLetter}`;
    await setDoc(doc(db, "users", currentUserId), { username: inputVal, profilePhotoURL: newProfilePhotoURL, }, { merge: true });
    currentUsername = inputVal; currentProfilePhotoURL = newProfilePhotoURL;
    closeProfileModal();
  } catch (error) { console.error("Error saving profile: ", error); alert("Error saving profile."); } finally { modalSaveButton.textContent = "SAVE"; modalSaveButton.disabled = false; }
}

function openProfileModal() { modalUsernameInput.value = currentUsername === "Anonymous" ? "" : currentUsername; profileModal.classList.add("is-open"); }
function closeProfileModal() { profileModal.classList.remove("is-open"); }
function showEditModal(docId, collectionName, currentText) { docToEditId = docId; collectionToEdit = collectionName; modalEditTextArea.value = currentText; editModal.classList.add("is-open"); }
function closeEditModal() { editModal.classList.remove("is-open"); docToEditId = null; }

async function saveEdit() {
  const newText = modalEditTextArea.value.trim();
  if (newText && docToEditId) {
    editModalSaveButton.textContent = "SAVING...";
    try { await updateDoc(doc(db, collectionToEdit, docToEditId), { text: newText, edited: true }); closeEditModal(); } 
    catch (e) { alert("Error: You can only edit your own messages."); }
    editModalSaveButton.textContent = "SAVE";
  }
}

function showConfirmModal(text, isMine, docId) {
  confirmModalText.textContent = text;
  confirmModalActionContainer.innerHTML = '';
  const isAdmin = isCurrentUserAdmin;
  if (isMine || isAdmin) {
    const btnForMe = document.createElement('button'); btnForMe.className = "flex-1 px-4 py-2 rounded-lg font-bold text-sm border border-white text-white hover:bg-white hover:text-black"; btnForMe.textContent = "FOR ME";
    btnForMe.onclick = async () => { closeConfirmModal(); try { await updateDoc(doc(db, currentPage, docId), { hiddenFor: arrayUnion(currentUserId) }); } catch(e) { console.error(e); } };
    const btnEveryone = document.createElement('button'); btnEveryone.className = "flex-1 px-4 py-2 rounded-lg font-bold text-sm bg-red-600 text-white hover:bg-red-500 border border-red-600"; btnEveryone.textContent = isAdmin && !isMine ? "NUKE (ADMIN)" : "EVERYONE";
    btnEveryone.onclick = async () => { closeConfirmModal(); try { await deleteDoc(doc(db, currentPage, docId)); } catch (e) { alert("Permission denied."); } };
    confirmModalActionContainer.append(btnForMe, btnEveryone);
  } else {
    const btnForMe = document.createElement('button'); btnForMe.className = "flex-1 px-4 py-2 rounded-lg font-bold text-sm bg-red-600 text-white hover:bg-red-500"; btnForMe.textContent = "HIDE";
    btnForMe.onclick = async () => { closeConfirmModal(); try { await updateDoc(doc(db, currentPage, docId), { hiddenFor: arrayUnion(currentUserId) }); } catch(e) { console.error("Hide failed:", e); } };
    confirmModalActionContainer.appendChild(btnForMe);
  }
  confirmModal.classList.add("is-open");
}
function closeConfirmModal() { confirmModal.classList.remove("is-open"); }

async function toggleReaction(docId, collectionName, reactionType, hasReacted) {
  if (!db || !currentUserId) return;
  const docRef = doc(db, collectionName, docId);
  const reactionField = `reactions.${reactionType}`;
  try {
    if (hasReacted) await updateDoc(docRef, { [reactionField]: arrayRemove(currentUserId) });
    else await updateDoc(docRef, { [reactionField]: arrayUnion(currentUserId) });
  } catch (error) { console.error("Error toggling reaction:", error); }
}

function showDropdownMenu(event, data) {
  event.stopPropagation();
  if (contextMenu.classList.contains("is-open") && currentContextMenuData && currentContextMenuData.id === data.id) { hideDropdownMenu(); return; }
  currentContextMenuData = data;
  const now = Date.now();
  const messageTime = parseInt(currentContextMenuData.timestamp, 10);
  const isRecent = isNaN(messageTime) ? true : (now - messageTime < 900000);
  const isMine = currentContextMenuData.isMine === "true";
  const isAdmin = isCurrentUserAdmin;
  menuEdit.style.display = isRecent && isMine ? "block" : "none";
  menuDelete.style.display = "block";
  if (menuPin) { menuPin.style.display = isAdmin ? "block" : "none"; menuPin.textContent = data.isPinned === "true" ? "Unpin Message" : "Pin Message 📌"; }
  if (menuBan) { 
      menuBan.style.display = (isAdmin && !isMine) ? "block" : "none"; 
      const userProfile = userProfiles[data.userId] || {};
      const isBanned = userProfile.banned === true;
      menuBan.textContent = isBanned ? "Unban User ✅" : "Ban User 🚫";
      menuBan.className = isBanned ? "text-green-500 hover:text-green-400 font-bold border-t border-[#333] mt-1 pt-1" : "text-red-500 hover:text-red-400 font-bold border-t border-[#333] mt-1 pt-1";
  }
  const rect = event.currentTarget.getBoundingClientRect();
  contextMenu.style.top = `${rect.bottom + 2}px`; contextMenu.style.left = isMine ? `${rect.right - 150}px` : `${rect.left}px`;
  contextMenu.classList.add("is-open");
}
function hideDropdownMenu() { contextMenu.classList.remove("is-open"); }
function handleMessageClick(bubble) { if (!isSelectionMode) return; const docId = bubble.dataset.id; if (selectedMessages.has(docId)) { selectedMessages.delete(docId); bubble.classList.remove("selected-message"); } else { selectedMessages.add(docId); bubble.classList.add("selected-message"); } updateSelectionBar(); }
function enterSelectionMode() { isSelectionMode = true; document.body.classList.add("selection-mode"); selectionBar.classList.remove("hidden"); chatForm.classList.add("hidden"); confessionForm.classList.add("hidden"); if (currentContextMenuData) { const docId = currentContextMenuData.id; selectedMessages.add(docId); const bubble = document.querySelector(`.message-bubble[data-id="${docId}"]`); if (bubble) bubble.classList.add("selected-message"); } updateSelectionBar(); }
function exitSelectionMode() { isSelectionMode = false; document.body.classList.remove("selection-mode"); selectionBar.classList.add("hidden"); selectedMessages.clear(); if (currentPage === "chat") { chatForm.classList.remove("hidden"); chatForm.classList.add("flex"); } else { confessionForm.classList.remove("hidden"); confessionForm.classList.add("flex"); } document.querySelectorAll(".selected-message").forEach(el => el.classList.remove("selected-message")); }
function updateSelectionBar() { const count = selectedMessages.size; selectionCount.textContent = `${count} selected`; if (count === 0 && isSelectionMode) exitSelectionMode(); }

// *** UPDATED MULTI-DELETE FUNCTION ***
async function handleMultiDelete() {
  const count = selectedMessages.size;
  if (count === 0) return;

  let allMine = true;
  selectedMessages.forEach(id => {
    const bubble = document.querySelector(`.message-bubble[data-id="${id}"]`);
    if (bubble && bubble.dataset.isMine !== "true") {
      allMine = false;
    }
  });

  const isAdmin = isCurrentUserAdmin;
  const canDeleteEveryone = isAdmin || allMine;

  confirmModalText.textContent = `Delete ${count} message${count > 1 ? 's' : ''}?`;
  confirmModalActionContainer.innerHTML = ''; 

  // Option 1: For Me (Hide)
  const btnForMe = document.createElement('button');
  btnForMe.className = "flex-1 px-4 py-2 rounded-lg font-bold text-sm border border-white text-white hover:bg-white hover:text-black";
  btnForMe.textContent = "FOR ME";
  btnForMe.onclick = async () => {
      closeConfirmModal();
      const batch = writeBatch(db);
      selectedMessages.forEach((docId) => {
          const docRef = doc(db, currentPage, docId);
          batch.update(docRef, { hiddenFor: arrayUnion(currentUserId) });
      });
      try { await batch.commit(); } 
      catch (e) { console.error(e); alert("Failed to hide messages."); }
      exitSelectionMode();
  };
  confirmModalActionContainer.appendChild(btnForMe);

  // Option 2: Everyone (Delete)
  if (canDeleteEveryone) {
      const btnEveryone = document.createElement('button');
      btnEveryone.className = "flex-1 px-4 py-2 rounded-lg font-bold text-sm bg-red-600 text-white hover:bg-red-500 border border-red-600";
      btnEveryone.textContent = "EVERYONE";
      btnEveryone.onclick = async () => {
          closeConfirmModal();
          const batch = writeBatch(db);
          selectedMessages.forEach((docId) => {
              const docRef = doc(db, currentPage, docId);
              batch.delete(docRef);
          });
          try { await batch.commit(); } 
          catch (e) { console.error(e); alert("Failed to delete messages."); }
          exitSelectionMode();
      };
      confirmModalActionContainer.appendChild(btnEveryone);
  }

  confirmModal.classList.add("is-open");
}

function scrollToBottom() { feedContainer.scrollTop = feedContainer.scrollHeight; userIsAtBottom = true; unreadMessages = 0; updateScrollButton(); }

function showPage(page) {
  currentPage = page;
  if (isSelectionMode) exitSelectionMode();
  cancelReplyMode();
  unsubscribeConfessions(); unsubscribeChat(); unsubscribeTypingStatus();
  typingIndicator.innerHTML = "&nbsp;";
  unreadMessages = 0; newMsgCount.classList.add("hidden");
  scrollToBottomBtn.classList.add("hidden"); scrollToBottomBtn.style.display = "";
  
  listenForPinnedMessages(); 

  if (page === "confessions") {
    navConfessions.classList.add("active"); navChat.classList.remove("active");
    confessionForm.classList.add("flex"); confessionForm.classList.remove("hidden");
    chatForm.classList.add("hidden"); chatForm.classList.remove("flex");
    typingIndicator.classList.add("hidden");
    listenForConfessions();
  } else {
    navChat.classList.add("active"); navConfessions.classList.remove("active");
    chatForm.classList.add("flex"); chatForm.classList.remove("hidden");
    confessionForm.classList.add("hidden"); confessionForm.classList.remove("flex");
    typingIndicator.classList.remove("hidden");
    listenForChat(); listenForTyping();
  }
}

let lastConfessionDocs = [];
let lastChatDocs = [];

function listenForConfessions(isRerender = false) {
  if (isRerender) { renderFeed(lastConfessionDocs, "confessions", null, true); return; }
  unsubscribeChat();
  feedContainer.innerHTML = '<div id="loading" class="text-center p-4">LOADING CONFESSIONS...</div>';
  let isFirstSnapshot = true; 
  unsubscribeConfessions = onSnapshot(query(confessionsCollection, orderBy("timestamp", "asc")), (snapshot) => {
      lastConfessionDocs = snapshot.docs;
      renderFeed(lastConfessionDocs, "confessions", snapshot, false, isFirstSnapshot);
      isFirstSnapshot = false; 
  }, (error) => { 
    // SECURITY: Use textContent for error messages to prevent injection
    const errorDiv = document.createElement("div");
    errorDiv.className = "text-center p-4 text-red-500";
    errorDiv.textContent = "Access Denied: " + error.message;
    feedContainer.innerHTML = "";
    feedContainer.appendChild(errorDiv);
  });
}

function listenForChat(isRerender = false) {
  if (isRerender) { renderFeed(lastChatDocs, "chat", null, true); return; }
  unsubscribeConfessions();
  feedContainer.innerHTML = '<div id="loading" class="text-center p-4">LOADING CHAT...</div>';
  let isFirstSnapshot = true; 
  unsubscribeChat = onSnapshot(query(chatCollection, orderBy("timestamp", "asc")), (snapshot) => {
      lastChatDocs = snapshot.docs;
      renderFeed(lastChatDocs, "chat", snapshot, false, isFirstSnapshot);
      isFirstSnapshot = false; 
  }, (error) => { 
    // SECURITY: Use textContent for error messages to prevent injection
    const errorDiv = document.createElement("div");
    errorDiv.className = "text-center p-4 text-red-500";
    errorDiv.textContent = "Access Denied: " + error.message;
    feedContainer.innerHTML = "";
    feedContainer.appendChild(errorDiv);
  });
}

function listenForTyping() {
  unsubscribeTypingStatus = onSnapshot(typingStatusCollection, (snapshot) => {
    const now = Date.now();
    const typingUsers = [];
    snapshot.docs.forEach((docSnap) => {
      if (docSnap.data().isTyping && docSnap.id !== currentUserId && now - docSnap.data().timestamp < 5000) { typingUsers.push(userProfiles[docSnap.id]?.username || "Someone"); }
    });
    if (typingUsers.length === 0) typingIndicator.innerHTML = "&nbsp;";
    else typingIndicator.textContent = typingUsers.length === 1 ? `${typingUsers[0]} is typing...` : "Several users are typing...";
  });
}

async function updateTypingStatus(isTyping) {
  if (!db || !currentUserId) return;
  if (typingTimeout) { clearTimeout(typingTimeout); typingTimeout = null; }
  try {
      const typingDocRef = doc(db, "typingStatus", currentUserId);
      await setDoc(typingDocRef, { isTyping: isTyping, timestamp: Date.now() });
      if (isTyping) typingTimeout = setTimeout(() => { updateTypingStatus(false); }, 3000);
  } catch(e) {}
}

function getDateHeader(date) {
  const today = new Date(); const yesterday = new Date(today); yesterday.setDate(yesterday.getDate() - 1);
  if (date.toDateString() === today.toDateString()) return "Today";
  if (date.toDateString() === yesterday.toDateString()) return "Yesterday";
  return date.toLocaleDateString([], { day: '2-digit', month: '2-digit', year: 'numeric' });
}

function formatMessageTime(date) {
  const diff = (new Date()) - date; const minutes = Math.floor(Math.floor(diff / 1000) / 60);
  if (minutes < 5) return Math.floor(diff/1000) < 60 ? "Just now" : `${minutes} mins ago`;
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });
}

function renderFeed(docs, type, snapshot, isRerender, isFirstSnapshot = false) {
  if (!isRerender && snapshot) {
      snapshot.docChanges().forEach((change) => {
          if (change.type === "added") {
              const data = change.doc.data();
              const msgTime = data.timestamp ? data.timestamp.toMillis() : 0;
              const isNewMessage = msgTime > appStartTime;
              if (isNewMessage && (document.visibilityState === "hidden" || currentPage !== type) && data.userId !== currentUserId && (!data.hiddenFor || !data.hiddenFor.includes(currentUserId))) {
                  showNotification(type === "chat" ? "New Chat" : "New Confession", data.text || "New message");
              }
          }
      });
  }

  const prevScrollTop = feedContainer.scrollTop;
  const wasAtBottom = userIsAtBottom;
  feedContainer.innerHTML = "";
  
  if (docs.length === 0) {
    const loadingEl = document.createElement("div"); loadingEl.id = "loading"; loadingEl.className = "text-center p-4"; loadingEl.textContent = `NO ${type.toUpperCase()} YET. BE THE FIRST!`; feedContainer.appendChild(loadingEl); return;
  }

  let lastUserId = null; let lastDateString = null; 
  const isAdmin = isCurrentUserAdmin;

  docs.forEach((docInstance) => {
    const data = docInstance.data();
    if (data.hiddenFor && data.hiddenFor.includes(currentUserId)) return;

    const text = data.text || "...";
    let messageDateObj = data.timestamp ? data.timestamp.toDate() : new Date();
    const messageDateStr = messageDateObj.toDateString(); 

    if (lastDateString !== messageDateStr) {
        const sepDiv = document.createElement('div'); sepDiv.className = 'date-separator'; sepDiv.innerHTML = `<span>${getDateHeader(messageDateObj)}</span>`; feedContainer.appendChild(sepDiv); lastDateString = messageDateStr; lastUserId = null; 
    }

    const docUserId = data.userId; const profile = userProfiles[docUserId] || {}; const username = profile.username || "Anonymous"; const photoURL = profile.profilePhotoURL || `https://placehold.co/32x32/000000/ffffff?text=${(username[0]||"?").toUpperCase()}`;
    const isMine = currentUserId && docUserId === currentUserId; const isConsecutive = docUserId && docUserId === lastUserId; lastUserId = docUserId; const userColor = getUserColor(docUserId);

    const alignWrapper = document.createElement("div"); alignWrapper.className = `flex w-full ${isMine ? "justify-end" : "justify-start"}`;
    const row = document.createElement("div"); row.className = "message-wrapper"; 
    const bubble = document.createElement("div"); bubble.className = `message-bubble rounded-lg max-w-xs sm:max-w-md md:max-w-lg ${isMine ? "my-message" : ""} ${isConsecutive ? "mt-0.5" : "mt-6"}`;
    if (data.isPinned) { bubble.classList.add("border-l-4"); bubble.style.borderLeftColor = "#fbbf24"; }
    bubble.dataset.id = docInstance.id; bubble.dataset.text = text; bubble.dataset.isMine = isMine; bubble.dataset.userId = docUserId; bubble.dataset.username = username; bubble.dataset.isPinned = data.isPinned || false; bubble.dataset.timestamp = data.timestamp ? data.timestamp.toMillis() : Date.now();
    if (!isMine) { bubble.style.borderLeft = `3px solid ${userColor}`; bubble.style.background = `linear-gradient(90deg, ${userColor}10, transparent)`; }
    if (isSelectionMode && selectedMessages.has(docInstance.id)) bubble.classList.add("selected-message");
    bubble.addEventListener('click', (e) => { if (isSelectionMode) { e.preventDefault(); e.stopPropagation(); handleMessageClick(bubble); } });
    const kebabBtn = document.createElement("button"); kebabBtn.className = "kebab-btn"; kebabBtn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" fill="currentColor" viewBox="0 0 16 16"><path d="M9.5 13a1.5 1.5 0 1 1-3 0 1.5 1.5 0 0 1 3 0zm0-5a1.5 1.5 0 1 1-3 0 1.5 1.5 0 0 1 3 0zm0-5a1.5 1.5 0 1 1-3 0 1.5 1.5 0 0 1 3 0z"/></svg>`;
    kebabBtn.addEventListener("click", (e) => showDropdownMenu(e, bubble.dataset)); bubble.appendChild(kebabBtn);

    if (!isConsecutive) {
      const headerElement = document.createElement("div"); headerElement.className = `flex items-center gap-1.5 mb-1 ${isMine ? "justify-end" : "justify-start"}`;
      const imgElement = document.createElement("img"); imgElement.src = photoURL; imgElement.className = `chat-pfp ${isMine ? "order-2" : "order-1"}`; if (!isMine) imgElement.style.borderColor = userColor;
      const usernameElement = document.createElement("div"); usernameElement.className = `font-bold text-sm opacity-90 ${isMine ? "order-1 text-right" : "order-2 text-left"}`; usernameElement.textContent = username; if (!isMine) usernameElement.style.color = userColor;
      headerElement.appendChild(imgElement); headerElement.appendChild(usernameElement); bubble.appendChild(headerElement);
    }

    if (data.replyTo) {
      const replyPreview = document.createElement("div"); replyPreview.className = "reply-preview";
      const replyAuthorEl = document.createElement("div"); replyAuthorEl.className = "reply-author"; replyAuthorEl.textContent = (userProfiles[data.replyTo.userId] || {}).username || "Anonymous"; if (!isMine) { replyPreview.style.borderLeftColor = userColor; replyAuthorEl.style.color = userColor; }
      const replyTextEl = document.createElement("div"); replyTextEl.className = "reply-text"; replyTextEl.textContent = data.replyTo.text;
      replyPreview.appendChild(replyAuthorEl); replyPreview.appendChild(replyTextEl);
      replyPreview.addEventListener("click", () => { const originalBubble = document.querySelector(`.message-bubble[data-id="${data.replyTo.messageId}"]`); if (originalBubble) { originalBubble.scrollIntoView({ behavior: "smooth", block: "center" }); originalBubble.style.backgroundColor = "rgba(255, 255, 255, 0.1)"; setTimeout(() => { originalBubble.style.backgroundColor = ""; }, 1000); } });
      bubble.appendChild(replyPreview);
    }

    const textElement = document.createElement("p"); textElement.className = "text-left"; 
    // SECURITY: Use textContent for user data to prevent XSS, add pin icon separately
    if (data.isPinned) { 
      const pinIcon = document.createElement("span");
      pinIcon.className = "text-amber-400 mr-1";
      pinIcon.title = "Pinned";
      pinIcon.textContent = "📌";
      textElement.appendChild(pinIcon);
      textElement.appendChild(document.createTextNode(text));
    } else { 
      textElement.textContent = text; 
    }
    bubble.appendChild(textElement);

    const footerDiv = document.createElement("div"); footerDiv.className = "bubble-footer"; footerDiv.style.justifyContent = isMine ? "flex-end" : "flex-start";
    const timeElement = document.createElement("span"); timeElement.className = "inner-timestamp"; timeElement.dataset.ts = data.timestamp ? data.timestamp.toMillis() : Date.now();
    timeElement.textContent = formatMessageTime(messageDateObj); if (data.edited) timeElement.textContent += " (edited)";
    footerDiv.appendChild(timeElement); bubble.appendChild(footerDiv);

    const replyBtn = document.createElement("button"); replyBtn.className = "side-action-btn"; replyBtn.innerHTML = "↩"; replyBtn.onclick = (e) => { e.stopPropagation(); startReplyMode(bubble.dataset); };
    const reactBtn = document.createElement("button"); reactBtn.className = "side-action-btn"; reactBtn.innerHTML = "♡";
    const picker = document.createElement("div"); picker.className = "reaction-picker hidden";
    const docReactions = data.reactions || {};
    Object.entries(REACTION_TYPES).forEach(([rtype, emoji]) => {
      const opt = document.createElement("span"); opt.className = "reaction-option"; opt.textContent = emoji;
      opt.onclick = (e) => { e.stopPropagation(); const hasReacted = (docReactions[rtype] || []).includes(currentUserId); toggleReaction(docInstance.id, type, rtype, hasReacted); picker.classList.add("hidden"); };
      picker.appendChild(opt);
    });
    reactBtn.onclick = (e) => { e.stopPropagation(); document.querySelectorAll(".reaction-picker").forEach(p => p.classList.add("hidden")); const rect = reactBtn.getBoundingClientRect(); picker.style.top = `${rect.top - 60}px`; picker.style.left = window.innerWidth < 640 ? "50%" : `${rect.left}px`; if (window.innerWidth < 640) picker.style.transform = "translateX(-50%)"; picker.classList.remove("hidden"); document.body.appendChild(picker); };

    const chipsContainer = document.createElement("div"); chipsContainer.className = "reaction-chips-container"; let hasChips = false;
    Object.keys(REACTION_TYPES).forEach(rtype => {
      const userIds = docReactions[rtype] || []; if (userIds.length > 0) { hasChips = true; const chip = document.createElement("div"); chip.className = "reaction-chip"; const hasReacted = userIds.includes(currentUserId); if (hasReacted) chip.classList.add("user-reacted"); chip.innerHTML = `${REACTION_TYPES[rtype]} ${userIds.length}`; chip.onclick = (e) => { e.stopPropagation(); toggleReaction(docInstance.id, type, rtype, hasReacted); }; chipsContainer.appendChild(chip); }
    });
    if (hasChips) { bubble.appendChild(chipsContainer); bubble.classList.add("has-reactions"); }

    if (isMine) { row.appendChild(reactBtn); row.appendChild(replyBtn); row.appendChild(bubble); } else { row.appendChild(bubble); row.appendChild(replyBtn); row.appendChild(reactBtn); }
    alignWrapper.appendChild(row); feedContainer.appendChild(alignWrapper);
  });

  const scrollAnchor = document.createElement("div"); scrollAnchor.id = "scrollAnchor"; scrollAnchor.style.height = "1px"; scrollAnchor.style.width = "100%"; feedContainer.appendChild(scrollAnchor); if (bottomObserver) { bottomObserver.disconnect(); bottomObserver.observe(scrollAnchor); }

  const hasNewMessages = snapshot && snapshot.docChanges().some(change => change.type === 'added');
  if (isFirstSnapshot && docs.length > 0) { feedContainer.style.scrollBehavior = "auto"; scrollToBottom(); setTimeout(() => { scrollToBottom(); feedContainer.style.scrollBehavior = "smooth"; }, 200); } else if (hasNewMessages) { if ((docs.length > 0 && docs[docs.length - 1].data().userId === currentUserId) || wasAtBottom) { scrollToBottom(); } else { unreadMessages++; updateScrollButton(); } } else { feedContainer.scrollTop = prevScrollTop; }
}

document.addEventListener("click", (e) => { if(!e.target.closest(".side-action-btn") && !e.target.closest(".reaction-picker")) { document.querySelectorAll(".reaction-picker").forEach(p => p.classList.add("hidden")); } if (!contextMenu.contains(e.target) && !e.target.closest(".kebab-btn")) hideDropdownMenu(); });
setInterval(() => { document.querySelectorAll('.inner-timestamp').forEach(el => { const ts = parseInt(el.dataset.ts); if (ts > 0) el.textContent = formatMessageTime(new Date(ts)) + (el.textContent.includes("edited") ? " (edited)" : ""); }); }, 60000);
scrollToBottomBtn.addEventListener("click", scrollToBottom);

async function postMessage(collectionRef, input) {
  if (currentUsername === "Anonymous") { alert("Set username first!"); openProfileModal(); return; }
  if (db && currentUserId) { 
    const banRef = doc(db, "banned_users", currentUserId); 
    const banSnap = await getDoc(banRef); 
    if (banSnap.exists()) { alert("You have been banned from posting."); input.value = ""; return; } 
  }
  const text = input.value.trim();
  if (text && db) { 
    try { 
      // Send message
      await addDoc(collectionRef, { 
        text: text, 
        timestamp: serverTimestamp(), 
        userId: currentUserId, 
        ...(replyToMessage && { replyTo: { messageId: replyToMessage.id, userId: replyToMessage.userId, text: replyToMessage.text } }) 
      }); 
      
      // SECURITY: Update lastMessageAt for rate limiting (required by security rules)
      await setDoc(doc(db, "users", currentUserId), { 
        lastMessageAt: serverTimestamp() 
      }, { merge: true });
      
      input.value = ""; 
      cancelReplyMode(); 
      updateTypingStatus(false); 
      scrollToBottom(); 
    } catch (e) { 
      console.error(e); 
      // Check if it's a rate limit error
      if (e.code === 'permission-denied') {
        alert("Please wait a moment before sending another message.");
      } else {
        alert("Send failed."); 
      }
    } 
  }
}

confessionForm.addEventListener("submit", (e) => { e.preventDefault(); postMessage(confessionsCollection, confessionInput); });
chatForm.addEventListener("submit", (e) => { e.preventDefault(); postMessage(chatCollection, chatInput); });
navConfessions.addEventListener("click", () => showPage("confessions")); navChat.addEventListener("click", () => showPage("chat"));
profileButton.addEventListener("click", openProfileModal); modalCloseButton.addEventListener("click", closeProfileModal); modalSaveButton.addEventListener("click", handleProfileSave); editModalCancelButton.addEventListener("click", closeEditModal); editModalSaveButton.addEventListener("click", saveEdit); confirmModalNoButton.addEventListener("click", closeConfirmModal);
menuEdit.addEventListener("click", () => { if (currentContextMenuData) showEditModal(currentContextMenuData.id, currentPage, currentContextMenuData.text); hideDropdownMenu(); });
menuDelete.addEventListener("click", () => { if (currentContextMenuData) { const isMine = currentContextMenuData.isMine === "true"; showConfirmModal(isMine ? "Delete this message?" : "Hide for me?", isMine, currentContextMenuData.id); } hideDropdownMenu(); });
menuSelect.addEventListener("click", () => { enterSelectionMode(); hideDropdownMenu(); });
selectionCancel.addEventListener("click", exitSelectionMode); selectionDelete.addEventListener("click", handleMultiDelete); cancelReply.addEventListener("click", cancelReplyMode);
confessionInput.addEventListener("keydown", (e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); postMessage(confessionsCollection, confessionInput); } else updateTypingStatus(true); });
chatInput.addEventListener("keydown", (e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); postMessage(chatCollection, chatInput); } else updateTypingStatus(true); });

function startReplyMode(messageData) { let repliedUserId = messageData.userId || (messageData.isMine === "true" ? currentUserId : null); replyToMessage = { id: messageData.id, userId: repliedUserId, text: messageData.text }; replyAuthor.textContent = `Replying to ${(userProfiles[repliedUserId] || {}).username || "Anonymous"}`; replyText.textContent = replyToMessage.text; replyBar.classList.add("show"); (currentPage === "chat" ? chatInput : confessionInput).focus(); }
function cancelReplyMode() { replyToMessage = null; replyBar.classList.remove("show"); }

initFirebase();