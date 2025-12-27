const functions = require("firebase-functions");
const admin = require("firebase-admin");

admin.initializeApp();
const db = admin.firestore();

// ═══════════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════════

const RATE_LIMITS = {
  NEW_USER_INTERVAL_MS: 5000,      // 5 seconds for new users
  TRUSTED_USER_INTERVAL_MS: 2000,  // 2 seconds for trusted users
  MAX_MESSAGES_PER_MINUTE: 12,     // Max messages per minute
  AUTO_BAN_THRESHOLD: 20,          // Auto-ban after this many messages/minute
};

const MESSAGE_MAX_LENGTH = 500;
const USERNAME_MAX_LENGTH = 30;

// ═══════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════════

/**
 * Validate message text
 */
function isValidMessageText(text) {
  if (typeof text !== 'string') return false;
  const trimmed = text.trim();
  if (trimmed.length === 0 || trimmed.length > MESSAGE_MAX_LENGTH) return false;
  
  // Check for control characters
  const controlCharRegex = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/;
  return !controlCharRegex.test(trimmed);
}

/**
 * Validate username
 */
function isValidUsername(username) {
  if (typeof username !== 'string') return false;
  const trimmed = username.trim();
  
  if (trimmed.length < 1 || trimmed.length > USERNAME_MAX_LENGTH) return false;
  
  // Check format
  if (!/^[a-zA-Z0-9_\- ]+$/.test(trimmed)) return false;
  
  // Check for leading/trailing spaces
  if (trimmed.startsWith(' ') || trimmed.endsWith(' ')) return false;
  
  // Check reserved words
  const reserved = [
    'anonymous', 'admin', 'moderator', 'system', 'konvo', 'mod',
    'support', 'staff', 'official', 'root', 'owner', 'bot', 'help'
  ];
  
  const lower = trimmed.toLowerCase();
  if (reserved.some(r => lower === r || lower.includes(r))) {
    return false;
  }
  
  return true;
}

/**
 * Check if user is banned
 */
async function isUserBanned(userId) {
  const banDoc = await db.doc(`banned_users/${userId}`).get();
  return banDoc.exists;
}

/**
 * Get user data
 */
async function getUserData(userId) {
  const userDoc = await db.doc(`users/${userId}`).get();
  return userDoc.exists ? userDoc.data() : null;
}

// ═══════════════════════════════════════════════════════════════════
// SEND MESSAGE FUNCTION
// ═══════════════════════════════════════════════════════════════════

exports.sendMessage = functions.https.onCall(async (data, context) => {
  // 1. Check authentication
  if (!context.auth) {
    throw new functions.https.HttpsError(
      "unauthenticated",
      "You must be signed in to send messages."
    );
  }

  const uid = context.auth.uid;
  const { text, collection: collectionName, replyTo } = data;

  // 2. Validate collection name
  if (!collectionName || !['chat', 'confessions'].includes(collectionName)) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "Invalid collection specified."
    );
  }

  // 3. Validate message text
  if (!text || typeof text !== 'string') {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "Message text is required."
    );
  }

  const trimmedText = text.trim();

  if (!isValidMessageText(trimmedText)) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      `Message must be 1-${MESSAGE_MAX_LENGTH} characters and contain no invalid characters.`
    );
  }

  // 4. Check if user is banned
  const banned = await isUserBanned(uid);
  if (banned) {
    throw new functions.https.HttpsError(
      "permission-denied",
      "You have been banned from sending messages."
    );
  }

  // 5. Get user profile
  const userData = await getUserData(uid);
  if (!userData || !userData.username) {
    throw new functions.https.HttpsError(
      "failed-precondition",
      "Please set a username before sending messages."
    );
  }

  const trustLevel = userData.trustLevel || 0;

  // 6. SERVER-SIDE RATE LIMITING (Transaction for atomicity)
  const now = admin.firestore.Timestamp.now();
  const nowMillis = now.toMillis();
  const rateLimitRef = db.doc(`rate_limits/${uid}`);

  try {
    await db.runTransaction(async (transaction) => {
      const rateLimitDoc = await transaction.get(rateLimitRef);
      const rateLimitData = rateLimitDoc.exists ? rateLimitDoc.data() : {
        messageTimestamps: [],
        lastMessageAt: null
      };

      // Clean old timestamps (older than 1 minute)
      const oneMinuteAgo = nowMillis - 60000;
      const recentTimestamps = (rateLimitData.messageTimestamps || [])
        .filter(ts => ts > oneMinuteAgo);

      // Check per-minute limit
      if (recentTimestamps.length >= RATE_LIMITS.MAX_MESSAGES_PER_MINUTE) {
        throw new Error("RATE_LIMIT_MINUTE");
      }

      // Check per-message interval based on trust level
      const lastMsg = rateLimitData.lastMessageAt;
      const minInterval = trustLevel >= 1
        ? RATE_LIMITS.TRUSTED_USER_INTERVAL_MS
        : RATE_LIMITS.NEW_USER_INTERVAL_MS;

      if (lastMsg && (nowMillis - lastMsg) < minInterval) {
        throw new Error("RATE_LIMIT_INTERVAL");
      }

      // Check for auto-ban threshold
      if (recentTimestamps.length >= RATE_LIMITS.AUTO_BAN_THRESHOLD - 1) {
        // This message would trigger auto-ban
        throw new Error("AUTO_BAN_TRIGGERED");
      }

      // Update rate limit record
      recentTimestamps.push(nowMillis);
      transaction.set(rateLimitRef, {
        messageTimestamps: recentTimestamps,
        lastMessageAt: nowMillis
      });

      // Create the message
      const messageRef = db.collection(collectionName).doc();
      const messageData = {
        text: trimmedText,
        timestamp: now,
        userId: uid
      };

      // Add reply data if present
      if (replyTo && typeof replyTo === 'object') {
        if (replyTo.messageId && replyTo.userId && replyTo.text !== undefined) {
          messageData.replyTo = {
            messageId: String(replyTo.messageId).substring(0, 100),
            userId: String(replyTo.userId).substring(0, 128),
            text: String(replyTo.text || '').substring(0, MESSAGE_MAX_LENGTH)
          };
        }
      }

      transaction.set(messageRef, messageData);

      // Update user stats
      transaction.update(db.doc(`users/${uid}`), {
        lastMessageAt: now,
        messageCount: admin.firestore.FieldValue.increment(1)
      });
    });

    return { success: true };

  } catch (error) {
    if (error.message === "RATE_LIMIT_MINUTE") {
      throw new functions.https.HttpsError(
        "resource-exhausted",
        "Too many messages. Please wait a minute before sending more."
      );
    }

    if (error.message === "RATE_LIMIT_INTERVAL") {
      const waitTime = trustLevel >= 1 ? 2 : 5;
      throw new functions.https.HttpsError(
        "resource-exhausted",
        `Please wait ${waitTime} seconds before sending another message.`
      );
    }

    if (error.message === "AUTO_BAN_TRIGGERED") {
      // Auto-ban the user for spamming
      try {
        await autoBanUser(uid, userData.username);
      } catch (banError) {
        console.error("Auto-ban failed:", banError);
      }

      throw new functions.https.HttpsError(
        "permission-denied",
        "You have been automatically banned for spamming."
      );
    }

    console.error("sendMessage error:", error);
    throw new functions.https.HttpsError(
      "internal",
      "Failed to send message. Please try again."
    );
  }
});

// ═══════════════════════════════════════════════════════════════════
// AUTO-BAN FUNCTION
// ═══════════════════════════════════════════════════════════════════

async function autoBanUser(userId, username) {
  const batch = db.batch();

  // Ban the user
  batch.set(db.doc(`banned_users/${userId}`), {
    bannedBy: "SYSTEM_AUTO_BAN",
    timestamp: admin.firestore.FieldValue.serverTimestamp(),
    reason: "Automatic ban: Exceeded message rate limit (spam detection)",
    username: username || 'Unknown'
  });

  // Update user document
  batch.update(db.doc(`users/${userId}`), {
    banned: true
  });

  // Get user's devices for device/IP bans
  const devicesSnapshot = await db.collection("user_devices")
    .where("userId", "==", userId)
    .get();

  const processedFingerprints = new Set();
  const processedIPs = new Set();

  devicesSnapshot.docs.forEach(deviceDoc => {
    const deviceData = deviceDoc.data();

    // Ban device fingerprint
    if (deviceData.fingerprint && !processedFingerprints.has(deviceData.fingerprint)) {
      processedFingerprints.add(deviceData.fingerprint);

      batch.set(db.doc(`banned_devices/${deviceData.fingerprint}`), {
        fingerprint: deviceData.fingerprint,
        userId: userId,
        username: username || 'Unknown',
        bannedBy: "SYSTEM_AUTO_BAN",
        timestamp: admin.firestore.FieldValue.serverTimestamp(),
        reason: "Automatic ban: Spam detection",
        userAgent: deviceData.userAgent || null,
        platform: deviceData.platform || null,
      });
    }

    // Ban IP hash
    if (deviceData.ipHash && !processedIPs.has(deviceData.ipHash)) {
      processedIPs.add(deviceData.ipHash);

      batch.set(db.doc(`banned_ips/${deviceData.ipHash}`), {
        ipHash: deviceData.ipHash,
        fingerprint: deviceData.fingerprint || null,
        userId: userId,
        username: username || 'Unknown',
        bannedBy: "SYSTEM_AUTO_BAN",
        timestamp: admin.firestore.FieldValue.serverTimestamp(),
        reason: "Automatic ban: Spam detection",
      });
    }
  });

  await batch.commit();

  console.log(`Auto-banned user ${userId} (${username}) for spam. Devices: ${processedFingerprints.size}, IPs: ${processedIPs.size}`);
}

// ═══════════════════════════════════════════════════════════════════
// SET USERNAME FUNCTION
// ═══════════════════════════════════════════════════════════════════

exports.setUsername = functions.https.onCall(async (data, context) => {
  // 1. Check authentication
  if (!context.auth) {
    throw new functions.https.HttpsError(
      "unauthenticated",
      "You must be signed in to set a username."
    );
  }

  const uid = context.auth.uid;
  const { username } = data;

  // 2. Validate username
  if (!username || typeof username !== 'string') {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "Username is required."
    );
  }

  const trimmedUsername = username.trim();

  if (!isValidUsername(trimmedUsername)) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "Invalid username. Use letters, numbers, spaces, underscores, and hyphens (1-30 characters). Reserved words are not allowed."
    );
  }

  // 3. Check if user is banned
  const banned = await isUserBanned(uid);
  if (banned) {
    throw new functions.https.HttpsError(
      "permission-denied",
      "You have been banned."
    );
  }

  // 4. Check username availability and set atomically
  try {
    await db.runTransaction(async (transaction) => {
      // Check if username is taken by another user
      const usersWithName = await db.collection("users")
        .where("username", "==", trimmedUsername)
        .get();

      let isTaken = false;
      usersWithName.forEach(doc => {
        if (doc.id !== uid) {
          isTaken = true;
        }
      });

      if (isTaken) {
        throw new Error("USERNAME_TAKEN");
      }

      // Check reserved_usernames collection
      const reservedRef = db.doc(`reserved_usernames/${trimmedUsername.toLowerCase()}`);
      const reservedDoc = await transaction.get(reservedRef);

      if (reservedDoc.exists && reservedDoc.data().userId !== uid) {
        throw new Error("USERNAME_TAKEN");
      }

      // Reserve the username
      transaction.set(reservedRef, {
        userId: uid,
        username: trimmedUsername,
        timestamp: admin.firestore.FieldValue.serverTimestamp()
      });

      // Generate profile photo URL
      const profilePhotoURL = `https://ui-avatars.com/api/?name=${encodeURIComponent(trimmedUsername)}&background=random&size=128`;

      // Get current user data to check if this is a new user
      const userRef = db.doc(`users/${uid}`);
      const userDoc = await transaction.get(userRef);

      if (userDoc.exists) {
        // Existing user - update
        const oldUsername = userDoc.data().username;

        // Delete old reserved username if different
        if (oldUsername && oldUsername.toLowerCase() !== trimmedUsername.toLowerCase()) {
          const oldReservedRef = db.doc(`reserved_usernames/${oldUsername.toLowerCase()}`);
          transaction.delete(oldReservedRef);
        }

        transaction.update(userRef, {
          username: trimmedUsername,
          profilePhotoURL: profilePhotoURL,
          lastMessageAt: admin.firestore.FieldValue.serverTimestamp()
        });
      } else {
        // New user - create
        transaction.set(userRef, {
          username: trimmedUsername,
          profilePhotoURL: profilePhotoURL,
          trustLevel: 0,
          messageCount: 0,
          createdAt: admin.firestore.FieldValue.serverTimestamp(),
          lastMessageAt: admin.firestore.FieldValue.serverTimestamp()
        });
      }
    });

    return { success: true };

  } catch (error) {
    if (error.message === "USERNAME_TAKEN") {
      throw new functions.https.HttpsError(
        "already-exists",
        "This username is already taken. Please choose another."
      );
    }

    console.error("setUsername error:", error);
    throw new functions.https.HttpsError(
      "internal",
      "Failed to set username. Please try again."
    );
  }
});

// ═══════════════════════════════════════════════════════════════════
// RATE LIMIT MONITOR (Background function)
// ═══════════════════════════════════════════════════════════════════

exports.monitorRateLimits = functions.firestore
  .document("rate_limits/{userId}")
  .onUpdate(async (change, context) => {
    const data = change.after.data();
    const userId = context.params.userId;
    const timestamps = data.messageTimestamps || [];

    // Count messages in last minute
    const oneMinuteAgo = Date.now() - 60000;
    const recentCount = timestamps.filter(ts => ts > oneMinuteAgo).length;

    // If exceeds threshold, auto-ban
    if (recentCount >= RATE_LIMITS.AUTO_BAN_THRESHOLD) {
      console.log(`Rate limit exceeded for user ${userId}: ${recentCount} messages/minute`);

      try {
        // Check if already banned
        const banDoc = await db.doc(`banned_users/${userId}`).get();
        if (banDoc.exists) {
          return null;
        }

        // Get username
        const userDoc = await db.doc(`users/${userId}`).get();
        const username = userDoc.exists ? userDoc.data().username : 'Unknown';

        await autoBanUser(userId, username);
      } catch (error) {
        console.error(`Failed to auto-ban user ${userId}:`, error);
      }
    }

    return null;
  });

// ═══════════════════════════════════════════════════════════════════
// CLEANUP OLD RATE LIMITS (Scheduled function - runs daily)
// ═══════════════════════════════════════════════════════════════════

exports.cleanupRateLimits = functions.pubsub
  .schedule('every 24 hours')
  .onRun(async (context) => {
    const cutoff = Date.now() - (24 * 60 * 60 * 1000); // 24 hours ago

    const rateLimitsSnapshot = await db.collection("rate_limits").get();

    const batch = db.batch();
    let deleteCount = 0;

    rateLimitsSnapshot.docs.forEach(doc => {
      const data = doc.data();
      const lastMessage = data.lastMessageAt || 0;

      // Delete if no activity in 24 hours
      if (lastMessage < cutoff) {
        batch.delete(doc.ref);
        deleteCount++;
      }
    });

    if (deleteCount > 0) {
      await batch.commit();
      console.log(`Cleaned up ${deleteCount} old rate limit records`);
    }

    return null;
  });

// ═══════════════════════════════════════════════════════════════════
// TRACK DEVICE COUNT (Trigger function)
// ═══════════════════════════════════════════════════════════════════

exports.trackDeviceCount = functions.firestore
  .document("user_devices/{deviceDocId}")
  .onCreate(async (snap, context) => {
    const data = snap.data();
    const userId = data.userId;

    if (!userId) return null;

    const countRef = db.doc(`user_device_counts/${userId}`);

    try {
      await countRef.set({
        count: admin.firestore.FieldValue.increment(1),
        lastUpdated: admin.firestore.FieldValue.serverTimestamp()
      }, { merge: true });
    } catch (error) {
      console.error("trackDeviceCount error:", error);
    }

    return null;
  });

exports.decrementDeviceCount = functions.firestore
  .document("user_devices/{deviceDocId}")
  .onDelete(async (snap, context) => {
    const data = snap.data();
    const userId = data.userId;

    if (!userId) return null;

    const countRef = db.doc(`user_device_counts/${userId}`);

    try {
      await countRef.set({
        count: admin.firestore.FieldValue.increment(-1),
        lastUpdated: admin.firestore.FieldValue.serverTimestamp()
      }, { merge: true });
    } catch (error) {
      console.error("decrementDeviceCount error:", error);
    }

    return null;
  });

console.log("Konvo Cloud Functions loaded successfully");