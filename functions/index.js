const { onDocumentCreated } = require("firebase-functions/v2/firestore");
const { onCall, HttpsError } = require("firebase-functions/v2/https");
const { initializeApp } = require("firebase-admin/app");
const { getFirestore, Timestamp, FieldValue } = require("firebase-admin/firestore");
const crypto = require('crypto');

initializeApp();
const db = getFirestore();

// ⚙️ SETTINGS
const SPAM_THRESHOLD = 7;
const TIME_WINDOW = 10;
const BAN_REASON = "Automated Ban: Message Flooding (Cloud Function)";
const MAX_BATCH_SIZE = 400;

// ⚙️ RATE LIMITS
const RATE_LIMITS = Object.freeze({
  MESSAGE_COOLDOWN_MS: 1000,
  REACTION_COOLDOWN_MS: 500,
  TYPING_COOLDOWN_MS: 300,
  DEVICE_REGISTRATION_COOLDOWN_MS: 3600000, // 1 hour
  PROFILE_UPDATE_COOLDOWN_MS: 5000,
  MAX_DEVICES_PER_USER: 5,
  MAX_MESSAGES_PER_MINUTE: 20,
  MAX_REACTIONS_PER_MINUTE: 30,
});

// ⚙️ RECAPTCHA SETTINGS
const RECAPTCHA_SECRET_KEY = process.env.RECAPTCHA_SECRET_KEY || '';
const RECAPTCHA_SCORE_THRESHOLD = 0.5;
const RECAPTCHA_ENABLED = !!RECAPTCHA_SECRET_KEY && RECAPTCHA_SECRET_KEY !== 'YOUR_RECAPTCHA_SECRET_KEY';

// ============================
// HELPER: Secure IP Hashing with HMAC
// ============================
const IP_HASH_SECRET = process.env.IP_HASH_SECRET || 'konvo_secure_salt_2024_' + crypto.randomBytes(16).toString('hex');

function hashIP(ip) {
  if (!ip || typeof ip !== 'string') return null;
  
  // Normalize IP
  const normalizedIP = ip.trim().toLowerCase();
  if (!normalizedIP) return null;
  
  return 'ip_' + crypto
    .createHmac('sha256', IP_HASH_SECRET)
    .update(normalizedIP)
    .digest('hex')
    .substring(0, 32);
}

// ============================
// HELPER: Extract IP from request
// ============================
function extractIPFromRequest(request) {
  if (!request || !request.rawRequest) return null;
  
  const headers = request.rawRequest.headers || {};
  
  // Check X-Forwarded-For first (standard proxy header)
  const forwardedFor = headers['x-forwarded-for'];
  if (forwardedFor) {
    // Take the first IP (original client)
    const firstIP = forwardedFor.split(',')[0].trim();
    if (isValidIP(firstIP)) return firstIP;
  }
  
  // Check other common headers
  const realIP = headers['x-real-ip'];
  if (realIP && isValidIP(realIP)) return realIP;
  
  // Fallback to connection IP
  const connectionIP = request.rawRequest.ip || request.rawRequest.connection?.remoteAddress;
  if (connectionIP && isValidIP(connectionIP)) return connectionIP;
  
  return null;
}

// ============================
// HELPER: Validate IP format
// ============================
function isValidIP(ip) {
  if (!ip || typeof ip !== 'string') return false;
  
  // IPv4 pattern
  const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipv4Pattern.test(ip)) {
    const parts = ip.split('.').map(Number);
    return parts.every(part => part >= 0 && part <= 255);
  }
  
  // IPv6 pattern (simplified)
  const ipv6Pattern = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
  return ipv6Pattern.test(ip);
}

// ============================
// HELPER: Validate text content
// ============================
function validateText(text, maxLength = 500) {
  if (typeof text !== 'string') {
    return { valid: false, error: 'Invalid text format' };
  }
  
  const trimmed = text.trim();
  
  if (trimmed.length === 0) {
    return { valid: false, error: 'Text cannot be empty' };
  }
  
  if (trimmed.length > maxLength) {
    return { valid: false, error: 'Text too long' };
  }
  
  // Check for control characters (except newlines and tabs)
  const controlCharRegex = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/;
  if (controlCharRegex.test(trimmed)) {
    return { valid: false, error: 'Text contains invalid characters' };
  }
  
  return { valid: true, text: trimmed };
}

// ============================
// HELPER: Sanitize string for logging (prevent log injection)
// ============================
function sanitizeForLog(str, maxLength = 100) {
  if (typeof str !== 'string') return '[non-string]';
  return str
    .substring(0, maxLength)
    .replace(/[\r\n\t]/g, ' ')
    .replace(/[^\x20-\x7E]/g, '?');
}

// ============================
// HELPER: Split operations into batches
// ============================
async function executeBatchedOperations(operations) {
  if (!operations || operations.length === 0) return 0;
  
  const batches = [];
  
  for (let i = 0; i < operations.length; i += MAX_BATCH_SIZE) {
    const batch = db.batch();
    const chunk = operations.slice(i, i + MAX_BATCH_SIZE);
    
    chunk.forEach(op => {
      if (op.type === 'set') {
        batch.set(op.ref, op.data, op.options || {});
      } else if (op.type === 'update') {
        batch.update(op.ref, op.data);
      } else if (op.type === 'delete') {
        batch.delete(op.ref);
      }
    });
    
    batches.push(batch.commit());
  }
  
  await Promise.all(batches);
  return batches.length;
}

// ============================
// HELPER: Get username from user document
// ============================
async function getUsernameById(userId) {
  if (!userId || typeof userId !== 'string') return 'Unknown';
  
  try {
    const userDoc = await db.collection("users").doc(userId).get();
    if (userDoc.exists) {
      const data = userDoc.data();
      return data?.username || 'Unknown';
    }
    return 'Unknown';
  } catch (error) {
    console.warn(`Failed to fetch username for ${sanitizeForLog(userId)}`);
    return 'Unknown';
  }
}

// ============================
// HELPER: Check if user is banned
// ============================
async function isUserBanned(userId) {
  if (!userId) return true;
  
  try {
    const banDoc = await db.collection("banned_users").doc(userId).get();
    return banDoc.exists;
  } catch (error) {
    console.error('Error checking ban status');
    return false;
  }
}

// ============================
// HELPER: Check if device is banned
// ============================
async function isDeviceBanned(fingerprint) {
  if (!fingerprint) return false;
  
  try {
    const banDoc = await db.collection("banned_devices").doc(fingerprint).get();
    return banDoc.exists;
  } catch (error) {
    return false;
  }
}

// ============================
// HELPER: Check if IP is banned
// ============================
async function isIPBanned(ipHash) {
  if (!ipHash) return false;
  
  try {
    const banDoc = await db.collection("banned_ips").doc(ipHash).get();
    return banDoc.exists;
  } catch (error) {
    return false;
  }
}

// ============================
// HELPER: Verify reCAPTCHA token
// ============================
async function verifyRecaptcha(token, expectedAction = null) {
  if (!RECAPTCHA_ENABLED) {
    console.log('reCAPTCHA is disabled, skipping verification');
    return { success: true, score: 1.0, skipped: true };
  }
  
  if (!token || typeof token !== 'string') {
    return { success: false, score: 0, error: 'No token provided' };
  }
  
  try {
    const response = await fetch('https://www.google.com/recaptcha/api/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `secret=${encodeURIComponent(RECAPTCHA_SECRET_KEY)}&response=${encodeURIComponent(token)}`
    });
    
    if (!response.ok) {
      return { success: false, score: 0, error: 'Verification request failed' };
    }
    
    const data = await response.json();
    
    if (!data.success) {
      return { success: false, score: 0, error: 'Token invalid' };
    }
    
    // Check action if provided (reCAPTCHA v3)
    if (expectedAction && data.action && data.action !== expectedAction) {
      return { success: false, score: data.score || 0, error: 'Action mismatch' };
    }
    
    // Check score threshold
    const score = data.score || 0;
    if (score < RECAPTCHA_SCORE_THRESHOLD) {
      return { success: false, score, error: 'Score too low' };
    }
    
    return { success: true, score };
  } catch (error) {
    console.error('reCAPTCHA verification error:', error.message);
    // Fail open in case of network issues (configurable)
    return { success: false, score: 0, error: 'Verification failed' };
  }
}

// ============================
// HELPER: Rate limit check
// ============================
async function checkRateLimit(userId, limitType, cooldownMs, maxCount = null, windowMs = null) {
  const rateLimitRef = db.collection("rate_limits").doc(`${userId}_${limitType}`);
  
  try {
    const result = await db.runTransaction(async (transaction) => {
      const doc = await transaction.get(rateLimitRef);
      const now = Timestamp.now();
      const nowMs = now.toMillis();
      
      if (!doc.exists) {
        // First action
        transaction.set(rateLimitRef, {
          lastAction: now,
          count: 1,
          windowStart: now
        });
        return { allowed: true, remaining: maxCount ? maxCount - 1 : null };
      }
      
      const data = doc.data();
      const lastActionMs = data.lastAction?.toMillis() || 0;
      const timeSinceLastAction = nowMs - lastActionMs;
      
      // Check cooldown
      if (timeSinceLastAction < cooldownMs) {
        const waitTime = Math.ceil((cooldownMs - timeSinceLastAction) / 1000);
        return { allowed: false, waitTime, reason: 'cooldown' };
      }
      
      // Check count within window if specified
      if (maxCount && windowMs) {
        const windowStartMs = data.windowStart?.toMillis() || 0;
        const timeSinceWindowStart = nowMs - windowStartMs;
        
        if (timeSinceWindowStart < windowMs) {
          // Still in window
          const count = (data.count || 0) + 1;
          if (count > maxCount) {
            return { allowed: false, reason: 'rate_limit', resetIn: Math.ceil((windowMs - timeSinceWindowStart) / 1000) };
          }
          transaction.update(rateLimitRef, {
            lastAction: now,
            count: count
          });
          return { allowed: true, remaining: maxCount - count };
        } else {
          // Window expired, reset
          transaction.set(rateLimitRef, {
            lastAction: now,
            count: 1,
            windowStart: now
          });
          return { allowed: true, remaining: maxCount - 1 };
        }
      }
      
      // Simple cooldown update
      transaction.update(rateLimitRef, {
        lastAction: now,
        count: FieldValue.increment(1)
      });
      
      return { allowed: true };
    });
    
    return result;
  } catch (error) {
    console.error('Rate limit check error:', error.message);
    // Fail closed for security
    return { allowed: false, reason: 'error' };
  }
}

// ============================
// SPAM DETECTION (Trigger-based)
// ============================
exports.detectSpamAndBan = onDocumentCreated(
  {
    document: "{collectionId}/{messageId}",
    region: "asia-south1"
  },
  async (event) => {
    const { collectionId, messageId } = event.params;

    if (collectionId !== "chat" && collectionId !== "confessions") return null;

    const snapshot = event.data;
    if (!snapshot) return null;

    const msgData = snapshot.data();
    const userId = msgData?.userId;

    if (!userId || typeof userId !== 'string') return null;

    const now = Timestamp.now();
    const windowStart = new Date(now.toMillis() - (TIME_WINDOW * 1000));

    try {
      // Check if user is already banned (idempotency)
      const banRef = db.collection("banned_users").doc(userId);
      const existingBan = await banRef.get();
      
      if (existingBan.exists) {
        console.log(`User ${sanitizeForLog(userId)} already banned, deleting spam message`);
        try {
          await snapshot.ref.delete();
        } catch (delErr) {
          console.warn('Failed to delete message from banned user');
        }
        return null;
      }

      // Count recent messages
      const recentMsgs = await db.collection(collectionId)
        .where("userId", "==", userId)
        .where("timestamp", ">", windowStart)
        .get();

      if (recentMsgs.size >= SPAM_THRESHOLD) {
        console.log(`Banning User ${sanitizeForLog(userId)}: ${recentMsgs.size} msgs in ${TIME_WINDOW}s`);

        // Fetch actual username
        const username = await getUsernameById(userId);

        // Use transaction for atomic ban
        const banSuccessful = await db.runTransaction(async (transaction) => {
          const banDoc = await transaction.get(banRef);
          
          if (banDoc.exists) {
            console.log(`Race condition avoided: User already banned`);
            return false;
          }
          
          // Set ban in transaction
          transaction.set(banRef, {
            bannedBy: "SYSTEM_CLOUD_FUNCTION",
            reason: BAN_REASON,
            timestamp: now,
            username: username.substring(0, 30),
            messageCount: recentMsgs.size,
            triggeredBy: messageId
          });
          
          // Update user document
          const userRef = db.collection("users").doc(userId);
          transaction.set(userRef, { banned: true }, { merge: true });
          
          return true;
        });

        if (!banSuccessful) {
          return null;
        }

        // Collect all ban operations
        const operations = [];

        // Get all devices for this user
        const devices = await db.collection("user_devices")
          .where("userId", "==", userId)
          .get();

        const processedFingerprints = new Set();
        const processedIPs = new Set();

        devices.forEach((doc) => {
          const data = doc.data();
          
          // Ban device fingerprint
          if (data.fingerprint && !processedFingerprints.has(data.fingerprint)) {
            processedFingerprints.add(data.fingerprint);
            operations.push({
              type: 'set',
              ref: db.collection("banned_devices").doc(data.fingerprint),
              data: {
                fingerprint: data.fingerprint,
                userId,
                username: username.substring(0, 30),
                bannedBy: "SYSTEM_CLOUD_FUNCTION",
                reason: BAN_REASON,
                timestamp: now,
                userAgent: data.userAgent?.substring(0, 500) || null,
                platform: data.platform?.substring(0, 50) || null
              }
            });
          }
          
          // Ban IP hash
          if (data.ipHash && !processedIPs.has(data.ipHash)) {
            processedIPs.add(data.ipHash);
            operations.push({
              type: 'set',
              ref: db.collection("banned_ips").doc(data.ipHash),
              data: {
                ipHash: data.ipHash,
                userId,
                username: username.substring(0, 30),
                bannedBy: "SYSTEM_CLOUD_FUNCTION",
                reason: BAN_REASON,
                timestamp: now
              }
            });
          }
        });

        // Delete all recent spam messages
        recentMsgs.forEach((doc) => {
          operations.push({
            type: 'delete',
            ref: doc.ref
          });
        });

        // Execute all operations in batches
        const batchCount = await executeBatchedOperations(operations);
        
        console.log(`User ${sanitizeForLog(userId)} (${sanitizeForLog(username)}) terminated.`);
        console.log(`Banned ${processedFingerprints.size} device(s), ${processedIPs.size} IP(s), deleted ${recentMsgs.size} message(s)`);
      }
    } catch (error) {
      console.error("Error in spam detection:", error.message);
    }

    return null;
  }
);

// ============================
// SEND MESSAGE (Server-side)
// ============================
exports.sendMessage = onCall(
  {
    region: "asia-south1",
    enforceAppCheck: false // Enable when App Check is configured
  },
  async (request) => {
    // Verify authentication
    if (!request.auth || !request.auth.uid) {
      throw new HttpsError('unauthenticated', 'Authentication required.');
    }
    
    const userId = request.auth.uid;
    const { text, collection, replyTo, recaptchaToken, fingerprint } = request.data || {};
    
    // Validate collection
    if (!['chat', 'confessions'].includes(collection)) {
      throw new HttpsError('invalid-argument', 'Invalid request.');
    }
    
    // Validate text
    const textValidation = validateText(text, 500);
    if (!textValidation.valid) {
      throw new HttpsError('invalid-argument', 'Invalid message.');
    }
    
    try {
      // Check ban status
      if (await isUserBanned(userId)) {
        throw new HttpsError('permission-denied', 'Access denied.');
      }
      
      // Extract and check IP
      const clientIP = extractIPFromRequest(request);
      const ipHash = hashIP(clientIP);
      
      if (ipHash && await isIPBanned(ipHash)) {
        throw new HttpsError('permission-denied', 'Access denied.');
      }
      
      // Check device fingerprint if provided
      if (fingerprint && typeof fingerprint === 'string') {
        if (await isDeviceBanned(fingerprint)) {
          throw new HttpsError('permission-denied', 'Access denied.');
        }
      }
      
      // Verify reCAPTCHA
      const recaptchaResult = await verifyRecaptcha(recaptchaToken, 'send_message');
      if (!recaptchaResult.success && !recaptchaResult.skipped) {
        console.warn(`reCAPTCHA failed for user ${sanitizeForLog(userId)}: ${recaptchaResult.error}`);
        throw new HttpsError('permission-denied', 'Verification failed.');
      }
      
      // Check rate limit
      const rateCheck = await checkRateLimit(
        userId, 
        'message', 
        RATE_LIMITS.MESSAGE_COOLDOWN_MS,
        RATE_LIMITS.MAX_MESSAGES_PER_MINUTE,
        60000
      );
      
      if (!rateCheck.allowed) {
        if (rateCheck.reason === 'cooldown') {
          throw new HttpsError('resource-exhausted', 'Please wait before sending.');
        }
        throw new HttpsError('resource-exhausted', 'Too many messages. Please slow down.');
      }
      
      // Get user profile
      const userDoc = await db.collection("users").doc(userId).get();
      if (!userDoc.exists) {
        throw new HttpsError('failed-precondition', 'Please set up your profile first.');
      }
      
      const userData = userDoc.data();
      if (!userData.username || userData.username.length < 1) {
        throw new HttpsError('failed-precondition', 'Please set a username first.');
      }
      
      // Prepare message data
      const now = Timestamp.now();
      const messageData = {
        text: textValidation.text,
        timestamp: now,
        userId: userId
      };
      
      // Validate and add reply data if present
      if (replyTo && typeof replyTo === 'object') {
        if (replyTo.messageId && replyTo.userId && replyTo.text) {
          messageData.replyTo = {
            messageId: String(replyTo.messageId).substring(0, 100),
            userId: String(replyTo.userId).substring(0, 128),
            text: String(replyTo.text).substring(0, 200)
          };
        }
      }
      
      // Create message with transaction
      const messageRef = db.collection(collection).doc();
      
      await db.runTransaction(async (transaction) => {
        transaction.set(messageRef, messageData);
        
        // Update user's message stats (server-side only)
        transaction.update(db.collection("users").doc(userId), {
          lastMessageAt: now,
          messageCount: FieldValue.increment(1)
        });
        
        // Update device IP if fingerprint provided
        if (fingerprint && ipHash) {
          const deviceDocId = `${userId}_${fingerprint}`;
          const deviceRef = db.collection("user_devices").doc(deviceDocId);
          const deviceDoc = await transaction.get(deviceRef);
          
          if (deviceDoc.exists) {
            transaction.update(deviceRef, {
              lastSeen: now,
              ipHash: ipHash
            });
          }
        }
      });
      
      return {
        success: true,
        messageId: messageRef.id
      };
      
    } catch (error) {
      if (error instanceof HttpsError) {
        throw error;
      }
      console.error('Error sending message:', error.message);
      throw new HttpsError('internal', 'Failed to send message.');
    }
  }
);

// ============================
// REGISTER DEVICE (Server-side IP)
// ============================
exports.registerDevice = onCall(
  {
    region: "asia-south1"
  },
  async (request) => {
    if (!request.auth || !request.auth.uid) {
      throw new HttpsError('unauthenticated', 'Authentication required.');
    }
    
    const userId = request.auth.uid;
    const { fingerprint, userAgent, language, timezone, screenResolution, platform } = request.data || {};
    
    // Validate fingerprint
    if (!fingerprint || typeof fingerprint !== 'string') {
      throw new HttpsError('invalid-argument', 'Invalid request.');
    }
    
    const sanitizedFingerprint = fingerprint.substring(0, 100).replace(/[^a-zA-Z0-9_-]/g, '');
    if (sanitizedFingerprint.length < 8) {
      throw new HttpsError('invalid-argument', 'Invalid request.');
    }
    
    try {
      // Check ban status
      if (await isUserBanned(userId)) {
        throw new HttpsError('permission-denied', 'Access denied.');
      }
      
      // Check device fingerprint ban
      if (await isDeviceBanned(sanitizedFingerprint)) {
        throw new HttpsError('permission-denied', 'Device not allowed.');
      }
      
      // Extract server-side IP
      const clientIP = extractIPFromRequest(request);
      const ipHash = hashIP(clientIP);
      
      // Check IP ban
      if (ipHash && await isIPBanned(ipHash)) {
        throw new HttpsError('permission-denied', 'Access denied.');
      }
      
      // Check rate limit for device registration
      const rateCheck = await checkRateLimit(
        userId,
        'device_reg',
        RATE_LIMITS.DEVICE_REGISTRATION_COOLDOWN_MS
      );
      
      const deviceDocId = `${userId}_${sanitizedFingerprint}`;
      const deviceRef = db.collection("user_devices").doc(deviceDocId);
      const now = Timestamp.now();
      
      const existingDevice = await deviceRef.get();
      
      if (existingDevice.exists) {
        // Update existing device
        await deviceRef.update({
          lastSeen: now,
          ipHash: ipHash,
          userAgent: userAgent ? String(userAgent).substring(0, 500) : null
        });
        
        return { success: true, isNew: false };
      }
      
      // For new device registration, check rate limit
      if (!rateCheck.allowed) {
        throw new HttpsError('resource-exhausted', 'Please wait before registering another device.');
      }
      
      // Check user profile exists
      const userDoc = await db.collection("users").doc(userId).get();
      if (!userDoc.exists) {
        throw new HttpsError('failed-precondition', 'Please create your profile first.');
      }
      
      const userData = userDoc.data();
      
      // Check device count
      const deviceCount = userData.deviceCount || 0;
      if (deviceCount >= RATE_LIMITS.MAX_DEVICES_PER_USER) {
        throw new HttpsError('resource-exhausted', 'Maximum devices reached.');
      }
      
      // Create new device using transaction
      await db.runTransaction(async (transaction) => {
        transaction.set(deviceRef, {
          userId: userId,
          fingerprint: sanitizedFingerprint,
          ipHash: ipHash,
          userAgent: userAgent ? String(userAgent).substring(0, 500) : null,
          language: language ? String(language).substring(0, 20) : null,
          timezone: timezone ? String(timezone).substring(0, 100) : null,
          screenResolution: screenResolution ? String(screenResolution).substring(0, 20) : null,
          platform: platform ? String(platform).substring(0, 50) : null,
          firstSeen: now,
          lastSeen: now
        });
        
        transaction.update(db.collection("users").doc(userId), {
          deviceCount: FieldValue.increment(1),
          lastDeviceReg: now
        });
      });
      
      return { success: true, isNew: true };
      
    } catch (error) {
      if (error instanceof HttpsError) {
        throw error;
      }
      console.error('Error registering device:', error.message);
      throw new HttpsError('internal', 'Failed to register device.');
    }
  }
);

// ============================
// UPDATE REACTION (Server-side rate limiting)
// ============================
exports.updateReaction = onCall(
  {
    region: "asia-south1"
  },
  async (request) => {
    if (!request.auth || !request.auth.uid) {
      throw new HttpsError('unauthenticated', 'Authentication required.');
    }
    
    const userId = request.auth.uid;
    const { messageId, collection, reactionType, action } = request.data || {};
    
    const validReactions = ['thumbsup', 'laugh', 'surprised', 'heart', 'skull'];
    
    if (!['chat', 'confessions'].includes(collection)) {
      throw new HttpsError('invalid-argument', 'Invalid request.');
    }
    
    if (!validReactions.includes(reactionType)) {
      throw new HttpsError('invalid-argument', 'Invalid request.');
    }
    
    if (!['add', 'remove'].includes(action)) {
      throw new HttpsError('invalid-argument', 'Invalid request.');
    }
    
    if (!messageId || typeof messageId !== 'string') {
      throw new HttpsError('invalid-argument', 'Invalid request.');
    }
    
    try {
      // Check ban status
      if (await isUserBanned(userId)) {
        throw new HttpsError('permission-denied', 'Access denied.');
      }
      
      // Check rate limit
      const rateCheck = await checkRateLimit(
        userId,
        'reaction',
        RATE_LIMITS.REACTION_COOLDOWN_MS,
        RATE_LIMITS.MAX_REACTIONS_PER_MINUTE,
        60000
      );
      
      if (!rateCheck.allowed) {
        throw new HttpsError('resource-exhausted', 'Please wait before adding another reaction.');
      }
      
      // Update reaction
      const messageRef = db.collection(collection).doc(messageId);
      
      await db.runTransaction(async (transaction) => {
        const messageDoc = await transaction.get(messageRef);
        
        if (!messageDoc.exists) {
          throw new HttpsError('not-found', 'Message not found.');
        }
        
        const reactions = messageDoc.data().reactions || {};
        const reactionList = reactions[reactionType] || [];
        const hasReacted = reactionList.includes(userId);
        
        if (action === 'add' && !hasReacted) {
          transaction.update(messageRef, {
            [`reactions.${reactionType}`]: FieldValue.arrayUnion(userId)
          });
        } else if (action === 'remove' && hasReacted) {
          transaction.update(messageRef, {
            [`reactions.${reactionType}`]: FieldValue.arrayRemove(userId)
          });
        }
      });
      
      return { success: true };
      
    } catch (error) {
      if (error instanceof HttpsError) {
        throw error;
      }
      console.error('Error updating reaction:', error.message);
      throw new HttpsError('internal', 'Failed to update reaction.');
    }
  }
);

// ============================
// UPDATE TYPING STATUS (Server-side rate limiting)
// ============================
exports.updateTypingStatus = onCall(
  {
    region: "asia-south1"
  },
  async (request) => {
    if (!request.auth || !request.auth.uid) {
      throw new HttpsError('unauthenticated', 'Authentication required.');
    }
    
    const userId = request.auth.uid;
    const { isTyping } = request.data || {};
    
    if (typeof isTyping !== 'boolean') {
      throw new HttpsError('invalid-argument', 'Invalid request.');
    }
    
    try {
      // Check ban status (quick check, no detailed error)
      if (await isUserBanned(userId)) {
        throw new HttpsError('permission-denied', 'Access denied.');
      }
      
      // Rate limit check (less strict for typing)
      const rateCheck = await checkRateLimit(
        userId,
        'typing',
        RATE_LIMITS.TYPING_COOLDOWN_MS
      );
      
      if (!rateCheck.allowed) {
        // Silently ignore too-frequent typing updates
        return { success: true, throttled: true };
      }
      
      const typingRef = db.collection("typingStatus").doc(userId);
      
      await typingRef.set({
        isTyping: isTyping,
        timestamp: Date.now()
      });
      
      return { success: true };
      
    } catch (error) {
      if (error instanceof HttpsError) {
        throw error;
      }
      // Don't expose typing errors
      return { success: false };
    }
  }
);

// ============================
// UPDATE PROFILE (Server-side validation)
// ============================
exports.updateProfile = onCall(
  {
    region: "asia-south1"
  },
  async (request) => {
    if (!request.auth || !request.auth.uid) {
      throw new HttpsError('unauthenticated', 'Authentication required.');
    }
    
    const userId = request.auth.uid;
    const { username, recaptchaToken } = request.data || {};
    
    // Validate username
    if (!username || typeof username !== 'string') {
      throw new HttpsError('invalid-argument', 'Invalid username.');
    }
    
    const trimmedUsername = username.trim();
    
    if (trimmedUsername.length < 1 || trimmedUsername.length > 30) {
      throw new HttpsError('invalid-argument', 'Username must be 1-30 characters.');
    }
    
    // Check for valid characters
    const usernameRegex = /^[a-zA-Z0-9_\- ]+$/;
    if (!usernameRegex.test(trimmedUsername)) {
      throw new HttpsError('invalid-argument', 'Invalid characters in username.');
    }
    
    // Check reserved names
    const reserved = ['anonymous', 'admin', 'moderator', 'system', 'konvo', 'mod', 'support', 'staff', 'official', 'root', 'owner', 'bot', 'help'];
    const lowerUsername = trimmedUsername.toLowerCase();
    
    for (const word of reserved) {
      if (lowerUsername === word || lowerUsername.includes(word)) {
        throw new HttpsError('invalid-argument', 'This username is not allowed.');
      }
    }
    
    try {
      // Check ban status
      if (await isUserBanned(userId)) {
        throw new HttpsError('permission-denied', 'Access denied.');
      }
      
      // Verify reCAPTCHA for profile updates
      const recaptchaResult = await verifyRecaptcha(recaptchaToken, 'update_profile');
      if (!recaptchaResult.success && !recaptchaResult.skipped) {
        throw new HttpsError('permission-denied', 'Verification failed.');
      }
      
      // Rate limit
      const rateCheck = await checkRateLimit(
        userId,
        'profile',
        RATE_LIMITS.PROFILE_UPDATE_COOLDOWN_MS
      );
      
      if (!rateCheck.allowed) {
        throw new HttpsError('resource-exhausted', 'Please wait before updating again.');
      }
      
      // Check if username is taken
      const usernameQuery = await db.collection("users")
        .where("username", "==", trimmedUsername)
        .get();
      
      for (const doc of usernameQuery.docs) {
        if (doc.id !== userId) {
          throw new HttpsError('already-exists', 'Username is already taken.');
        }
      }
      
      // Generate profile photo URL
      const profilePhotoURL = `https://ui-avatars.com/api/?name=${encodeURIComponent(trimmedUsername)}&background=random&size=128`;
      
      // Update profile
      const userRef = db.collection("users").doc(userId);
      const now = Timestamp.now();
      
      await userRef.set({
        username: trimmedUsername,
        profilePhotoURL: profilePhotoURL,
        updatedAt: now
      }, { merge: true });
      
      return {
        success: true,
        username: trimmedUsername,
        profilePhotoURL: profilePhotoURL
      };
      
    } catch (error) {
      if (error instanceof HttpsError) {
        throw error;
      }
      console.error('Error updating profile:', error.message);
      throw new HttpsError('internal', 'Failed to update profile.');
    }
  }
);

// ============================
// CHECK BAN STATUS (For client initialization)
// ============================
exports.checkBanStatus = onCall(
  {
    region: "asia-south1"
  },
  async (request) => {
    if (!request.auth || !request.auth.uid) {
      throw new HttpsError('unauthenticated', 'Authentication required.');
    }
    
    const userId = request.auth.uid;
    const { fingerprint } = request.data || {};
    
    try {
      // Check user ban
      const userBanned = await isUserBanned(userId);
      if (userBanned) {
        return { banned: true, type: 'user' };
      }
      
      // Check device ban
      if (fingerprint && typeof fingerprint === 'string') {
        const deviceBanned = await isDeviceBanned(fingerprint);
        if (deviceBanned) {
          return { banned: true, type: 'device' };
        }
      }
      
      // Check IP ban
      const clientIP = extractIPFromRequest(request);
      const ipHash = hashIP(clientIP);
      
      if (ipHash) {
        const ipBanned = await isIPBanned(ipHash);
        if (ipBanned) {
          return { banned: true, type: 'ip' };
        }
      }
      
      return { banned: false };
      
    } catch (error) {
      console.error('Error checking ban status:', error.message);
      // Fail open for ban check to avoid blocking legitimate users
      return { banned: false, error: true };
    }
  }
);