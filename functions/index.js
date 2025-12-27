const functions = require("firebase-functions");
const admin = require("firebase-admin");

admin.initializeApp();
const db = admin.firestore();

// ⚙️ SETTINGS: Tune these to catch spammers
const SPAM_THRESHOLD = 7;   // Max messages allowed...
const TIME_WINDOW = 10;     // ...in this many seconds
const BAN_REASON = "Automated Ban: Message Flooding (Cloud Function)";

exports.detectSpamAndBan = functions.firestore
  .document("{collectionId}/{messageId}")
  .onCreate(async (snapshot, context) => {
    const { collectionId } = context.params;

    // 1. Only watch chat and confessions
    if (collectionId !== "chat" && collectionId !== "confessions") return null;

    const msgData = snapshot.data();
    const userId = msgData.userId;
    const now = admin.firestore.Timestamp.now();
    
    // Calculate the time window (e.g., 10 seconds ago)
    const windowStart = new Date(now.toMillis() - (TIME_WINDOW * 1000));

    try {
      // 2. Count how many messages this user sent recently
      const recentMsgs = await db.collection(collectionId)
        .where("userId", "==", userId)
        .where("timestamp", ">", windowStart)
        .get();

      // 3. If they exceeded the limit...
      if (recentMsgs.size >= SPAM_THRESHOLD) {
        console.log(`🚨 Banning User ${userId}: ${recentMsgs.size} msgs in ${TIME_WINDOW}s`);

        const batch = db.batch();

        // A. Ban the User ID
        const banRef = db.collection("banned_users").doc(userId);
        batch.set(banRef, {
          bannedBy: "SYSTEM_CLOUD_FUNCTION",
          reason: BAN_REASON,
          timestamp: now,
          username: msgData.username || "Unknown"
        });

        // B. Mark User Profile as Banned
        const userRef = db.collection("users").doc(userId);
        batch.set(userRef, { banned: true }, { merge: true });

        // C. Find and Ban their Device Fingerprint & IP
        const devices = await db.collection("user_devices")
          .where("userId", "==", userId)
          .get();

        devices.forEach((doc) => {
          const data = doc.data();
          if (data.fingerprint) {
            batch.set(db.collection("banned_devices").doc(data.fingerprint), {
              userId,
              reason: BAN_REASON,
              timestamp: now
            });
          }
          if (data.ipHash) {
            batch.set(db.collection("banned_ips").doc(data.ipHash), {
              userId,
              reason: BAN_REASON,
              timestamp: now
            });
          }
        });

        // D. Delete the Spam Messages
        recentMsgs.forEach((doc) => {
          batch.delete(doc.ref);
        });

        // Execute the Ban
        await batch.commit();
        console.log(`✅ User ${userId} has been terminated.`);
      }
    } catch (error) {
      console.error("Error in spam detection:", error);
    }
  });