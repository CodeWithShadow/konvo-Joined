const { onDocumentCreated } = require("firebase-functions/v2/firestore");
const { initializeApp } = require("firebase-admin/app");
const { getFirestore, Timestamp } = require("firebase-admin/firestore");

initializeApp();
const db = getFirestore();

// ⚙️ SETTINGS
const SPAM_THRESHOLD = 7;
const TIME_WINDOW = 10;
const BAN_REASON = "Automated Ban: Message Flooding (Cloud Function)";

// ✅ Added region configuration
exports.detectSpamAndBan = onDocumentCreated(
  {
    document: "{collectionId}/{messageId}",
    region: "asia-south1"  // 👈 Mumbai region
  },
  async (event) => {
    const { collectionId } = event.params;

    if (collectionId !== "chat" && collectionId !== "confessions") return null;

    const snapshot = event.data;
    if (!snapshot) return null;

    const msgData = snapshot.data();
    const userId = msgData.userId;

    if (!userId) return null;

    const now = Timestamp.now();
    const windowStart = new Date(now.toMillis() - (TIME_WINDOW * 1000));

    try {
      const recentMsgs = await db.collection(collectionId)
        .where("userId", "==", userId)
        .where("timestamp", ">", windowStart)
        .get();

      if (recentMsgs.size >= SPAM_THRESHOLD) {
        console.log(`🚨 Banning User ${userId}: ${recentMsgs.size} msgs in ${TIME_WINDOW}s`);

        const batch = db.batch();

        const banRef = db.collection("banned_users").doc(userId);
        batch.set(banRef, {
          bannedBy: "SYSTEM_CLOUD_FUNCTION",
          reason: BAN_REASON,
          timestamp: now,
          username: msgData.username || "Unknown"
        });

        const userRef = db.collection("users").doc(userId);
        batch.set(userRef, { banned: true }, { merge: true });

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

        recentMsgs.forEach((doc) => {
          batch.delete(doc.ref);
        });

        await batch.commit();
        console.log(`✅ User ${userId} has been terminated.`);
      }
    } catch (error) {
      console.error("Error in spam detection:", error);
    }

    return null;
  }
);