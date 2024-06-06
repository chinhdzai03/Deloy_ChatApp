const admin = require('firebase-admin');

const setupFirebase = () => {
    try {
        const serviceAccount = require('./serviceAccountKey.json');
        admin.initializeApp({
            credential: admin.credential.cert(serviceAccount),
            storageBucket: 'gs://chat-webapp-81c85.appspot.com'
        });
        console.log("Firebase established successfully");
    } catch (error) {
        console.error("Firebase initialization failed:", error);
    }
};

setupFirebase();
const Firestore = admin.firestore();

const FirebaseStorage = admin.storage();

module.exports = { Firestore, FirebaseStorage };