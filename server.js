import express from "express";
import multer from "multer";
import cors from "cors";
import { initializeApp } from "firebase/app";
import {
  createUserWithEmailAndPassword,
  getAuth,
  sendEmailVerification,
} from "firebase/auth";
import { getStorage, ref, uploadBytes, getDownloadURL } from "firebase/storage";
import {
  getDatabase,
  ref as dbRef,
  push,
  set,
  get,
  serverTimestamp,
} from "firebase/database";

// Firebase configuration
const firebaseConfig = {
  apiKey: "AIzaSyD1YgPZ2_yGPPu54E54DrJyBD8hN7h8J8s",
  authDomain: "isrc-2a615.firebaseapp.com",
  databaseURL: "https://isrc-2a615-default-rtdb.firebaseio.com",
  projectId: "isrc-2a615",
  storageBucket: "isrc-2a615.appspot.com",
  messagingSenderId: "538265921590",
  appId: "1:538265921590:web:86499e7bc8dc7c294cd097",
  measurementId: "G-Q2ZJNQJ1MP",
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);
const storage = getStorage(app);
const database = getDatabase(app);
const auth = getAuth();

const server = express();
const upload = multer({ storage: multer.memoryStorage() });

server.use(express.json());
server.use(cors());

server.get("/", (req, res) => {
  res.send("App is working");
});

// Register the User
server.post("/register", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email and Password are required" });
  }

  try {
    const userCredential = await createUserWithEmailAndPassword(
      auth,
      email,
      password
    );

    const user = userCredential.user;

    await set(dbRef(database, `users/${user.uid}`), {
      uid: user.uid,
      email: user.email,
      createdAt: new Date().toISOString(),
    });

    // send verification email
    await sendEmailVerification(user);

    const idToken = await user.getIdToken();
    res
      .status(200)
      .json({ message: "User registered successfully", user, idToken });
  } catch (error) {
    if (error.code === "auth/email-already-in-use") {
      res.status(400).json({ message: "Email is already in use" });
    } else {
      console.error("Error registering user:", error);
      res.status(500).json({ message: "Error registering user", error });
    }
  }
});

// Login the User

server.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email and Password are required" });
  }

  try {
    const userCredential = await signInWithEmailAndPassword(
      auth,
      email,
      password
    );
    const user = userCredential.user;

    if (user.emailVerified) {
      const idToken = await user.getIdToken();
      res.status(200).json({ message: "Login successful", user, idToken });
    } else {
      res
        .status(400)
        .json({ message: "Please verify your email before logging in." });
    }
  } catch (error) {
    console.error("Error logging in:", error);
    res.status(500).json({ message: "Error logging in", error });
  }
});

// Check the verification Email

server.post("/check-verification", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email and Password are required" });
  }

  try {
    const userCredential = await signInWithEmailAndPassword(
      auth,
      email,
      password
    );
    const user = userCredential.user;

    if (user.emailVerified) {
      res.status(200).json({ message: "Email is verified" });
    } else {
      res.status(200).json({ message: "Email is not verified" });
    }
  } catch (error) {
    console.error("Error checking email verification:", error);
    res
      .status(500)
      .json({ message: "Error checking email verification", error });
  }
});

server.post("/upload", upload.single("certificate"), async (req, res) => {
  const { authCode } = req.body;
  const file = req.file;

  if (!authCode || !file) {
    return res
      .status(400)
      .json({ message: "Auth Code and Certificate are required" });
  }

  try {
    // Upload file to Firebase Storage
    const storageRef = ref(
      storage,
      `certificates/${Date.now()}-${file.originalname}`
    );
    const snapshot = await uploadBytes(storageRef, file.buffer);
    const downloadURL = await getDownloadURL(snapshot.ref);

    // Save Auth Code and file URL to Firebase Realtime Database
    const newUploadRef = push(dbRef(database, "certificates"));

    await set(newUploadRef, {
      id: newUploadRef.key,
      authCode,
      certificateUrl: downloadURL,
      uploadedAt: serverTimestamp(),
    });

    res.status(200).json({ message: "Upload successful", downloadURL });
  } catch (error) {
    console.error("Error uploading file:", error);
    res.status(500).json({ message: "Error uploading file", error });
  }
});

server.post("/verify", async (req, res) => {
  const { authCode } = req.body;

  if (!authCode) {
    return res.status(400).json({ message: "Auth Code is required" });
  }

  try {
    // Query Firebase Realtime Database for the given Auth Code
    const uploadsRef = dbRef(database, "certificates");

    // Fetch all child nodes under 'uploads'
    const snapshot = await get(uploadsRef);

    if (snapshot.exists()) {
      // Iterate through the children to find a matching authCode
      const data = snapshot.val();
      for (const key in data) {
        if (data[key].authCode === authCode) {
          return res
            .status(200)
            .json({ certificateUrl: data[key].certificateUrl });
        }
      }
    } else {
      res.status(404).json({ message: "No record found for this Auth Code" });
    }
  } catch (error) {
    console.error("Error fetching data:", error);
    res.status(500).json({ message: "Error fetching data", error });
  }
});

// Register the Campus Ambassador

server.post("/campus-ambassador", async (req, res) => {
  const {
    name,
    email,
    phone,
    state,
    city,
    college,
    yearOfStudy,
    degreeProgram,
  } = req.body;

  if (
    !name ||
    !email ||
    !phone ||
    !state ||
    !city ||
    !college ||
    !yearOfStudy ||
    !degreeProgram
  ) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    // Save the Campus Ambassador details to Firebase Realtime Database
    const newCampusAmbassadorRef = push(dbRef(database, "campus-ambassadors"));
    await set(newCampusAmbassadorRef, {
      name,
      email,
      phone,
      state,
      city,
      college,
      yearOfStudy,
      degreeProgram,
      createdAt: new Date().toISOString(),
    });
    res
      .status(200)
      .json({ message: "Campus Ambassador registered successfully" });
  } catch (error) {
    res.status(500).json({ message: "Internal Server Error" });
  }
});
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
