import express from "express";
import multer from "multer";
import cors from "cors";
import bodyParser from "body-parser";
import Razorpay from "razorpay";
import crypto from "crypto";
import { initializeApp } from "firebase/app";
import {
  createUserWithEmailAndPassword,
  getAuth,
  sendEmailVerification,
  signInWithEmailAndPassword,
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
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import rateLimit from "express-rate-limit";
import helmet from "helmet";

dotenv.config();

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

const razorpayInstance = new Razorpay({
  key_id: process.env.RZP_KEY_ID,
  key_secret: process.env.RZP_SECRET_KEY,
});

// Initialize Firebase
const app = initializeApp(firebaseConfig);
const storage = getStorage(app);
const database = getDatabase(app);
const auth = getAuth();

const server = express();
// Trust the first proxy
server.set("trust proxy", 1);
const upload = multer({ storage: multer.memoryStorage() });

server.use(cors());
server.use(express.json()); // Built-in body-parser for JSON
server.use(express.urlencoded({ extended: true })); // Built-in body-parser for URL-encoded data
server.use(bodyParser.json());

// API Security
const limiter = rateLimit({
  max: 100000,
  windowMs: 60 * 60 * 1000,
  message: "Too many requests from this IP, please try again in an hour",
});

server.use(limiter);
server.use(helmet());

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
    });

    // send verification email
    await sendEmailVerification(user);

    const token = jwt.sign({ uid: user.uid }, process.env.JWT_SECRET);
    res.status(200).json({ message: "User registered successfully", token });
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

    const token = jwt.sign({ uid: user.uid }, process.env.JWT_SECRET);

    res.status(200).json({ message: "Login successful", token });
  } catch (error) {
    console.error("Error logging in:", error);
    res.status(500).json({ message: "Error logging in", error });
  }
});

// token verification

// Middleware to verify Firebase ID token
const verifyToken = async (req, res, next) => {
  const token = req.headers.authorization?.split("Bearer ")[1];

  if (!token) {
    return res.status(401).json({ message: "ID Token is required" });
  }

  try {
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) {
        console.error("Error verifying token:", err);
        return res.status(401).json({ message: "Unauthorized" });
      }
      req.user = decoded;
      next();
    });
  } catch (error) {
    console.error("Error verifying ID token:", error);
    res.status(401).json({ message: "Invalid ID token", error });
  }
};

// Get the user Data
server.get("/user-profile", verifyToken, async (req, res) => {
  const uid = req.user.uid;

  try {
    const userRef = dbRef(database, `users/${uid}`);
    const userSnapshot = await get(userRef);

    if (userSnapshot.exists()) {
      const userData = userSnapshot.val();
      res.status(200).json({ message: "User profile sent", user: userData });
    } else {
      res.status(404).json({ message: "User not found" });
    }
  } catch (error) {
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// Team registration form
server.post("/register-team", verifyToken, async (req, res) => {
  const { uid } = req.user;
  const { formDetails, teamMembers } = req.body;

  if (!formDetails || !teamMembers) {
    return res.status(400).json({ error: "Missing team details" });
  }

  try {
    // Reference to the user data
    const userRef = dbRef(database, `users/${uid}`);

    // Fetch the existing user data
    const userSnapshot = await get(userRef);
    const userData = userSnapshot.val();

    if (!userData) {
      return res.status(404).json({ error: "User not found" });
    }

    // Update only the team details, preserving the existing email
    await set(userRef, {
      ...userData, // Preserve existing data including email
      team: {
        teamName: formDetails.teamName,
        country: formDetails.country,
        institutionName: formDetails.institutionName,
        teamLeader: {
          fullName: formDetails.teamLeader.fullName,
          email: formDetails.teamLeader.email,
          phoneNumber: formDetails.teamLeader.phoneNumber,
          dateOfBirth: formDetails.teamLeader.dateOfBirth,
        },
        teamMembers: teamMembers.map((member, index) => ({
          fullName: member.fullName,
          email: member.email,
          phoneNumber: member.phoneNumber,
          dateOfBirth: member.dateOfBirth,
          emergencyContact: member.emergencyContact,
        })),
      },
      // Adding registration status
      registrationStatus: "registered",
    });

    res.status(200).json({ message: "Team registered successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error registering team", error });
  }
});

// Set Team Image Upload
server.post(
  "/upload-team-image",
  verifyToken,
  upload.single("teamImage"),
  async (req, res) => {
    const uid = req.user.uid;
    const file = req.file;

    if (!file) {
      return res.status(400).json({ error: "No image file uploaded" });
    }

    try {
      const imageRef = ref(storage, `teamImages/${uid}/${file.originalname}`);
      await uploadBytes(imageRef, file.buffer);

      const imageUrl = await getDownloadURL(imageRef);

      await set(dbRef(database, `users/${uid}/teamImageUrl`), imageUrl);

      res
        .status(200)
        .json({ message: "Image uploaded successfully", imageUrl });
    } catch (error) {
      res.status(500).json({ error: "Failed to upload image", details: error });
    }
  }
);

// Set Resume Upload
server.post(
  "/upload-resume",
  verifyToken,
  upload.single("resume"),
  async (req, res) => {
    const uid = req.user.uid;
    const file = req.file;

    if (!file) {
      return res.status(400).json({ error: "No resume file uploaded" });
    }

    try {
      const resumeRef = ref(storage, `resumes/${uid}/${file.originalname}`);
      await uploadBytes(resumeRef, file.buffer);

      const resumeUrl = await getDownloadURL(resumeRef);

      await set(dbRef(database, `users/${uid}/resumeUrl`), resumeUrl);

      res
        .status(200)
        .json({ message: "Resume uploaded successfully", resumeUrl });
    } catch (error) {
      res
        .status(500)
        .json({ error: "Failed to upload resume", details: error });
    }
  }
);

// Payment Integration
server.post("/api/payment", (req, res) => {
  const { teamTotalPrice } = req.body;

  if (!teamTotalPrice) {
    return res.status(400).json({
      statusCode: 400,
      error: {
        code: "BAD_REQUEST_ERROR",
        description: "amount: is required.",
        metadata: {},
        reason: "input_validation_failed",
        source: "business",
        step: "payment_initiation",
      },
    });
  }

  try {
    const options = {
      amount: Number(teamTotalPrice) * 100,
      currency: "INR",
      receipt: crypto.randomBytes(10).toString("hex"),
    };

    razorpayInstance.orders.create(options, (err, order) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: "Failed to create order" });
      }
      res.status(200).json({ data: order });
      console.log("Order created now", order);
    });
  } catch (error) {
    res.status(500).json({ message: "Internal Server Error" });
    console.log(error);
  }
});

server.listen(4242, () => {
  console.log("Server is running on port 4242");
});
