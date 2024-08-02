import express from "express";
import multer from "multer";
import cors from "cors";
import bodyParser from "body-parser";
import Razorpay from "razorpay";
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
const upload = multer({ storage: multer.memoryStorage() });

server.use(cors());
server.use(express.json()); // Built-in body-parser for JSON
server.use(express.urlencoded({ extended: true })); // Built-in body-parser for URL-encoded data
server.use(bodyParser.json());

// API Security
const limiter = rateLimit({
  max: 1000,
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
        competitionTopic: formDetails.competitionTopic,
        mentor: {
          name: formDetails.mentorName,
          age: formDetails.mentorAge,
          email: formDetails.mentorEmail,
          phone: formDetails.mentorPhone,
        },
        members: teamMembers,
      },
    });

    res
      .status(200)
      .json({ message: "Team registered successfully", registered: true });
  } catch (error) {
    console.error("Error registering team:", error);
    res.status(500).json({ error: "Error registering team" });
  }
});

// Payment Gateway
server.post("/api/payment", (req, res) => {
  const { amount } = req.body;

  try {
    const options = {
      amount: Number(amount) * 100,
      currency: "INR",
      receipt: crypto.randomBytes(10).toString("hex"),
    };

    razorpayInstance.orders.create(options, (err, order) => {
      if (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to create order" });
      }
      res.status(200).json({ data: order });
      console.log("Order created", order);
    });
  } catch (error) {
    res.status(500).json({ message: "Internal Server Error" });
    console.log(error);
  }
});

// Payment Verification
server.post("/api/verify", verifyToken, async (req, res) => {
  const { uid } = req.user;
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature } =
    req.body;

  try {
    // Create sign string by concatenating order_id and payment_id
    const sign = razorpay_order_id + "|" + razorpay_payment_id;

    // Create ExpectedSign by hashing the sign string with the Razorpay secret key
    const expectedSign = crypto
      .createHmac("sha256", process.env.RZP_SECRET_KEY)
      .update(sign.toString())
      .digest("hex");

    // Compare the expectedSign with the received signature
    const isAuthentic = expectedSign === razorpay_signature;

    // Determine payment verification status
    const paymentVerified = isAuthentic; // true if signature matches, otherwise false

    // Save payment data to Firebase Realtime Database
    const userRef = dbRef(
      database,
      `users/${uid}/payments/${razorpay_payment_id}`
    );
    await set(userRef, {
      razorpay_order_id,
      razorpay_payment_id,
      razorpay_signature,
      paymentVerified,
    });

    // Send response based on payment verification status
    if (paymentVerified) {
      res.status(200).json({ message: "Payment verified successfully" });
    } else {
      res.status(400).json({ message: "Payment verification failed" });
    }
  } catch (error) {
    res.status(500).json({ message: "Internal Server Error" });
    console.error("Payment verification error:", error); // Log error details for troubleshooting
  }
});

// Get the User Details

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

// Admin panel route - upload Auth code and certificate (At the Moment Not in Use)
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
// Admin panel route - upload AuthCode, Name, and academic in database
server.post("/save-details", async (req, res) => {
  const { authCode, name, academicYear } = req.body;

  if (!authCode || !name || !academicYear) {
    return res
      .status(400)
      .json({ message: "Auth Code, Name, and Academic Year are required" });
  }

  try {
    const newDetailsRef = push(dbRef(database, "certificate-details"));
    await set(newDetailsRef, {
      authCode,
      name,
      academicYear,
    });

    res.status(200).json({ message: "Details saved successfully" });
  } catch (error) {
    console.error("Error saving details:", error);
    res.status(500).json({ message: "Error saving details", error });
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
