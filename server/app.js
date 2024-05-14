require("dotenv").config();
const express = require("express");
const https = require("https");
const bcryptjs = require("bcryptjs");
const jwt = require("jsonwebtoken");
const CryptoJS = require("crypto-js");
const multer = require("multer");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const Joi = require("joi");

// Connect DB
require("./db/connection");

// Import Files
const Users = require("./models/Users");
const Conversations = require("./models/Conversations");
const Messages = require("./models/Messages");

const sslOptions = {
  cert: fs.readFileSync("credentials/cert.pem"),
  key: fs.readFileSync("credentials/key.pem"),
};

// app Use
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cors());
app.use("/uploads", express.static(path.join(__dirname, "uploads")));
// Start the server
const port = 8000;

const server = https.createServer(sslOptions, app);

server.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});

const io = require("socket.io")(server, {
  cors: {
    origin: "https://localhost:3000",
    methods: ["GET", "POST"],
    allowedHeaders: ["Content-Type", "Authorization"],
  },
});

// Socket.io
let users = [];

// Handle user connection
io.on("connection", (socket) => {
  console.log("User connected", socket.id);

  // Add user to the users array
  socket.on("addUser", (userId) => {
    const isUserExist = users.find((user) => user.userId === userId);
    if (!isUserExist) {
      const user = { userId, socketId: socket.id };
      users.push(user);
      io.emit("getUsers", users);
    }
  });

  // handle message sending
  socket.on(
    "sendMessage",
    async ({
      senderId,
      receiverId,
      message,
      conversationId,
      fileUrl,
      fileName,
      fileType,
    }) => {
      console.log("fileUrl :>> ", fileUrl); // Log the file URL
      const receiver = users.find((user) => user.userId === receiverId);
      console.log("receiver :>> ", receiver);
      const sender = users.find((user) => user.userId === senderId);
      const user = await Users.findById(senderId);
      console.log("sender :>> ", sender, receiver);
      if (receiver) {
        // If receiver is online, send the message to both sender and receiver
        io.to(receiver.socketId)
          .to(sender.socketId)
          .emit("getMessage", {
            senderId,
            message,
            conversationId,
            receiverId,
            ...(fileUrl && { fileUrl }),
            ...(fileName && { fileName }),
            ...(fileType && { fileType }),
            user: { id: user._id, fullName: user.fullName, email: user.email },
          });
      } else {
        // If receiver is offline, send the message only to the sender
        console.log("receiver offline");
        io.to(sender.socketId).emit("getMessage", {
          senderId,
          message,
          conversationId,
          receiverId,
          ...(fileUrl && { fileUrl }),
          ...(fileName && { fileName }),
          ...(fileType && { fileType }),
          user: { id: user._id, fullName: user.fullName, email: user.email },
        });
      }
    }
  );

  // Handle user disconnection
  socket.on("disconnect", () => {
    // Remove user from the users array
    users = users.filter((user) => user.socketId !== socket.id);
    io.emit("getUsers", users);
  });
});

// Validation schemas
const registerSchema = Joi.object({
  fullName: Joi.string().required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
});

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required(),
});

const messageSchema = Joi.object({
  conversationId: Joi.string().required(),
  senderId: Joi.string().required(),
  message: Joi.string().allow(""),
  receiverId: Joi.string().allow(""),
});

// Routes
app.get("/", (req, res) => {
  res.send("Welcome");
});

app.post("/api/register", async (req, res, next) => {
  try {
    const { error } = registerSchema.validate(req.body);
    if (error) {
      return res.status(400).send(error.details[0].message);
    }
    const { fullName, email, password } = req.body;

    const isAlreadyExist = await Users.findOne({ email });
    if (isAlreadyExist) {
      res.status(400).send("User already exists");
    } else {
      const secretKey = CryptoJS.lib.WordArray.random(16).toString(); // Generate a random secret key
      const newUser = new Users({ fullName, email, secretKey });
      bcryptjs.hash(password, 10, (err, hashedPassword) => {
        newUser.set("password", hashedPassword);
        newUser.save();
        next();
      });
      return res.status(200).send("User registered successfully");
    }
  } catch (error) {
    console.log(error, "Error");
  }
});

app.post("/api/login", async (req, res, next) => {
  try {
    const { error } = loginSchema.validate(req.body);
    if (error) {
      return res.status(400).send(error.details[0].message);
    }
    const { email, password } = req.body;

    const user = await Users.findOne({ email });
    if (!user) {
      res.status(400).send("User email or password is incorrect");
    } else {
      const validateUser = await bcryptjs.compare(password, user.password);
      if (!validateUser) {
        res.status(400).send("User email or password is incorrect");
      } else {
        const payload = {
          userId: user._id,
          email: user.email,
        };
        const JWT_SECRET_KEY = process.env.JWT_SECRET;

        jwt.sign(
          payload,
          JWT_SECRET_KEY,
          { expiresIn: 84600 },
          async (err, token) => {
            await Users.updateOne(
              { _id: user._id },
              {
                $set: { token },
              }
            );
            user.save();
            return res.status(200).json({
              user: {
                id: user._id,
                email: user.email,
                fullName: user.fullName,
              },
              token: token,
            });
          }
        );
      }
    }
  } catch (error) {
    console.log(error, "Error");
  }
});

app.post("/api/logout/:userId", async (req, res) => {
  try {
    const { userId } = req.params;
    await Users.updateOne(
      { _id: userId },
      {
        $set: { token: "" },
      }
    );
    res.status(200).send("User logged out successfully");
  } catch (error) {
    console.log(error, "Error");
  }
});

// Create a new conversation
app.post("/api/conversation", async (req, res) => {
  try {
    const { senderId, receiverId } = req.body;
    const newCoversation = new Conversations({
      members: [senderId, receiverId],
    });
    await newCoversation.save();
    res.status(200).send("Conversation created successfully");
  } catch (error) {
    console.log(error, "Error");
  }
});

// Get conversations htmlFor a specific user
app.get("/api/conversations/:userId", async (req, res) => {
  try {
    const userId = req.params.userId;
    const conversations = await Conversations.find({
      members: { $in: [userId] },
    });
    const conversationUserData = Promise.all(
      conversations.map(async (conversation) => {
        const receiverId = conversation.members.find(
          (member) => member !== userId
        );
        const user = await Users.findById(receiverId);
        return {
          user: {
            receiverId: user._id,
            email: user.email,
            fullName: user.fullName,
          },
          conversationId: conversation._id,
        };
      })
    );
    res.status(200).json(await conversationUserData);
  } catch (error) {
    console.log(error, "Error");
  }
});

// Handle sending messages
app.post(
  "/api/message",
  multer({ dest: "uploads/" }).single("file"),
  async (req, res) => {
    try {
      const { error } = messageSchema.validate(req.body);
      if (error) {
        return res.status(400).send(error.details[0].message);
      }
      const { conversationId, senderId, message, receiverId = "" } = req.body;

      // Get the sender's secret key
      const sender = await Users.findById(senderId);
      const senderSecretKey = sender.secretKey;

      // Encrypt the message using the sender's secret key
      const encryptedMessage = message
        ? CryptoJS.AES.encrypt(message, senderSecretKey).toString()
        : "";

      let fileUrl = "";
      let fileName = "";
      let fileType = "";

      if (req.file) {
        const fileData = fs.readFileSync(
          path.join(__dirname, "uploads", req.file.filename)
        );
        

        // Get the sender's secret key
        const sender = await Users.findById(senderId);
        const senderSecretKey = sender.secretKey;

        // Convert the file data to a WordArray object
        const wordArray = CryptoJS.lib.WordArray.create(fileData);

        // Encrypt the file data using the sender's secret key
        const encryptedFileData = CryptoJS.AES.encrypt(
          wordArray,
          senderSecretKey
        ).toString();

        // Save the encrypted file
        const encryptedFilename = `${req.file.filename}.enc`;
        fs.writeFileSync(
          path.join(__dirname, "uploads", encryptedFilename),
          encryptedFileData
        );

        fileUrl = `${req.protocol}://${req.get(
          "host"
        )}/uploads/${encryptedFilename}`;
        fileName = req.file.originalname;
        fileType = req.file.mimetype;

        // Remove the original unencrypted file
        fs.unlinkSync(path.join(__dirname, "uploads", req.file.filename));
      }

      // Create a new conversation and send the message
      if (conversationId === "new" && receiverId) {
        const newConversation = new Conversations({
          members: [senderId, receiverId],
        });
        await newConversation.save();
        const newMessage = new Messages({
          conversationId: newConversation._id,
          senderId,
          message: encryptedMessage,
          fileUrl,
          fileName,
          fileType,
        });
        await newMessage.save();
        return res.status(200).send("Message sent successfully");
      }
      // Send the message to an existing conversation
      else if (!conversationId && !receiverId) {
        return res.status(400).send("Please fill all required fields");
      }

      // Save the encrypted message and file information to the conversation
      const newMessage = new Messages({
        conversationId,
        senderId,
        message: encryptedMessage,
        fileUrl,
        fileName,
        fileType,
      });
      await newMessage.save();
      res.status(200).send("Message sent successfully");
    } catch (error) {
      console.log(error, "Error");
      res.status(500).send("Internal Server Error");
    }
  }
);

// Get messages htmlFor a specific conversation
app.get("/api/message/:conversationId", async (req, res) => {
  try {
    //check messages htmlFor a specific conversation
    const checkMessages = async (conversationId) => {
      console.log(conversationId, "conversationId");
      const messages = await Messages.find({ conversationId });
      const messageUserData = Promise.all(
        messages.map(async (message) => {
          const user = await Users.findById(message.senderId);
          // Get the user's secret key
          const userSecretKey = user.secretKey;
          // Decrypt the message using the user's secret key
          const decryptedMessage = message.message
            ? CryptoJS.AES.decrypt(message.message, userSecretKey).toString(
                CryptoJS.enc.Utf8
              )
            : "";
  
          let decryptedFileUrl = message.fileUrl;
          if (message.fileUrl) {
            const encryptedFileData = fs.readFileSync(
              path.join(__dirname, "uploads", path.basename(message.fileUrl))
            );
            const decryptedWordArray = CryptoJS.AES.decrypt(
              encryptedFileData.toString(),
              userSecretKey
            );
            const decryptedFileData = Buffer.from(
              decryptedWordArray.toString(CryptoJS.enc.Base64),
              "base64"
            );
            const decryptedFilename = `decrypted_${path.basename(
              message.fileUrl,
              ".enc"
            )}`;
            fs.writeFileSync(
              path.join(__dirname, "uploads", decryptedFilename),
              decryptedFileData
            );
            decryptedFileUrl = `${req.protocol}://${req.get(
              "host"
            )}/uploads/${decryptedFilename}`;
          }

          console.log(decryptedMessage, "decryptedMessage");
          console.log(decryptedFileUrl, "decryptedFileUrl");
  
          return {
            user: { id: user._id, email: user.email, fullName: user.fullName },
            message: decryptedMessage,
            fileUrl: decryptedFileUrl,
            fileName: message.fileName,
            fileType: message.fileType,
          };
        })
      );
      console.log(messages, "messages");
      res.status(200).json(await messageUserData);
    };
    const conversationId = req.params.conversationId;
    if (conversationId === "new") {
      // Check if there is an existing conversation between the sender and receiver
      const checkConversation = await Conversations.find({
        members: { $all: [req.query.senderId, req.query.receiverId] },
      });
      if (checkConversation.length > 0) {
        // If conversation exists, retrieve messages
        checkMessages(checkConversation[0]._id);
      } else {
        // If conversation does not exist, return empty array
        return res.status(200).json([]);
      }
    } else {
      // Retrieve messages htmlFor the given conversationId
      checkMessages(conversationId);
    }
  } catch (error) {
    console.log("Error", error);
  }
});


// Get all users except the specified user
app.get("/api/users/:userId", async (req, res) => {
  try {
    const userId = req.params.userId;
    const users = await Users.find({ _id: { $ne: userId } });
    const usersData = Promise.all(
      users.map(async (user) => {
        return {
          user: {
            email: user.email,
            fullName: user.fullName,
            receiverId: user._id,
          },
        };
      })
    );
    res.status(200).json(await usersData);
  } catch (error) {
    console.log("Error", error);
  }
});
