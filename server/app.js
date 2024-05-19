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
const winston = require("winston");
const sanitizeHtml = require("sanitize-html");

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

const fileExtensionMap = {
  pdf: "pdf",
  png: "png",
  jpeg: "jpeg",
  jpg: "jpeg",
  docx: "vnd.openxmlformats-officedocument.wordprocessingml.document",
  txt: "plain",
  xlsx: "vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  pptx: "vnd.openxmlformats-officedocument.presentationml.presentation",
  mp4: "mp4",
  mp3: "mpeg",
  wav: "wav",
  zip: "zip",
  rar: "x-rar-compressed",
  "7z": "x-7z-compressed",
  ppt: "vnd.ms-powerpoint",
  xls: "vnd.ms-excel",
  doc: "msword",
  csv: "csv",
  json: "json",
  xml: "xml",
  "x-msdownload": "exe",
};

// Winston logger
const logger = winston.createLogger({
  level: "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: "error.log", level: "error" }),
    new winston.transports.File({ filename: "combined.log" }),
  ],
});

// Middleware to authenticate user
function authenticateUser(req, res, next) {
  if (
    req.query.userId ||
    req.query.senderId ||
    req.query.receiverId ||
    req.params.senderId ||
    req.params.receiverId ||
    req.params.userId ||
    req.body.senderId ||
    req.body.receiverId ||
    req.body.userId
  ) {
    logger.info("User authenticated", {
      userId:
        req.params.userId ||
        req.body.userId ||
        req.query.senderId ||
        req.query.receiverId,
    });
    next();
  } else {
    logger.warn("Unauthorized access");
    res.status(401).send("Unauthorized");
  }
}

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
  logger.info(`Server started on port ${port}`);
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
  logger.info("User connected", { socketId: socket.id });
  // Add user to the users array
  socket.on("addUser", (userId) => {
    const isUserExist = users.find((user) => user.userId === userId);
    if (!isUserExist) {
      const user = { userId, socketId: socket.id, isOnline: true };
      users.push(user);
      io.emit("getUsers", users);

      logger.info("User added", { userId, socketId: socket.id });
    }
  });

  // Handle typing status
  socket.on("typing", ({ senderId, receiverId, isTyping }) => {
    const receiver = users.find((user) => user.userId === receiverId);
    if (receiver) {
      io.to(receiver.socketId).emit("typingStatus", { senderId, isTyping });
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
      logger.info("Message sending initiated", {
        senderId,
        receiverId,
        conversationId,
      });
      logger.debug("File URL", { fileUrl });

      const receiver = users.find((user) => user.userId === receiverId);
      logger.debug("Receiver", { receiver });

      const sender = users.find((user) => user.userId === senderId);
      logger.debug("Sender", { sender });

      const user = await Users.findById(senderId);
      logger.debug("User", {
        id: user._id,
        fullName: user.fullName,
        email: user.email,
      });

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
        logger.info("Message sent to both sender and receiver", {
          senderId,
          receiverId,
          conversationId,
        });
      } else {
        // If receiver is offline, send the message only to the sender
        logger.info("Receiver is offline. Sending message to sender only", {
          senderId,
          receiverId,
          conversationId,
        });
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

  // search through the users array for online users and emit the online users
  setInterval(async () => {
    const onlineUsers = users.filter((user) => user.isOnline);

    let onlineUsersData = [];

    for (const user of onlineUsers) {
      const userData = await Users.findById(user.userId);

      onlineUsersData.push(userData);
    }

    io.emit("getOnlineUsers", onlineUsersData);
  }, 5000);

  // Handle user disconnection
  socket.on("disconnect", () => {
    // Update user's online status to false and remove user from the users array
    users = users.filter((user) => user.socketId !== socket.id);
    io.emit("getUsers", users);
    logger.info("User disconnected", { socketId: socket.id });
  });
});
// Validation schemas
const registerSchema = Joi.object({
  fullName: Joi.string().min(6).required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
});

const loginSchema = Joi.object({
  // fullname is empty
  fullName: Joi.string().allow(""),
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
  try {
    logger.info("GET / - Welcome route accessed");
    res.send("Welcome");
  } catch (error) {
    logger.error("GET / - Error:", error);
    res.status(500).send("Internal Server Error");
  }
});

app.post("/api/register", async (req, res, next) => {
  try {
    logger.info("POST /api/register - User registration initiated");
    const { error } = registerSchema.validate(req.body);
    if (error) {
      logger.warn(
        "POST /api/register - Validation error:",
        error.details[0].message
      );
      return res.status(400).send(error.details[0].message);
    }
    const { fullName, email, password } = req.body;

    // Sanitize input data
    const sanitizedFullName = sanitizeHtml(fullName);
    const sanitizedEmail = sanitizeHtml(email);

    const isAlreadyExist = await Users.findOne({ email: sanitizedEmail });
    if (isAlreadyExist) {
      logger.warn("POST /api/register - User already exists");
      res.status(400).send("User already exists");
    } else {
      const secretKey = CryptoJS.lib.WordArray.random(16).toString(); // Generate a random secret key
      const newUser = new Users({
        fullName: sanitizedFullName,
        email: sanitizedEmail,
        secretKey,
      });
      bcryptjs
        .hash(password, 10)
        .then((hashedPassword) => {
          newUser.set("password", hashedPassword);
          return newUser.save();
        })
        .then(() => {
          logger.info("POST /api/register - User registered successfully");
          next();
        })
        .catch((err) => {
          logger.error("POST /api/register - Error:", err);
          res.status(500).send("Internal Server Error");
        });
      return res.status(200).send("User registered successfully");
    }
  } catch (error) {
    logger.error("POST /api/register - Error:", error);
    res.status(500).send("Internal Server Error");
  }
});

app.post("/api/login", async (req, res, next) => {
  try {
    const { error } = loginSchema.validate(req.body);
    if (error) {
      logger.error("POST /api/login - Validation Error:", error);
      return res.status(400).send(error.details[0].message);
    }
    const { email, password } = req.body;

    // Sanitize input data
    const sanitizedEmail = sanitizeHtml(email);

    const user = await Users.findOne({ email: sanitizedEmail });
    if (!user) {
      logger.error("POST /api/login - User not found");
      res.status(400).send("User email or password is incorrect");
    } else {
      const validateUser = await bcryptjs.compare(password, user.password);
      if (!validateUser) {
        logger.error("POST /api/login - Invalid password");
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
            if (err) {
              logger.error("POST /api/login - JWT Sign Error:", err);
              return res.status(500).send("Internal Server Error");
            }
            await Users.updateOne(
              { _id: user._id },
              {
                $set: { token },
              }
            );
            user.token = token;
            await user.save();
            logger.info("POST /api/login - User logged in successfully");
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
    logger.error("POST /api/login - Error:", error);
    res.status(500).send("Internal Server Error");
  }
});

// logout route
app.post("/api/logout", authenticateUser, async (req, res) => {
  try {
    const { userId } = req.body;

    // Sanitize input data
    const sanitizedUserId = sanitizeHtml(userId);

    await Users.updateOne(
      { _id: sanitizedUserId },
      {
        $set: { token: "" },
      },
      (err) => {
        if (err) {
          logger.error("POST /api/logout - Error:", err);
          return res.status(500).send("Internal Server Error");
        }
        logger.info("POST /api/logout - User logged out successfully");
        res.status(200).send("User logged out successfully");
      }
    );
  } catch (error) {
    logger.error("POST /api/logout - Error:", error);
    res.status(500).send("Internal Server Error");
  }
});

// Create a new conversation
app.post("/api/conversation", authenticateUser, async (req, res) => {
  try {
    const { senderId, receiverId } = req.body;

    // Sanitize input data
    const sanitizedSenderId = sanitizeHtml(senderId);
    const sanitizedReceiverId = sanitizeHtml(receiverId);

    const newConversation = new Conversations({
      members: [sanitizedSenderId, sanitizedReceiverId],
    });
    await newConversation.save((err) => {
      if (err) {
        logger.error("POST /api/conversation - Error:", err);
        return res.status(500).send("Internal Server Error");
      }
      logger.info("POST /api/conversation - Conversation created successfully");
      res.status(200).send("Conversation created successfully");
    });
  } catch (error) {
    logger.error("POST /api/conversation - Error:", error);
    res.status(500).send("Internal Server Error");
  }
});

// Get conversations for a specific user
app.get("/api/conversations/:userId", authenticateUser, async (req, res) => {
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
    logger.info(
      "GET /api/conversations/:userId - Conversations retrieved successfully"
    );
    res.status(200).json(await conversationUserData);
  } catch (error) {
    logger.error("GET /api/conversations/:userId - Error:", error);
    res.status(500).send("Internal Server Error");
  }
});

// Handle sending messages
app.post(
  "/api/message",
  multer({ dest: "uploads/" }).single("file"),
  authenticateUser,
  async (req, res) => {
    try {
      logger.info("POST /api/message - Message sending initiated");
      const { error } = messageSchema.validate(req.body);
      if (error) {
        logger.warn(
          "POST /api/message - Validation error:",
          error.details[0].message
        );
        return res.status(400).send(error.details[0].message);
      }
      const { conversationId, senderId, message, receiverId = "" } = req.body;

      // Sanitize input data
      const sanitizedConversationId = sanitizeHtml(conversationId);
      const sanitizedSenderId = sanitizeHtml(senderId);
      const sanitizedMessage = sanitizeHtml(message);
      const sanitizedReceiverId = sanitizeHtml(receiverId);

      // Get the sender's secret key
      const sender = await Users.findById(sanitizedSenderId);
      const senderSecretKey = sender.secretKey;

      // Encrypt the message using the sender's secret key
      const encryptedMessage = sanitizedMessage
        ? CryptoJS.AES.encrypt(sanitizedMessage, senderSecretKey).toString()
        : "";

      let fileUrl = "";
      let fileName = "";
      let fileType = "";

      if (req.file) {
        const fileData = fs.readFileSync(
          path.join(__dirname, "uploads", req.file.filename)
        );

        // Get the sender's secret key
        const sender = await Users.findById(sanitizedSenderId);
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
      if (sanitizedConversationId === "new" && sanitizedReceiverId) {
        const newConversation = new Conversations({
          members: [sanitizedSenderId, sanitizedReceiverId],
        });
        await newConversation
          .save()
          .then(() => {
            const newMessage = new Messages({
              conversationId: newConversation._id,
              senderId: sanitizedSenderId,
              message: encryptedMessage,
              fileUrl,
              fileName,
              fileType,
            });
            return newMessage.save();
          })
          .then(() => {
            logger.info("POST /api/message - Message sent successfully");
            res.status(200).send("Message sent successfully");
          })
          .catch((err) => {
            logger.error("POST /api/message - Error:", err);
            res.status(500).send("Internal Server Error");
          });
      }
      // Send the message to an existing conversation
      else if (!sanitizedConversationId && !sanitizedReceiverId) {
        logger.warn("POST /api/message - Missing conversationId or receiverId");
        return res.status(400).send("Please fill all required fields");
      } else {
        // Save the encrypted message and file information to the conversation
        const newMessage = new Messages({
          conversationId: sanitizedConversationId,
          senderId: sanitizedSenderId,
          message: encryptedMessage,
          fileUrl,
          fileName,
          fileType,
        });
        await newMessage
          .save()
          .then(() => {
            logger.info("POST /api/message - Message sent successfully");
            res.status(200).send("Message sent successfully");
          })
          .catch((err) => {
            logger.error("POST /api/message - Error saving message:", err);
            res.status(500).send("Internal Server Error");
          });
      }
    } catch (error) {
      logger.error("POST /api/message - Error:", error);
      res.status(500).send("Internal Server Error");
    }
  }
);

// Get messages for a specific conversation
app.get("/api/message/:conversationId", authenticateUser, async (req, res) => {
  try {
    //check messages for a specific conversation
    const checkMessages = async (conversationId) => {
      logger.info(
        "GET /api/message/:conversationId - Checking messages for conversation",
        { conversationId }
      );
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
            )}`;

            const fileExtension = message.fileType.split("/")[1];
            const fileType = fileExtensionMap[fileExtension];
            console.log(fileType);
            console.log(fileExtension);

            if (fileType) {
              const decryptedFilePath = path.join(
                __dirname,
                "uploads",
                `${decryptedFilename}.${fileType}`
              );
              fs.writeFileSync(decryptedFilePath, decryptedFileData);
              decryptedFileUrl = `${req.protocol}://${req.get(
                "host"
              )}/uploads/${decryptedFilename}.${fileExtension}`;
            } 
            if (fileType === "exe") {
              decryptedFileUrl = `${req.protocol}://${req.get(
                "host"
              )}/uploads/${decryptedFilename}.${fileType}`;
            }

          }

          logger.info("GET /api/message/:conversationId - Message decrypted", {
            decryptedMessage,
            decryptedFileUrl,
          });

          return {
            user: {
              id: user._id,
              email: user.email,
              fullName: user.fullName,
            },
            message: decryptedMessage,
            fileUrl: decryptedFileUrl,
            fileName: message.fileName,
            fileType: message.fileType,
          };
        })
      );
      logger.info(
        "GET /api/message/:conversationId - Messages retrieved successfully"
      );
      res.status(200).json(await messageUserData);
    };
    const conversationId = req.params.conversationId;

    // Sanitize input data
    const sanitizedConversationId = sanitizeHtml(conversationId);
    const sanitizedSenderId = sanitizeHtml(req.query.senderId);
    const sanitizedReceiverId = sanitizeHtml(req.query.receiverId);

    if (sanitizedConversationId === "new") {
      // Check if there is an existing conversation between the sender and receiver
      const checkConversation = await Conversations.find({
        members: { $all: [sanitizedSenderId, sanitizedReceiverId] },
      });
      if (checkConversation.length > 0) {
        // If conversation exists, retrieve messages
        checkMessages(checkConversation[0]._id);
      } else {
        // If conversation does not exist, return empty array
        return res.status(200).json([]);
      }
    } else {
      // check if the authenticated user is the same as the users in the conversation
      const conversation = await Conversations.findById(
        sanitizedConversationId
      );
      if (
        conversation.members.includes(sanitizedSenderId) &&
        conversation.members.includes(sanitizedReceiverId)
      ) {
        // Retrieve messages for the given conversationId
        checkMessages(sanitizedConversationId);
      }
    }
  } catch (error) {
    logger.error("GET /api/message/:conversationId - Error:", error);
    res.status(500).send("Internal Server Error");
  }
});

// Get all users except the specified user
app.get("/api/users/:userId", authenticateUser, async (req, res) => {
  try {
    logger.info("GET /api/users/:userId - Get all users except specified user");
    const userId = req.params.userId;

    // Sanitize input data
    const sanitizedUserId = sanitizeHtml(userId);

    const users = await Users.find({ _id: { $ne: sanitizedUserId } });
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
    logger.info("GET /api/users/:userId - Users retrieved successfully");
    res.status(200).json(await usersData);
  } catch (error) {
    logger.error("GET /api/users/:userId - Error:", error);
    res.status(500).send("Internal Server Error");
  }
});
