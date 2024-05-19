import { useEffect, useRef, useState } from "react";
import Input from "../../components/Input";
import { io } from "socket.io-client";
import { jwtDecode } from "jwt-decode";

const Dashboard = () => {
  const [user, setUser] = useState(
    JSON.parse(localStorage.getItem("user:detail"))
  );

  const [conversations, setConversations] = useState([]);
  const [messages, setMessages] = useState({});
  const [message, setMessage] = useState("");
  const [users, setUsers] = useState([]);
  const [socket, setSocket] = useState(null);
  const [selectedFile, setSelectedFile] = useState(null);
  const [onlineUsersId, setOnlineUsersId] = useState([]);
  const [typingStatus, setTypingStatus] = useState({});

  const messageRef = useRef(null);
  let fileInputRef = null;

  useEffect(() => {
    const socket = io("https://localhost:8000");
    setSocket(socket);

    return () => {
      socket.disconnect();
    };
  }, []);

  useEffect(() => {
    socket?.emit("addUser", user?.id);

    socket?.on("getOnlineUsers", (users) => {
      setOnlineUsersId(users.map((user) => user._id));
    });

    socket?.on("typingStatus", ({ senderId, isTyping }) => {
      setTypingStatus((prevStatus) => ({
        ...prevStatus,
        [senderId]: isTyping,
      }));
    });

    socket?.on("getMessage", (data) => {
      setMessages((prev) => ({
        ...prev,
        messages: [
          ...prev.messages,
          {
            user: data.user,
            message: data.message,
            fileUrl: data.fileUrl,
            fileName: data.fileName,
            fileType: data.fileType,
          },
        ],
      }));
    });
  }, [socket]);

  useEffect(() => {
    messageRef?.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages?.messages]);

  useEffect(() => {
    const loggedInUser = JSON.parse(localStorage.getItem("user:detail"));
    const fetchConversations = async () => {
      const res = await fetch(
        `https://localhost:8000/api/conversations/${loggedInUser?.id}`,
        {
          method: "GET",
          headers: {
            "Content-Type": "application/json",
          },
        }
      );
      const resData = await res.json();
      setConversations(resData);
    };
    fetchConversations();
  }, []);

  useEffect(() => {
    const fetchUsers = async () => {
      const res = await fetch(`https://localhost:8000/api/users/${user?.id}`, {
        method: "GET",
        headers: {
          "Content-Type": "application/json",
        },
      });
      const resData = await res.json();
      setUsers(resData);
    };
    fetchUsers();
  }, []);

  const handleLogout = async () => {
    // decrypt token and get id
    const token = localStorage.getItem("user:token");
    const decodedToken = jwtDecode(token);
    const userId = decodedToken.id;

    // remove user from active users
    socket?.emit("removeUser", userId);

    // remove token and user details from local storage
    localStorage.removeItem("user:token");
    localStorage.removeItem("user:detail");

    // call log out api

    const res = await fetch(`https://localhost:8000/api/logout/${userId}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
    });

    // redirect to login page

    window.location.href = "/users/sign_in";
  };

  const fetchMessages = async (conversationId, receiver) => {
    const res = await fetch(
      `https://localhost:8000/api/message/${conversationId}?senderId=${user?.id}&&receiverId=${receiver?.receiverId}`,
      {
        method: "GET",
        headers: {
          "Content-Type": "application/json",
        },
      }
    );
    const resData = await res.json();
    setMessages({ messages: resData, receiver, conversationId });

  };

  const sendMessage = async (e) => {
    setMessage("");
    const formData = new FormData();
    formData.append("conversationId", messages?.conversationId);
    formData.append("senderId", user?.id);
    formData.append("message", message);
    formData.append("receiverId", messages?.receiver?.receiverId);

    if (selectedFile) {
      formData.append("file", selectedFile);
    }

    try {
      await fetch("https://localhost:8000/api/message", {
        method: "POST",
        body: formData,
      });

      if (selectedFile) {
        socket?.emit("sendMessage", {
          senderId: user?.id,
          message: message,
          conversationId: messages?.conversationId,
          receiverId: messages?.receiver?.receiverId,
          fileUrl: selectedFile ? URL.createObjectURL(selectedFile) : null,
          fileName: selectedFile.name,
          fileType: selectedFile.type,
        });
        setTypingStatus({});
        
      } else {
        socket?.emit("sendMessage", {
          senderId: user?.id,
          message: message,
          conversationId: messages?.conversationId,
          receiverId: messages?.receiver?.receiverId,
          fileUrl: null,
          fileName: null,
          fileType: null,
        });
        setTypingStatus({});
        setSelectedFile(null);
        window.location.reload();

      }
    } catch (error) {
      console.error("Error uploading file:", error);
    }
  };

  const handleMessageChange = (e) => {
    setMessage(e.target.value);
    const isTyping = e.target.value !== "";
    socket?.emit("typing", {
      senderId: user?.id,
      receiverId: messages?.receiver?.receiverId,
      isTyping,
    });
    if (!isTyping) {
      setTypingStatus({});
    } 
  };

  const stopTyping = () => {
    socket?.emit("typing", {
      senderId: user?.id,
      receiverId: messages?.receiver?.receiverId,
      isTyping: false,
    });
    setTypingStatus({});
  };

  return (
    <div className="w-screen flex">
      <div className="w-[25%] h-screen bg-secondary overflow-scroll">
        <div className="flex items-center my-8 mx-14">
          <div>
            <img
              src={"https://ui-avatars.com/api/" + user?.fullName}
              width={75}
              height={75}
              className="border border-primary p-[2px] rounded-full"
            />
          </div>
          <div className="ml-8">
            <h3 className="text-2xl">{user?.fullName}</h3>
            <p className="text-lg font-light">My Account</p>
          </div>
          {/* logoutbutton */}
          <button
            onClick={handleLogout}
            className="ml-auto text-primary font-semibold"
          >
            Logout
          </button>
        </div>
        <hr />
        <div className="mx-14 mt-10">
          <div className="text-primary text-lg">Messages</div>
          <div>
            {conversations.length > 0 ? (
              conversations.map(({ conversationId, user }) => {
                return (
                  <div
                    className="flex items-center py-8 border-b border-b-gray-300"
                    key={conversationId}
                  >
                    <div
                      className="cursor-pointer flex items-center"
                      onClick={() => fetchMessages(conversationId, user)}
                    >
                      <div className="relative">
                        <img
                          src={"https://ui-avatars.com/api/" + user?.fullName}
                          className="w-[60px] h-[60px] rounded-full p-[2px] border border-primary"
                        />
                        {user && onlineUsersId.includes(user.receiverId) && (
                          <div className="absolute bottom-0 right-0 w-3 h-3 bg-green-500 rounded-full"></div>
                        )}
                        {user && !onlineUsersId.includes(user.receiverId) && (
                          <div className="absolute bottom-0 right-0 w-3 h-3 bg-gray-500 rounded-full"></div>
                        )}
                      </div>
                      <div className="ml-6">
                        <h3 className="text-lg font-semibold">
                          {user?.fullName}
                        </h3>
                        <p className="text-sm font-light text-gray-600">
                          {user?.email}
                        </p>
                      </div>
                    </div>
                  </div>
                );
              })
            ) : (
              <div className="text-center text-lg font-semibold mt-24">
                No Conversations
              </div>
            )}
          </div>
        </div>
      </div>
      <div className="w-[50%] h-screen bg-white flex flex-col items-center">
        {messages?.receiver?.fullName && (
          <div className="w-[75%] bg-secondary h-[80px] my-14 rounded-full flex items-center px-14 py-2">
            <div className="cursor-pointer">
              <img src={"https://ui-avatars.com/api/" + messages?.receiver?.fullName}
                 width={60} height={60} className="rounded-full" />
            </div>
            <div className="ml-6 mr-auto">
              <h3 className="text-lg">{messages?.receiver?.fullName}</h3>
              <p className="text-sm font-light text-gray-600">
                {messages?.receiver?.email}
              </p>
            </div>
            <div className="cursor-pointer">
              <svg
                xmlns="http://www.w3.org/2000/svg"
                className="icon icon-tabler icon-tabler-phone-outgoing"
                width="24"
                height="24"
                viewBox="0 0 24 24"
                strokeWidth="1.5"
                stroke="black"
                fill="none"
                strokeLinecap="round"
                strokeLinejoin="round"
              >
                <path stroke="none" d="M0 0h24v24H0z" fill="none" />
                <path d="M5 4h4l2 5l-2.5 1.5a11 11 0 0 0 5 5l1.5 -2.5l5 2v4a2 2 0 0 1 -2 2a16 16 0 0 1 -15 -15a2 2 0 0 1 2 -2" />
                <line x1="15" y1="9" x2="20" y2="4" />
                <polyline points="16 4 20 4 20 8" />
              </svg>
            </div>
          </div>
        )}
        <div className="h-[75%] w-full overflow-scroll shadow-sm">
          <div className="p-14">
            {messages?.messages?.length > 0 ? (
              messages?.messages?.map((msg, index) => (
                <div
                  key={index}
                  className={`flex ${
                    msg?.user?.id === user?.id ? "justify-end" : "justify-start"
                  } mb-4`}
                  ref={
                    index === messages?.messages?.length - 1 ? messageRef : null
                  }
                >
                  <div
                    className={`p-4 rounded-lg ${
                      msg?.user?.id === user?.id
                        ? "bg-primary text-white"
                        : "bg-light"
                    }`}
                  >
                    {msg.fileUrl ? (
                      msg.fileType.includes("image") ? (
                        <>
                          <p className="mb-3">{msg.message}</p>
                          <img
                            src={msg.fileUrl}
                            alt={msg.fileName}
                            className="max-w-xs"
                            onError={(e) => {
                              e.target.onerror = null;
                              setTimeout(() => {
                                e.target.src = msg.fileUrl;
                              }, 1000);
                            }}
                          />
                        </>
                      ) : (
                        <a href={msg.fileUrl} download={msg.fileName}>
                          {msg.fileName}
                        </a>
                      )
                    ) : (
                      msg.message
                    )}
                  </div>
                </div>
              ))
            ) : (
              <div className="text-center text-lg font-semibold mt-24">
                No Messages or No Conversation Selected
              </div>
            )}
          </div>
        </div>
        {messages?.receiver?.fullName && (
          <div className="p-14 w-full flex items-center">
            {typingStatus[messages?.receiver?.receiverId] && (
              <div className="ml-4 text-sm text-gray-500">
                {messages?.receiver?.fullName} is typing...
              </div>
            )}
            <Input
              placeholder="Type a message..."
              value={message}
              onChange={handleMessageChange}
              onBlur={stopTyping}
              className="w-[75%]"
              inputClassName="p-4 border-0 shadow-md rounded-full bg-light focus:ring-0 focus:border-0 outline-none"
            />
            <div
              id="sendMessage"
              className={`ml-4 p-2 cursor-pointer bg-light rounded-full`}
              onClick={() => sendMessage()}
            >
              <svg
                xmlns="http://www.w3.org/2000/svg"
                className="icon icon-tabler icon-tabler-send"
                width="30"
                height="30"
                viewBox="0 0 24 24"
                strokeWidth="1.5"
                stroke="#2c3e50"
                fill="none"
                strokeLinecap="round"
                strokeLinejoin="round"
              >
                <path stroke="none" d="M0 0h24v24H0z" fill="none" />
                <line x1="10" y1="14" x2="21" y2="3" />
                <path d="M21 3l-6.5 18a0.55 .55 0 0 1 -1 0l-3.5 -7l-7 -3.5a0.55 .55 0 0 1 0 -1l18 -6.5" />
              </svg>
            </div>
            <input
              type="file"
              className="hidden"
              onChange={(e) => setSelectedFile(e.target.files[0])}
              ref={(input) => (fileInputRef = input)}
            />
            <div
              id="addFile"
              className={`ml-4 p-2 cursor-pointer bg-light rounded-full
              }`}
              onClick={() => fileInputRef.click()}
            >
              <svg
                xmlns="http://www.w3.org/2000/svg"
                className="icon icon-tabler icon-tabler-circle-plus"
                width="30"
                height="30"
                viewBox="0 0 24 24"
                strokeWidth="1.5"
                stroke="#2c3e50"
                fill="none"
                strokeLinecap="round"
                strokeLinejoin="round"
              >
                <path stroke="none" d="M0 0h24v24H0z" fill="none" />
                <circle cx="12" cy="12" r="9" />
                <line x1="9" y1="12" x2="15" y2="12" />
                <line x1="12" y1="9" x2="12" y2="15" />
              </svg>
            </div>
          </div>
        )}
      </div>
      <div className="w-[25%] h-screen bg-light px-8 py-16 overflow-scroll">
        <div key={user?.id} className="text-primary text-lg">
          People
        </div>
        <div>
          {users.length > 0 ? (
            users.map(({ userId, user }) => {
              return (
                <div
                  className="flex items-center py-8 border-b border-b-gray-300"
                  key={userId}
                >
                  <div
                    className="cursor-pointer flex items-center"
                    onClick={() => fetchMessages("new", user)}
                  >
                    <div className="relative">
                      <img
                        src={"https://ui-avatars.com/api/" + user?.fullName}
                        className="w-[60px] h-[60px] rounded-full p-[2px] border border-primary"
                      />
                      {onlineUsersId.includes(user?.receiverId) && (
                        <div className="absolute bottom-0 right-0 w-3 h-3 bg-green-500 rounded-full"></div>
                      )}
                      {!onlineUsersId.includes(user?.receiverId) && (
                        <div className="absolute bottom-0 right-0 w-3 h-3 bg-gray-500 rounded-full"></div>
                      )}
                    </div>
                    <div className="ml-6">
                      <h3 className="text-lg font-semibold">
                        {user?.fullName}
                      </h3>
                      <p className="text-sm font-light text-gray-600">
                        {user?.email}
                      </p>
                    </div>
                  </div>
                </div>
              );
            })
          ) : (
            <div className="text-center text-lg font-semibold mt-24">
              No Conversations
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
