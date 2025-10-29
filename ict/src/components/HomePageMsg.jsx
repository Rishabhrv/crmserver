// src/components/HomePageMsg.jsx
import React, { useState, useEffect, useRef } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import {
  faBars,
  faBold,
  faItalic,
  faStrikethrough,
  faLink,
  faListUl,
  faListOl,
  faPlus,
  faFaceSmile,
  faAt,
  faFile,
  faCircleDown,
} from "@fortawesome/free-solid-svg-icons";
import Backimage from "./faf22eaf-7d73-4f8b-9dc2-c60cf5387878.jpg";
import { createSocket, getSocket } from "../socket";
import ChatUserInfo from "./ChatUserInfo";

const HomePageMsg = ({ token, conversation, user }) => {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState("");
  const socketRef = useRef(null);
  const messagesRef = useRef(null);
   const [showInfo, setShowInfo] = useState(false);

   

const handleFileChange = async (e) => {
  const file = e.target.files[0];
  if (!file) return;


  // Upload to backend
  const formData = new FormData();
  formData.append("file", file);

  try {
    const res = await fetch("http://localhost:5001/upload_file", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
      },
      body: formData,
    });
    const data = await res.json();

    if (res.ok && data.url) {
      const s = getSocket();
      const payload = {
  token,
  conversation_id: conversation.id,
  message: data.url,
  message_type: file.type.startsWith("image/") ? "image" : "file", // ✅ correct key
};

      s.emit("send_message", payload);
    } else {
      console.error("File upload failed:", data);
    }
  } catch (err) {
    console.error("Upload error:", err);
  }
};


  // ✅ Helper to convert UTC → IST
  const toIST = (dateStr) => {
    if (!dateStr) return new Date();
    return new Date(new Date(dateStr).getTime() - 5.5 * 60 * 60 * 1000);
  };


  // ✅ Initialize socket
  useEffect(() => {
    if (!token) return;
    const s = createSocket(token);
    socketRef.current = s;

    s.on("connect", () => {
      // console.log("Socket connected");
    });

    // ✅ Handle new messages safely
    s.on("new_message", (msg) => {
      if (conversation && msg.conversation_id === conversation.id) {
        setMessages((prev) => {
          const exists = prev.some((m) => {
            const mIST = toIST(m.timestamp);
            const msgIST = toIST(msg.timestamp);
            return (
              m.message === msg.message &&
              m.sender_id === msg.sender_id &&
              Math.abs(mIST - msgIST) < 2000
            );
          });
          return exists ? msg : [...prev, msg];
        });
      }
    });

    s.on("auth_error", (d) => {
      console.error("socket auth error", d);
    });

    return () => {
      if (s) s.off("new_message");
    };
  }, [token, conversation]);

  // ✅ Fetch messages when conversation changes
  useEffect(() => {
    if (!conversation) {
      setMessages([]);
      return;
    }

    fetch(`http://localhost:5001/messages/${conversation.id}`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((r) => r.json())
      .then((data) => setMessages(data))
      .catch((err) => console.error(err));

    const s = getSocket();
    if (s && conversation) s.emit("join", { token, conversation_id: conversation.id });

    return () => {
      if (s && conversation) s.emit("leave", { conversation_id: conversation.id });
    };
  }, [conversation, token]);

  // ✅ Auto-scroll when new messages arrive
  useEffect(() => {
    if (messagesRef.current) {
      messagesRef.current.scrollTop = messagesRef.current.scrollHeight;
    }
  }, [messages]);

  // ✅ Send message
  const sendMessage = () => {
    if (!input.trim() || !conversation) return;
    const s = getSocket();
    const payload = {
  token,
  conversation_id: conversation.id,
  message: input.trim(),
  message_type: "text",  // ✅ add message_type
};

    if (s) {
      s.emit("send_message", payload);
      setInput("");
    } else {
      console.error("Socket not connected");
    }
  };

    // ✅ If no conversation selected, show empty state
  if (!conversation) {
    return (
      <div className="flex flex-col w-full items-center justify-center text-gray-500 text-center h-full my-auto py-auto">
        <p className="text-lg font-semibold">No conversation selected</p>
        <p className="text-sm text-gray-400">
          Select a user from the left to start chatting 💬
        </p>
      </div>
    );
  }

  return (
    <div className="flex w-full p-2 ml-5">
      <div className="w-full">
        {/* Header */}
        <div className="flex border-b border-gray-200 py-3 justify-between">
          <div className="flex">
            <div className="bg-gray-200 p-2 rounded-full px-3">
              <h1 className="font-semibold text-gray-500 text-lg">
  {conversation
    ? (conversation.other_username || conversation.username || "U")[0].toUpperCase()
    : "U"}
</h1>
            </div>
            <div className="p-1 pl-3">
              <h3 className="text-sm font-semibold text-gray-600">
  {conversation
    ? conversation.other_username || conversation.username || "No conversation selected"
    : "No conversation selected"}
</h3>
              <p className="text-xs">Online</p>
            </div>
          </div>
          <div
        className="p-2 cursor-pointer hover:text-gray-600"
        onClick={() => setShowInfo(!showInfo)}
      >
        <FontAwesomeIcon icon={faBars} />
      </div>
        </div>

        {/* Messages */}
        <div
          style={{
            backgroundImage: `url(${Backimage})`,
            backgroundSize: "cover",
            backgroundPosition: "center",
            width: "100%",
          }}
          className="h-105 pt-4 overflow-y-auto p-4 hide-scrollbar"
          ref={messagesRef}
        >
          {messages.map((msg, idx) => {
  const mine = msg.sender_id === user?.id;



  return (
    <div
      key={idx}
      className={`flex ${mine ? "justify-end" : "justify-start"} mb-2`}
    >
      <div
        className={`${
          mine ? "bg-gray-200" : "bg-blue-200"
        } w-fit max-w-xs p-2 rounded-lg shadow-lg`}
      >
        {(() => {
  const fileUrl = msg.message;
  const fileName = fileUrl.split("/").pop();
  const isImage = msg.message_type === "image" || /\.(jpg|jpeg|png|gif|webp)$/i.test(fileUrl);
  const isFile = msg.message_type === "file" || /\.(pdf|docx?|txt|zip|rar)$/i.test(fileUrl);

  if (isImage) {
    return (
      <div className="relative group">
        <img
          src={fileUrl}
          alt="sent"
          className="max-w-[200px] rounded-lg cursor-pointer transition-transform duration-200 group-hover:scale-[1.03]"
          onClick={() => window.open(fileUrl, "_blank")}
        />
        <button
  onClick={async () => {
    if (!fileUrl) return;
    try {
      const response = await fetch(fileUrl, { mode: "cors" });
      const blob = await response.blob();
      const blobUrl = window.URL.createObjectURL(blob);

      const link = document.createElement("a");
      link.href = blobUrl;
      link.download = fileName || "download";
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);

      // Clean up the blob URL
      window.URL.revokeObjectURL(blobUrl);
    } catch (error) {
      console.error("Download failed:", error);
    }
  }}
  className="absolute bottom-1 right-1 text-gray-500 rounded-md text-lg opacity-0 group-hover:opacity-100 transition"
>
  <FontAwesomeIcon icon={faCircleDown} />
</button>

      </div>
    );
  } else if (isFile) {
    return (
      <div className="bg-white flex items-center space-x-3 border border-gray-300 rounded-lg p-2">
        <div className="bg-gray-200 w-8 h-8 flex items-center justify-center rounded-full text-sm">
          <FontAwesomeIcon icon={faFile} className="text-gray-500"/>
        </div>
        <div className="flex-1">
          <p className="text-xs font-semibold text-gray-800 w-32 break-words whitespace-normal">
            {fileName}
          </p>
          <button
            onClick={() => {
              const a = document.createElement("a");
              a.href = fileUrl;
              a.download = fileName;
              a.click();
            }}
            className="text-[10px] text-blue-600"
          >
            Download
          </button>
        </div>
      </div>
    );
  } else {
    return <p className="text-sm text-gray-800 break-words">{msg.message}</p>;
  }
})()}


        <p className="text-right text-[9px] pt-1">
          {(() => {
            const ts = msg.timestamp;
            const match = ts?.match(/\d{2}:\d{2}:\d{2}/);
            if (!match) return "";
            const [h, m] = match[0].split(":").map(Number);
            let hours = h;
            const ampm = hours >= 12 ? "PM" : "AM";
            hours = hours % 12 || 12;
            return `${hours.toString().padStart(2, "0")}:${m
              .toString()
              .padStart(2, "0")} ${ampm}`;
          })()}
        </p>
      </div>
    </div>
  );
})}

        </div>

        {/* Input Box */}
        <div className="w-full border border-gray-300 rounded-lg bg-white shadow-sm pb-2 mt-2">
          <div className="flex items-center space-x-2 text-gray-600 bg-gray-100 mb-2 p-2">
            <button className="font-bold">
              <FontAwesomeIcon icon={faBold} />
            </button>
            <button className="italic">
              <FontAwesomeIcon icon={faItalic} />
            </button>
            <button className="line-through">
              <FontAwesomeIcon icon={faStrikethrough} />
            </button>
            <span>|</span>
            <button>
              <FontAwesomeIcon icon={faLink} />
            </button>
            <button>
              <FontAwesomeIcon icon={faListUl} />
            </button>
            <button>
              <FontAwesomeIcon icon={faListOl} />
            </button>
          </div>

          <textarea
            className="w-full h-12 outline-none resize-none text-sm px-2"
            placeholder="Type a message..."
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                sendMessage();
              }
            }}
          />

          <div className="flex justify-between items-center mt-2 text-gray-600 px-2 pb-2">
            <div className="flex space-x-3">
  <label className="bg-gray-200 rounded-full font-semibold text-sm px-1 shadow-sm cursor-pointer">
    <FontAwesomeIcon icon={faPlus} />
    <input
      type="file"
      className="hidden"
      onChange={handleFileChange}
      accept="image/*,application/pdf,application/msword,application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    />
  </label>
  <button>Aa</button>
  <button>
    <FontAwesomeIcon icon={faFaceSmile} />
  </button>
  <button>
    <FontAwesomeIcon icon={faAt} />
  </button>
</div>

            <div className="flex items-center space-x-2">
              <button
                onClick={sendMessage}
                className="bg-gray-600 rounded-lg shadow-ms px-2 text-white"
              >
                ▶ Send
              </button>
            </div>
          </div>
        </div>
      </div>
      {showInfo && (
        <div className="mt-2 z-10">
          <ChatUserInfo />
        </div>
      )}


    </div>
  );
};

export default HomePageMsg;
