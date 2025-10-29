// src/components/HomePageUsers.jsx
import React, { useEffect, useState } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faPlus } from "@fortawesome/free-solid-svg-icons";

const HomePageUsers = ({ token, onSelectConversation, user }) => {
  const [convos, setConvos] = useState([]);
  const [searchTerm, setSearchTerm] = useState("");
  const [searchResults, setSearchResults] = useState([]);
  const [loading, setLoading] = useState(false);

  // 🔹 Fetch existing conversations
  useEffect(() => {
    fetch("http://localhost:5001/conversations", {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((r) => r.json())
      .then((data) => {
        if (Array.isArray(data)) {
          const formatted = data.map((c) => ({ ...c, hasConversation: true }));
          setConvos(formatted);
        } else {
          setConvos([]);
        }
      })
      .catch((err) => {
        console.error("Error fetching conversations:", err);
        setConvos([]);
      });
  }, [token]);

  // 🔹 Handle search
  useEffect(() => {
    if (!searchTerm.trim()) {
      setSearchResults([]);
      return;
    }

    setLoading(true);
    const timer = setTimeout(() => {
      fetch(
        `http://localhost:5001/users?search=${encodeURIComponent(searchTerm)}`,
        {
          headers: { Authorization: `Bearer ${token}` },
        }
      )
        .then((r) => r.json())
        .then((data) => {
          const userList = Array.isArray(data) ? data : [];
          const existingUsernames = new Set(
            convos.map((c) => c.other_username)
          );

          // ✅ Mark if user already has a conversation
          const results = userList.map((u) => ({
            ...u,
            hasConversation: existingUsernames.has(u.username),
          }));
          setSearchResults(results);
        })
        .catch((err) => console.error("Search error:", err))
        .finally(() => setLoading(false));
    }, 400);

    return () => clearTimeout(timer);
  }, [searchTerm, convos, token]);

  const listToShow = searchTerm ? searchResults : convos;

  // 🔹 Create new conversation
  const createConversation = async (otherUserId) => {
    try {
      const res = await fetch("http://localhost:5001/createConversation", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          user1_id: user.id,
          user2_id: otherUserId,
        }),
      });

      const data = await res.json();
      if (data.success) {
        alert("Conversation created!");
        // ✅ Add new convo to list
        setConvos((prev) => [
          ...prev,
          { ...data.conversation, hasConversation: true },
        ]);
        setSearchTerm("");

        // Optional: directly open the chat without reload
        onSelectConversation(data.conversation);

        // Or if you prefer hard reload:
         window.location.reload();
      } else {
        alert("Failed to create conversation.");
      }
    } catch (err) {
      console.error("Error creating conversation:", err);
    }
  };

  return (
    <div className="ml-4 w-72">
      {/* 🔍 Search Bar */}
      <div className="flex items-center bg-white rounded-2xl shadow-sm px-3 py-2 w-74 mt-4">
        <input
          type="text"
          className="w-full outline-none text-gray-700 placeholder-gray-400"
          placeholder="Search Users & Groups"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
        />
      </div>

      {/* 💬 Conversation/User List */}
      <div className="mt-4">
        {loading && <div className="p-4 text-gray-500">Searching...</div>}

        {Array.isArray(listToShow) && listToShow.length > 0 ? (
          listToShow.map((c) => (
            <div
              key={c.id || c.user_id}
              onClick={() => {
                if (c.hasConversation) {
                  // ✅ If already has conversation, open chat directly
                  const convo = convos.find(
                    (conv) =>
                      conv.other_username === c.username ||
                      conv.other_user_id === c.id
                  );
                  if (convo) {
                    onSelectConversation(convo);
                  } else {
                    // If user is from search results but has convo
                    onSelectConversation(c);
                  }
                }
              }}
              className="flex items-center border-b border-gray-200 py-3 cursor-pointer hover:bg-gray-50 transition-colors"
            >
              <div className="bg-gray-200 p-2 rounded-full px-3 mr-3 flex items-center justify-center">
                <h1 className="font-semibold text-gray-500">
                  {(c.other_username || c.username)?.[0]?.toUpperCase() || "U"}
                </h1>
              </div>

              <div className="flex-1">
                <h3 className="text-sm font-semibold text-gray-600">
                  {c.other_username || c.username}
                </h3>
                <p className="text-xs text-gray-500">
                  {c.last_message
                    ? c.last_message
                    : c.email
                    ? c.email
                    : "No messages yet"}
                </p>
              </div>

              {/* ✅ Add conversation button if no conversation exists */}
              {!c.hasConversation && (
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    createConversation(c.id);
                  }}
                  className="text-green-600 hover:text-green-800"
                  title="Start Conversation"
                >
                  <FontAwesomeIcon icon={faPlus} />
                </button>
              )}
            </div>
          ))
        ) : (
          !loading && (
            <div className="p-4 text-gray-500 text-sm">No users found</div>
          )
        )}
      </div>
    </div>
  );
};

export default HomePageUsers;
