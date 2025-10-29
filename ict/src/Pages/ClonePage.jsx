import React, { useState, useEffect } from "react";

const ClonePage = () => {
  const [token, setToken] = useState(localStorage.getItem("token"));
  const [user, setUser] = useState(null);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const urlToken = params.get("token");

    const activeToken = urlToken || localStorage.getItem("token");

    if (urlToken) {
      localStorage.setItem("token", urlToken);
      setToken(urlToken);
    } else if (activeToken) {
      setToken(activeToken);
    }

    // ✅ If no token found → redirect to login
    if (!activeToken) {
      window.location.href = "http://localhost:5001/login";
      return;
    }

    // ✅ Validate token and get user details
    fetch("http://localhost:5001/auth/validate_and_details", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: activeToken }),
    })
      .then((res) => res.json())
      .then((data) => {
        if (data.valid) {
          setUser({
            id: data.user_id,
            ...data.user_details,
          });
        } else {
          console.warn("Token invalid:", data.error);
          localStorage.removeItem("token");
          window.location.href = "http://localhost:5001/login";
        }
      })
      .catch((err) => {
        console.error("Failed to fetch user details:", err);
        localStorage.removeItem("token");
        window.location.href = "http://localhost:5001/login";
      });
  }, []);

  useEffect(() => {
    console.log("🧍‍♂️ Current logged-in user:", user);
  }, [user]);

  if (!token || !user) {
    return (
      <div className="flex items-center justify-center h-screen">
        <h2 className="text-gray-600 text-xl font-semibold">
          Loading user info...
        </h2>
      </div>
    );
  }

  // ✅ Button click handler
  const goToChatApp = () => {
    const redirectUrl = `http://localhost:3000/chat?token=${token}`;
    window.location.href = redirectUrl;
  };

  return (
    <div className="flex items-center justify-center h-screen">
      <button
        onClick={goToChatApp}
        className="bg-blue-600 text-white px-6 py-3 rounded-lg shadow-md hover:bg-blue-700 transition"
      >
       ChatApp
      </button>
    </div>
  );
};

export default ClonePage;
