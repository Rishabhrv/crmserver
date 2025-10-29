import React, { useState, useEffect } from "react";
import Slidebar from "../components/Slidebar";
import HomePageUsers from "../components/HomePageUsers";
import HomePageMsg from "../components/HomePageMsg";

const FLASK_AUTH_URL = "http://localhost:5001/auth/validate_and_details";
const FLASK_LOGIN_URL = "http://localhost:5001/login";

// ✅ Allowed roles and apps
const VALID_ROLES = ["admin", "user"];
const VALID_APPS = {
  Main: "main",
  Operations: "operations",
  IJISEM: "ijisem",
  Tasks: "tasks",
  Sales: "sales",
  Clone: "clone",
};

const VALID_ACCESS = {
    // Loop buttons (table)
    "ISBN": "manage_isbn_dialog",
    "Payment": "manage_price_dialog",
    "Authors": "edit_author_dialog",
    "Operations": "edit_operation_dialog",
    "Printing & Delivery": "edit_inventory_delivery_dialog",
    "DatadashBoard": "datadashoard",
    "Advance Search": "advance_search",
    "Team Dashboard": "team_dashboard",
    "Print Management": "print_management",
    "Inventory": "inventory",
    "Open Author Positions": "open_author_positions",
    "Pending Work": "pending_books",
    "IJISEM": "ijisem",
    "Tasks": "tasks",
    "Details": "details",
    "Message": "messages",
    // Non-loop buttons
    "Add Book": "add_book_dialog",
    "Authors Edit": "edit_author_detail"
};

// ✅ Helper to redirect to login
const redirectToLogin = (message) => {
  console.warn("Redirecting:", message);
  localStorage.removeItem("token");
  alert(message || "Authentication failed. Please log in again.");
  window.location.href = FLASK_LOGIN_URL;
};

const HomePage = () => {
  const [token, setToken] = useState(localStorage.getItem("token"));
  const [user, setUser] = useState(null);
  const [selectedConv, setSelectedConv] = useState(null);

  // ✅ Main token + user validation logic
  const validateToken = async (activeToken) => {
    try {
      const res = await fetch(FLASK_AUTH_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: activeToken }),
      });

      if (!res.ok) {
        redirectToLogin("Authentication server not reachable.");
        return;
      }

      const data = await res.json();
      if (!data.valid) {
        redirectToLogin(`Invalid token: ${data.error || "Unknown error"}`);
        return;
      }

      // ✅ Extract user details
      const userDetails = data.user_details || {};
      const role = (userDetails.role || "").toLowerCase();
      const app = (userDetails.app || "").toLowerCase();
      let access = userDetails.access || [];
      if (typeof access === "string") access = access ? [access] : [];

      // ✅ Role validation
      if (!VALID_ROLES.includes(role)) {
        redirectToLogin(`Access denied: Invalid role '${role}'.`);
        return;
      }

      // ✅ App validation (non-admin only)
      if (role !== "admin") {
        const validApps = Object.values(VALID_APPS);
        if (!validApps.includes(app)) {
          redirectToLogin(`Access denied: Invalid app '${app}'.`);
          return;
        }

        // ✅ App-specific access validation
        if (app === "main") {
          if (!access.every((a) => Object.keys(VALID_ACCESS).includes(a))) {
            redirectToLogin(`Invalid access for main app: ${access.join(", ")}`);
            return;
          }
        } else if (app === "operations") {
          const VALID_ACCESS = [ 
            "writer",
            "proofreader",
            "formatter",
            "cover_designer",
          ];
          if (!(access.length === 1 && VALID_ACCESS.includes(access[0]))) {
            redirectToLogin(`Invalid access for operations app: ${access.join(", ")}`);
            return;
          }
        } else if (app === "ijisem") {
          if (!(access.length === 1 && access[0] === "Full Access")) {
            redirectToLogin(`Invalid access for IJISEM app: ${access.join(", ")}`);
            return;
          }
        }
      }

      // ✅ Token is valid → set user
      setUser({
        id: data.user_id,
        ...userDetails,
      });

    } catch (err) {
      console.error("Token validation failed:", err);
      redirectToLogin("Access denied: Token validation failed.");
    }
  };

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const urlToken = params.get("token");
    const activeToken = urlToken || localStorage.getItem("token");

    if (urlToken) {
      localStorage.setItem("token", urlToken);
      setToken(urlToken);
    } else if (activeToken) {
      setToken(activeToken);
    } else {
      redirectToLogin("Access denied: No token provided.");
      return;
    }

    // Validate the token
    validateToken(activeToken);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

// ✅ Decode JWT (client-side)
const decodeJWT = (token) => {
  try {
    const base64Url = token.split(".")[1];
    const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split("")
        .map((c) => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2))
        .join("")
    );
    return JSON.parse(jsonPayload);
  } catch (e) {
    return null;
  }
};

// ✅ Token expiry check — uses JWT exp (IST-based)
const checkTokenExpiry = (token) => {
  const payload = decodeJWT(token);
  if (!payload) {
    redirectToLogin("Invalid token structure.");
    return true;
  }

  // 🕓 Convert UTC → IST (UTC + 5.5 hours)
  const IST_OFFSET = 5.5 * 60 * 60 * 1000; // milliseconds

  const nowIST = Date.now() + IST_OFFSET;
  const expIST = (payload.exp || 0) * 1000 + IST_OFFSET;

  // 🧭 Compare current time to exp
  if (nowIST > expIST) {
    const expTime = new Date(expIST).toLocaleString("en-IN", {
      timeZone: "Asia/Kolkata",
    });
    console.log(`Token expired at ${expTime} IST`);
    redirectToLogin("Token expired. Please log in again.");
    return true;
  }

  return false;
};

// ✅ Example usage (in useEffect or validation)
if (checkTokenExpiry(token)) return;


  if (!token || !user) {
    return (
      <div className="flex items-center justify-center h-screen">
        <h2 className="text-gray-600 text-xl font-semibold">
          Validating your session...
        </h2>
      </div>
    );
  }

  return (
    <div className="flex">
      <Slidebar user={user} />
      <HomePageUsers
        token={token}
        onSelectConversation={(conv) => setSelectedConv(conv)}
        user={user}
      />
      <HomePageMsg token={token} conversation={selectedConv} user={user} />
    </div>
  );
};

export default HomePage;
