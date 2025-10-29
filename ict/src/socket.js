// src/socket.js
import { io } from "socket.io-client";

let socket = null;

export function createSocket(token) {
  if (socket) return socket;
  socket = io("http://localhost:5001", {
    transports: ["websocket", "polling"],
    autoConnect: true,
    // we'll authenticate after connect via event
  });

  // after connect, emit authenticate with token
  socket.on("connect", () => {
    if (token) {
      socket.emit("authenticate", { token });
    }
  });

  return socket;
}

export function getSocket() {
  return socket;
}
