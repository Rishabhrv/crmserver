// src/App.jsx
import "./App.css";
import { BrowserRouter as Router, Routes, Route} from "react-router-dom";
import HomePage from "./Pages/HomePage";
import ClonePage from "./Pages/ClonePage";

function AppRoutes() {

  return (
    <Routes>
      <Route path="/chat" element={<HomePage />} />
      <Route path="/clone" element={<ClonePage />} />
    </Routes>
  );
}

function App() {
  return (
    <Router>
      <AppRoutes />
    </Router>
  );
}

export default App;
