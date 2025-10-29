// src/components/Slidebar.jsx
import React from "react";
import { Link } from "react-router-dom";
import "../css/SlideBar.css";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faHouseChimney, faComment, faUserGroup } from "@fortawesome/free-solid-svg-icons";

const Slidebar = ({ user }) => {
  return (
   <div className="SliderBar w-17 bg-gray-50 h-screen m-2 mb-0 rounded-lg text-center pt-5 flex flex-col justify-between">
  {/* --- Top section --- */}
  <div>
    <Link to="/chatapp">
      <div className="bg-gray-500 p-2 m-3 rounded-lg hover:bg-gray-600 transition">
        <FontAwesomeIcon className="icon text-white" icon={faHouseChimney} />
      </div>
    </Link>

    <Link to="/chats">
      <div className="bg-gray-500 p-2 m-3 rounded-lg mt-5 hover:bg-gray-600 transition">
        <FontAwesomeIcon className="icon text-white" icon={faComment} />
      </div>
    </Link>

    <Link to="/chatgroup">
      <div className="bg-gray-500 p-2 m-3 rounded-lg mt-5 hover:bg-gray-600 transition">
        <FontAwesomeIcon className="icon text-white" icon={faUserGroup} />
      </div>
    </Link>
  </div>

  {/* --- Bottom section (User info) --- */}
  <div className="mb-6">
    {user ? (
      <div>
        <div className="text-sm font-semibold uppercase bg-gray-200 py-3 m-2 rounded-full">
          {user.username ? user.username.slice(0, 2) : ""}
        </div>
      </div>
    ) : (
      <div className="text-sm text-gray-400">Not logged</div>
    )}
  </div>
</div>

  );
};

export default Slidebar;
