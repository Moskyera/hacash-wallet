import React from "react";
import ReactDOM from "react-dom/client";
import MobileApp from "./MobileApp";
import { installSafeAreaInsets } from "./utils/safeArea";
import "./mobile.css";

installSafeAreaInsets();

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <MobileApp />
  </React.StrictMode>,
);