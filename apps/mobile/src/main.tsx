import React from "react";
import ReactDOM from "react-dom/client";
import MobileApp from "./MobileApp";
import { LanguageSwitcher, LocaleProvider } from "./locale";
import { installSafeAreaInsets } from "./utils/safeArea";
import "./mobile.css";

installSafeAreaInsets();

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <LocaleProvider>
      <LanguageSwitcher />
      <MobileApp />
    </LocaleProvider>
  </React.StrictMode>,
);