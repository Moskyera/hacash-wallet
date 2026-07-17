import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { LanguageSwitcher, LocaleProvider } from "./locale";
import "./styles.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <LocaleProvider>
      <LanguageSwitcher />
      <App />
    </LocaleProvider>
  </React.StrictMode>,
);