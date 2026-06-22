import { createRoot } from "react-dom/client";
import App from "./App";
// JetBrains Mono vendored locally (no CDN → fully offline, no third-party request).
import "@fontsource/jetbrains-mono/400.css";
import "@fontsource/jetbrains-mono/500.css";
import "@fontsource/jetbrains-mono/600.css";
import "@fontsource/jetbrains-mono/700.css";
import "@xterm/xterm/css/xterm.css";
import "./style.css";

createRoot(document.getElementById("root")!).render(<App />);
