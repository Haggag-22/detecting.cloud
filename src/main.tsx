import { createRoot } from "react-dom/client";
import { HelmetProvider } from "react-helmet-async";
import App from "./App.tsx";
import "./index.css";

const rootEl = document.getElementById("root")!;
document.documentElement.classList.remove("light");
document.documentElement.classList.add("dark");
localStorage.removeItem("theme");

function showBootError(err: unknown) {
  const message = err instanceof Error ? err.stack || err.message : String(err);
  rootEl.innerHTML = `<pre style="color:#fca5a5;padding:24px;white-space:pre-wrap;font:13px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace">${message.replace(/</g, "&lt;")}</pre>`;
}

try {
  createRoot(rootEl).render(
    <HelmetProvider>
      <App />
    </HelmetProvider>,
  );
} catch (err) {
  showBootError(err);
}
