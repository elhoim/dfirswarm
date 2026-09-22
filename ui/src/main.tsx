import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { TooltipProvider } from "@/components/ui/tooltip";
import { LiveProvider } from "@/lib/live";
import { App } from "./App";
import "./index.css";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <BrowserRouter>
      <LiveProvider>
        <TooltipProvider delayDuration={250}>
          <App />
        </TooltipProvider>
      </LiveProvider>
    </BrowserRouter>
  </StrictMode>,
);
