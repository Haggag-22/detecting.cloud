import { useState, useCallback, useRef, useEffect } from "react";
import { Footer } from "@/components/Footer";
import { AppSidebar } from "@/components/AppSidebar";
import { SidebarProvider } from "@/components/ui/sidebar";

const MIN_WIDTH = 220;
const MAX_WIDTH = 500;
const DEFAULT_WIDTH = 272;

export function Layout({ children }: { children: React.ReactNode }) {
  const [sidebarWidth, setSidebarWidth] = useState(DEFAULT_WIDTH);
  const isResizing = useRef(false);

  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    isResizing.current = true;
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";
  }, []);

  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      if (!isResizing.current) return;
      const newWidth = Math.min(MAX_WIDTH, Math.max(MIN_WIDTH, e.clientX));
      setSidebarWidth(newWidth);
    };
    const handleMouseUp = () => {
      if (isResizing.current) {
        isResizing.current = false;
        document.body.style.cursor = "";
        document.body.style.userSelect = "";
      }
    };
    window.addEventListener("mousemove", handleMouseMove);
    window.addEventListener("mouseup", handleMouseUp);
    return () => {
      window.removeEventListener("mousemove", handleMouseMove);
      window.removeEventListener("mouseup", handleMouseUp);
    };
  }, []);

  return (
    <SidebarProvider>
      <div
        className="min-h-screen flex w-full"
        style={{ "--sidebar-width": `${sidebarWidth}px` } as React.CSSProperties}
      >
        <AppSidebar />
        <div
          onMouseDown={handleMouseDown}
          className="relative shrink-0 w-1 cursor-col-resize z-30 hover:bg-primary/30 transition-colors"
        />
        <div className="flex min-w-0 flex-1 flex-col overflow-x-hidden">
          <main className="min-w-0 flex-1">{children}</main>
          <Footer />
        </div>
      </div>
    </SidebarProvider>
  );
}
