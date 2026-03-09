import { Navbar } from "@/components/Navbar";
import { Footer } from "@/components/Footer";
import { AppSidebar } from "@/components/AppSidebar";
import { SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar";
import { useLocation } from "react-router-dom";

const pagesWithSidebar = ["/research", "/attack-paths", "/detection-engineering", "/attack-graph"];

export function Layout({ children }: { children: React.ReactNode }) {
  const location = useLocation();
  const showSidebar = pagesWithSidebar.some((p) => location.pathname.startsWith(p));

  if (!showSidebar) {
    return (
      <div className="min-h-screen flex flex-col">
        <Navbar />
        <main className="flex-1 pt-16">{children}</main>
        <Footer />
      </div>
    );
  }

  return (
    <SidebarProvider>
      <div className="min-h-screen flex w-full">
        <AppSidebar />
        <div className="flex-1 flex flex-col min-w-0">
          <Navbar showSidebarTrigger />
          <main className="flex-1 pt-16">{children}</main>
          <Footer />
        </div>
      </div>
    </SidebarProvider>
  );
}
