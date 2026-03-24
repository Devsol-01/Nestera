import React from "react";
import Sidebar from "../components/dashboard/Sidebar";
import TopNav from "../components/dashboard/TopNav";

export const metadata = {
  title: "Dashboard - Nestera",
};

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="block bg-[#061218] min-h-screen overflow-x-hidden">
      <Sidebar />

      {/* Responsive margin: no margin on mobile, 180px on md+ to clear the fixed sidebar */}
      <div className="min-h-screen px-4 py-5 md:ml-[180px] md:px-6 max-w-full">
        <TopNav />
        <div className="mt-2">{children}</div>
      </div>
    </div>
  );
}
