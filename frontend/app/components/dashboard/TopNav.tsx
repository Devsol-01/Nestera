"use client";

import React from "react";
import { Search, Bell, HelpCircle } from "lucide-react";

const TopNav: React.FC = () => {
  return (
    <header
      className="sticky top-0 right-0 flex items-center justify-between bg-transparent z-40 backdrop-blur-sm px-0 md:px-6"
      style={{ height: 64 }}
    >
      {/* Left: heading + subtitle */}
      <div className="hidden sm:flex flex-col gap-0.5">
        <h2
          className="m-0 text-white font-bold leading-none"
          style={{ fontSize: 22 }}
        >
          Welcome back, Alex
        </h2>
        <p className="m-0 text-[#4e8a96]" style={{ fontSize: 13 }}>
          Here&apos;s your financial overview
        </p>
      </div>

      {/* Right: icons + avatar */}
      <div className="flex items-center ml-auto" style={{ gap: 10 }}>
        {[
          { Icon: Search, label: "Search" },
          { Icon: Bell, label: "Notifications" },
          { Icon: HelpCircle, label: "Help" },
        ].map(({ Icon, label }) => (
          <button
            key={label}
            aria-label={label}
            className="flex items-center justify-center text-[#6a9fae] cursor-pointer hover:text-white transition-colors bg-[#0e2330] border border-white/8 rounded-xl"
            style={{ width: 38, height: 38 }}
          >
            <Icon size={16} />
          </button>
        ))}

        {/* Avatar */}
        <div
          className="rounded-full bg-linear-to-b from-[#08c1c1] to-[#0fa3a3] flex items-center justify-center font-bold text-[#021515] select-none"
          style={{ width: 38, height: 38, fontSize: 15, marginLeft: 4 }}
        >
          A
        </div>
      </div>
    </header>
  );
};

export default TopNav;
