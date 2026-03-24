"use client";

import React from "react";

const NetWorthCard: React.FC = () => {
  return (
    <div
      style={{
        position: "relative",
        background:
          "linear-gradient(180deg, rgba(4,20,22,0.85), rgba(6,18,20,0.75))",
        border: "1px solid rgba(6,110,110,0.15)",
        borderRadius: "18px",
        padding: "28px",
        color: "#e6ffff",
        overflow: "hidden",
        minHeight: "160px",
        boxShadow: "0 10px 30px rgba(2,12,14,0.6)",
        backdropFilter: "blur(6px)",
      }}
    >
      {/* Wave SVG sits at the back */}
      <svg
        style={{
          position: "absolute",
          right: "-30px",
          top: 0,
          width: "84%",
          height: "110%",
          opacity: 0.55,
          zIndex: 0,
          pointerEvents: "none",
        }}
        viewBox="0 0 600 200"
        preserveAspectRatio="none"
        aria-hidden
      >
        <defs>
          <linearGradient id="g1" x1="0" x2="1">
            <stop offset="0%" stopColor="#07c1c1" stopOpacity="0.22" />
            <stop offset="100%" stopColor="#083b3b" stopOpacity="0.06" />
          </linearGradient>
        </defs>
        <path
          d="M0,80 C150,200 350,0 600,80 L600,200 L0,200 Z"
          fill="url(#g1)"
        />
      </svg>

      {/* Content on top */}
      <div style={{ position: "relative", zIndex: 1 }}>
        <div className="flex justify-between items-center">
          <div className="text-xs text-[#9bb7b7] font-semibold tracking-wide">
            TOTAL NET WORTH
          </div>
          <div
            style={{
              background:
                "linear-gradient(90deg, rgba(3,116,116,0.22), rgba(6,140,140,0.14))",
            }}
            className="px-3 py-2 rounded-2xl font-bold text-[#8ef4ef] inline-flex gap-2 items-center text-sm"
          >
            + $1,240.50{" "}
            <span className="text-[#cfe] text-xs font-semibold">(+5.4%)</span>
          </div>
        </div>

        <div className="text-5xl font-extrabold mt-3 tracking-tight text-white">
          $24,593.82
        </div>

        <div className="mt-2 text-[#95b7b7] text-sm">vs last month</div>
      </div>
    </div>
  );
};

export default NetWorthCard;
