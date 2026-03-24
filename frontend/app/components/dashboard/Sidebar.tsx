"use client";

import React, { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Menu,
  X,
  Home,
  PieChart,
  ShieldCheck,
  Settings,
  Landmark,
  TrendingUp,
  Copy,
  LayoutGrid,
} from "lucide-react";

const navLinks = [
  { label: "Dashboard", href: "/dashboard", icon: Home },
  { label: "Savings Pools", href: "/dashboard/savings-pools", icon: Landmark },
  { label: "Staking", href: "/dashboard/staking", icon: TrendingUp },
  { label: "Analytics", href: "/dashboard/analytics", icon: PieChart },
  { label: "Governance", href: "/dashboard/governance", icon: ShieldCheck },
  { label: "Settings", href: "/dashboard/settings", icon: Settings },
];

const Sidebar: React.FC = () => {
  const pathname = usePathname();
  const [open, setOpen] = useState(false);

  const isActive = (href: string) => {
    if (!pathname) return false;
    if (href === "/dashboard") return pathname === "/dashboard";
    return pathname === href || pathname.startsWith(href + "/");
  };

  return (
    <>
      {open && (
        <div
          className="fixed inset-0 bg-black/50 z-40 md:hidden"
          onClick={() => setOpen(false)}
        />
      )}

      <aside
        aria-label="Sidebar"
        style={{ width: 200, minWidth: 180 }}
        className={[
          "fixed left-0 top-0 h-screen z-50",
          "flex flex-col",
          "bg-[#0d1f28] text-[#d6f6f6]",
          "transition-transform duration-250 ease-in-out",
          open ? "translate-x-0" : "-translate-x-full md:translate-x-0",
        ].join(" ")}
      >
        {/* Logo */}
        <div className="flex items-center justify-between px-4 pt-5 pb-6">
          <Link
            href="/dashboard"
            className="flex items-center gap-2.5 no-underline text-inherit"
          >
            <div className="w-9 h-9 rounded-xl bg-[#0d4f4f] flex items-center justify-center text-[#08c1c1]">
              <LayoutGrid size={18} />
            </div>
            <span className="font-bold text-[15px] text-white">Nestera</span>
          </Link>

          <button
            className="md:hidden bg-transparent border-0 text-[#9aa9b1] cursor-pointer"
            onClick={() => setOpen(!open)}
            aria-label="Toggle menu"
          >
            {open ? <X size={18} /> : <Menu size={18} />}
          </button>
        </div>

        {/* Nav */}
        <nav
          className="flex-1 flex flex-col px-2 overflow-y-auto"
          style={{ gap: 4 }}
        >
          {navLinks.map((l) => {
            const Icon = l.icon as React.ElementType;
            const active = isActive(l.href);
            return (
              <Link
                key={l.href}
                href={l.href}
                onClick={() => setOpen(false)}
                style={{ padding: "11px 12px", fontSize: 14 }}
                className={[
                  "flex items-center rounded-xl no-underline font-medium transition-all duration-150 relative",
                  active
                    ? "bg-[rgba(8,193,193,0.13)] text-[#5de0e0]"
                    : "text-[#6e9aaa] hover:bg-white/5 hover:text-[#b8dfe0]",
                ].join(" ")}
              >
                {/* Left border accent for active */}
                {active && (
                  <span
                    className="absolute left-0 top-1/2 -translate-y-1/2 bg-[#08c1c1] rounded-r-full"
                    style={{ width: 3, height: "55%" }}
                  />
                )}
                <span
                  className="flex items-center justify-center shrink-0"
                  style={{ marginLeft: 8, marginRight: 12 }}
                >
                  <Icon size={17} />
                </span>
                <span>{l.label}</span>
              </Link>
            );
          })}
        </nav>

        {/* Footer */}
        <div className="px-3 py-4">
          <div
            className="flex items-center gap-2.5 rounded-xl border border-white/5 bg-white/3"
            style={{ padding: "10px 12px" }}
          >
            <div className="relative shrink-0">
              <div className="w-8 h-8 rounded-full bg-[#0d4f4f] flex items-center justify-center text-[#08c1c1] text-xs font-bold">
                0x
              </div>
              <span className="absolute bottom-0 right-0 w-2 h-2 rounded-full bg-[#13d3b3] border-2 border-[#0d1f28]" />
            </div>
            <div className="flex flex-col min-w-0">
              <div className="flex items-center gap-1 text-[10px] text-[#4a8090] uppercase tracking-wide font-semibold">
                <span className="inline-block w-1.5 h-1.5 rounded-full bg-[#13d3b3]" />
                Connected
              </div>
              <div className="text-[12px] font-semibold text-[#c8e8e8] truncate">
                0x4a...8f
              </div>
              <div className="text-[10px] text-[#4a8090]">Stellar Network</div>
            </div>
            <button
              className="ml-auto text-[#4a8090] hover:text-[#9ef0f0] bg-transparent border-0 cursor-pointer p-1 rounded transition-colors shrink-0"
              aria-label="Copy address"
            >
              <Copy size={12} />
            </button>
          </div>
        </div>
      </aside>

      {/* Mobile hamburger */}
      <button
        className="md:hidden fixed top-5 left-4 z-[60] flex items-center justify-center bg-[#0e2330] border border-white/8 rounded-xl text-[#6a9fae] hover:text-white transition-colors cursor-pointer"
        style={{ width: 38, height: 38 }}
        onClick={() => setOpen(!open)}
        aria-label="Toggle menu"
      >
        {open ? <X size={18} /> : <Menu size={18} />}
      </button>
    </>
  );
};

export default Sidebar;
