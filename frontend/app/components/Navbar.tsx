"use client";

import React, { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Wallet } from "lucide-react";

interface NavLink {
  label: string;
  href: string;
}

const Navbar: React.FC = () => {
  const pathname = usePathname();
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  const navLinks: NavLink[] = [
    { label: "Features", href: "/features" },
    { label: "Savings", href: "/savings" },
    { label: "Dashboard", href: "/dashboard" },
    { label: "Community", href: "/community" },
    { label: "Docs", href: "/docs" },
  ];

  const isActiveLink = (href: string): boolean => {
    return pathname === href || pathname?.startsWith(href + "/");
  };

  const navLinkBase =
    "text-sm font-medium no-underline text-slate-300 transition-all duration-200 border-b-2 border-transparent pb-0.5 hover:text-white";
  const navLinkActive =
    "text-cyan-500 border-cyan-500 border-b-cyan-500";

  const mobileLinkBase =
    "block py-3 px-3 rounded-md text-base font-medium no-underline text-slate-300 transition-all duration-200 border-l-4 border-transparent hover:text-white hover:bg-slate-800";
  const mobileLinkActive =
    "text-cyan-500 bg-slate-800 border-l-cyan-500";

  return (
    <nav className="sticky top-0 z-50 bg-[#061a1a]">
      <div className="w-full">
        <div className="flex justify-between items-center h-16 px-[30px]">
          <div className="shrink-0">
            <Link
              href="/"
              className="flex items-center gap-2 no-underline transition-all duration-200 ease-in-out hover:scale-105"
            >
              <div className="w-7 h-7 rounded-full bg-[#00c9c8] flex items-center justify-center text-[#061a1a] font-bold text-lg shrink-0 p-0">
                <Wallet size={18} color="#061a1a" strokeWidth={2} />
              </div>
              <span className="text-xl font-bold text-white max-sm:hidden">
                Nestera
              </span>
            </Link>
          </div>

          <div className="hidden md:flex items-center gap-8 flex-1 justify-center">
            {navLinks.map((link) => (
              <Link
                key={link.href}
                href={link.href}
                className={
                  isActiveLink(link.href)
                    ? `${navLinkBase} ${navLinkActive}`
                    : navLinkBase
                }
              >
                {link.label}
              </Link>
            ))}
          </div>

          <div className="flex items-center gap-4">
            <button
              type="button"
              className="hidden sm:inline-flex items-center justify-center py-3 px-6 rounded-full bg-[#00c9c8] text-[#061a1a] font-semibold text-sm border-none cursor-pointer shadow-[0_10px_15px_-3px_rgba(0,212,192,0.1)] transition-all duration-200 hover:shadow-[0_10px_15px_-3px_rgba(0,212,192,0.5)] hover:scale-105"
            >
              Connect Wallet
            </button>

            <button
              type="button"
              onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
              className="inline-flex md:hidden items-center justify-center p-2 rounded-md text-slate-400 bg-transparent border-none cursor-pointer transition-all duration-200 hover:text-white hover:bg-slate-800"
              aria-expanded={isMobileMenuOpen}
            >
              <span className="sr-only">Open main menu</span>
              {isMobileMenuOpen ? (
                <svg
                  className="w-6 h-6 stroke-current stroke-2 fill-none"
                  xmlns="http://www.w3.org/2000/svg"
                  fill="none"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    d="M6 18L18 6M6 6l12 12"
                  />
                </svg>
              ) : (
                <svg
                  className="w-6 h-6 stroke-current stroke-2 fill-none"
                  xmlns="http://www.w3.org/2000/svg"
                  fill="none"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    d="M4 6h16M4 12h16M4 18h16"
                  />
                </svg>
              )}
            </button>
          </div>
        </div>
      </div>

      <div
        className={`bg-[#061a1a] border-t border-slate-600 shadow-[0_10px_15px_-3px_rgba(0,0,0,0.1)] ${isMobileMenuOpen ? "block" : "hidden"}`}
      >
        <div className="p-2 pb-3 flex flex-col gap-1">
          {navLinks.map((link) => (
            <Link
              key={link.href}
              href={link.href}
              className={
                isActiveLink(link.href)
                  ? `${mobileLinkBase} ${mobileLinkActive}`
                  : mobileLinkBase
              }
              onClick={() => setIsMobileMenuOpen(false)}
            >
              {link.label}
            </Link>
          ))}
          <button
            type="button"
            className="w-full mt-4 py-3 px-6 rounded-full bg-[#00c9c8] text-[#061a1a] font-semibold text-sm border-none cursor-pointer shadow-[0_10px_15px_-3px_rgba(0,212,192,0.1)] transition-all duration-200 hover:shadow-[0_10px_15px_-3px_rgba(0,212,192,0.5)]"
          >
            Connect Wallet
          </button>
        </div>
      </div>
    </nav>
  );
};

export default Navbar;
