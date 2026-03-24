import "./globals.css";

import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Nestera - Decentralized Savings on Stellar",
  description: "Secure, transparent savings powered by Stellar & Soroban",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="bg-slate-950 text-white">{children}</body>
    </html>
  );
}
