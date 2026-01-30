import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google"; // Corrected import based on previous read
import "./globals.css";
import { WalletProvider } from "../contexts/WalletContext";
import WalletConnectButton from "../components/wallet-connect-button";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Nestera",
  description: "Nestera savings platform",
};

/**
 * Validates that required environment variables are present.
 */
function validateEnv() {
  const requiredEnvVars = [
    "NEXT_PUBLIC_STELLAR_NETWORK",
    "NEXT_PUBLIC_SOROBAN_RPC_URL",
    "NEXT_PUBLIC_NESTERA_CONTRACT_ID",
  ];

  const missingVars = requiredEnvVars.filter((key) => !process.env[key]);

  if (missingVars.length > 0 && process.env.NODE_ENV === "development") {
    console.warn(
      `⚠️ Nestera Warning: Missing environment variables: ${missingVars.join(", ")}. 
      Check your .env.local file.`
    );
  }
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  // 1. Run validation logic
  validateEnv();

  // 2. Safe Logging: Logs to the console during development without 
  // interfering with the React render tree (fixing the 'void' error).
  if (process.env.NODE_ENV === "development") {
    console.log("🌐 Nestera Environment Configuration:");
    console.table({
      Network: process.env.NEXT_PUBLIC_STELLAR_NETWORK || "❌ Not Set",
      Contract: process.env.NEXT_PUBLIC_NESTERA_CONTRACT_ID || "❌ Not Set",
      RPC: process.env.NEXT_PUBLIC_SOROBAN_RPC_URL || "❌ Not Set",
    });
  }

  return (
    <html lang="en">
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
      >
        <WalletProvider>
          <header className="bg-gray-800 text-white p-4 flex justify-between items-center shadow-md">
            <h1 className="text-xl font-bold">Nestera</h1>
            <WalletConnectButton />
          </header>
          {children}
        </WalletProvider>
      </body>
    </html>
  );
}