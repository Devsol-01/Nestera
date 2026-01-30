'use client';

import { useEffect } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useWallet } from '@/contexts/WalletContext';

export default function Dashboard() {
  const { isConnected, isTestnet, isConnecting, isInitializing } = useWallet();
  const router = useRouter();

  useEffect(() => {
    if (!isInitializing && !isConnecting && !isConnected) {
      router.push('/');
    }
  }, [isConnected, isConnecting, isInitializing, router]);

  if (isConnecting || isInitializing) {
    return (
      <div className="flex h-[50vh] items-center justify-center">
        <div className="w-8 h-8 border-4 border-indigo-500 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  if (!isConnected) return null; // Wait for redirect

  if (!isTestnet) {
    return (
      <div className="flex flex-col items-center justify-center h-[60vh] text-center px-4">
        <div className="w-16 h-16 bg-red-500/10 rounded-full flex items-center justify-center mb-4">
          <svg className="w-8 h-8 text-red-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
        </div>
        <h2 className="text-2xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-red-400 to-pink-600 mb-2">
          Wrong Network Detected
        </h2>
        <p className="text-gray-400 mb-6 max-w-md">
          Please open your Freighter wallet and switch the network to <span className="text-white font-mono bg-gray-800 px-1 rounded">Testnet</span> to access the Dashboard.
        </p>
        <button
          onClick={() => window.location.reload()}
          className="px-6 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm transition-colors"
        >
          Check Again
        </button>
      </div>
    );
  }

  return (
    <div className="p-8 max-w-6xl mx-auto">
      <div className="mb-8">
        <h1 className="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-indigo-400 to-purple-400 mb-2">
          Nestera Dashboard
        </h1>
        <p className="text-gray-400">
          Manage your active savings groups and track your contributions securely.
        </p>
      </div>
      
      <div className="mb-8 p-6 rounded-xl bg-gray-800/20 border border-gray-700/50 backdrop-blur-sm">
        <h3 className="text-lg font-semibold text-gray-200 mb-4">Quick Actions</h3>
        <nav className="flex gap-4">
          <Link
            href="/"
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-gray-800 hover:bg-gray-700 text-gray-300 transition-colors"
          >
            ← Back Home
          </Link>
          <Link
            href="/savings"
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white shadow-lg shadow-indigo-500/25 transition-colors"
          >
            View Savings Plans →
          </Link>
        </nav>
      </div>
    </div>
  );
}