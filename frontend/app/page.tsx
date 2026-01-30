'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useWallet } from '../contexts/WalletContext';

export default function HomePage() {
  const { isConnected, isTestnet, connectWallet, isConnecting } = useWallet();
  const router = useRouter();

  return (
    <div className="flex flex-col items-center justify-center min-h-[80vh] gap-6 text-center px-4">
      <h1 className="text-4xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-purple-600">
        Welcome to Nestera
      </h1>
      <p className="max-w-md text-gray-400">
        The savings platform built on Stellar. Connect your wallet to get started.
      </p>

      {isConnected ? (
        <div className="space-y-4">
          <div className="p-4 rounded-lg bg-gray-800/50 border border-gray-700">
            <p className="text-sm text-gray-400 mb-1">Status</p>
            <div className="flex items-center gap-2 justify-center">
              <span className={`w-2 h-2 rounded-full ${isTestnet ? 'bg-emerald-400' : 'bg-red-500'}`} />
              <span className={`font-medium ${isTestnet ? 'text-emerald-400' : 'text-red-400'}`}>
                {isTestnet ? 'Connected to Testnet' : 'Wrong Network'}
              </span>
            </div>
            {!isTestnet && (
              <p className="text-xs text-red-500/80 mt-2">
                Please switch your wallet to Stellar Testnet.
              </p>
            )}
          </div>

          <button
            onClick={() => isTestnet && router.push('/dashboard')}
            disabled={!isTestnet}
            className={`w-full px-6 py-3 rounded-lg font-medium transition-all transform hover:-translate-y-0.5 ${isTestnet
                ? 'bg-blue-600 hover:bg-blue-500 text-white shadow-lg shadow-blue-500/25 cursor-pointer'
                : 'bg-gray-800 text-gray-500 cursor-not-allowed opacity-50 border border-gray-700'
              }`}
          >
            {isTestnet ? 'Enter Dashboard' : 'Network Error'}
          </button>
        </div>
      ) : (
        <div className="flex flex-col gap-4">
          <button
            onClick={connectWallet}
            disabled={isConnecting}
            className="px-8 py-3 rounded-lg font-bold text-white bg-indigo-600 hover:bg-indigo-500 shadow-lg shadow-indigo-500/25 transition-all transform hover:-translate-y-0.5 active:scale-95 disabled:opacity-70 disabled:cursor-wait"
          >
            {isConnecting ? 'Connecting...' : 'Connect Freighter Wallet'}
          </button>
          <p className="text-xs text-gray-500">
            Don't have Freighter? <a href="https://www.freighter.app/" target="_blank" rel="noopener noreferrer" className="text-indigo-400 hover:text-indigo-300 underline">Download here</a>
          </p>
        </div>
      )}
    </div>
  );
}