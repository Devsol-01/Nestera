'use client';

import { useWallet } from '../contexts/WalletContext';

export default function WalletConnectButton() {
  const {
    isConnected,
    isConnecting,
    publicKey,
    isTestnet,
    connectWallet,
    disconnectWallet,
  } = useWallet();

  const truncateAddress = (address: string) => {
    if (!address) return '';
    return `${address.slice(0, 4)}...${address.slice(-4)}`;
  };

  if (isConnected && publicKey) {
    if (!isTestnet) {
      return (
        <button
          onClick={disconnectWallet}
          className="flex items-center gap-2 bg-red-500/10 border border-red-500 text-red-500 px-4 py-2 rounded-lg hover:bg-red-500/20 transition-all duration-200 font-medium text-sm"
          title="Click to disconnect"
        >
          <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
          <span>Wrong Network (Testnet Only)</span>
        </button>
      );
    }

    return (
      <button
        onClick={disconnectWallet}
        className="group flex items-center gap-2 bg-gray-800/50 border border-gray-700 hover:border-gray-600 text-gray-200 px-4 py-2 rounded-lg transition-all duration-200 backdrop-blur-sm"
        title="Click to disconnect"
      >
        <div className="w-2 h-2 rounded-full bg-emerald-400 group-hover:shadow-[0_0_8px_rgba(52,211,153,0.5)] transition-shadow" />
        <span className="font-mono text-sm tracking-wide">
          {truncateAddress(publicKey)}
        </span>
      </button>
    );
  }

  return (
    <button
      onClick={connectWallet}
      disabled={isConnecting}
      className={`relative px-6 py-2.5 rounded-lg overflow-hidden transition-all duration-200 ${
        isConnecting
          ? 'bg-gray-700 cursor-wait text-gray-400'
          : 'bg-indigo-600 hover:bg-indigo-500 text-white shadow-lg hover:shadow-indigo-500/25 active:scale-95'
      }`}
    >
      <span className="relative z-10 font-semibold text-sm">
        {isConnecting ? 'Connecting...' : 'Connect Wallet'}
      </span>
    </button>
  );
}
