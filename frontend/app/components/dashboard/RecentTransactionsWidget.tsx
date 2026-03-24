"use client";

import React from "react";

interface Transaction {
  id: number;
  type: "deposit" | "withdraw" | "swap" | "yield";
  title: string;
  timestamp: string;
  amount: string;
  isPositive: boolean | null; // null for neutral (swaps)
}

const TransactionRow: React.FC<{ transaction: Transaction }> = ({
  transaction,
}) => {
  const getIcon = () => {
    switch (transaction.type) {
      case "deposit":
        return (
          <svg
            className="w-5 h-5"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M19 14l-7 7m0 0l-7-7m7 7V3"
            />
          </svg>
        );
      case "withdraw":
        return (
          <svg
            className="w-5 h-5"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M5 10l7-7m0 0l7 7m-7-7v18"
            />
          </svg>
        );
      case "swap":
        return (
          <svg
            className="w-5 h-5"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4"
            />
          </svg>
        );
      case "yield":
        return (
          <svg
            className="w-5 h-5"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
            />
          </svg>
        );
    }
  };

  const getAmountColor = () => {
    if (transaction.isPositive === true) return "text-[#8ef4ef]";
    if (transaction.isPositive === false) return "text-[#ff9999]";
    return "text-white";
  };

  return (
    <div className="flex items-center gap-3 py-3 border-b border-white/5 last:border-0">
      <div className="w-9 h-9 rounded-lg bg-[rgba(6,110,110,0.15)] flex items-center justify-center text-[#7fbfbf] shrink-0">
        {getIcon()}
      </div>
      <div className="flex-1 min-w-0">
        <div className="font-semibold text-[#dff] text-sm">
          {transaction.title}
        </div>
        <div className="text-[#90b4b4] text-xs mt-0.5">
          {transaction.timestamp}
        </div>
      </div>
      <div className={`font-bold text-sm ${getAmountColor()}`}>
        {transaction.amount}
      </div>
    </div>
  );
};

const RecentTransactionsWidget: React.FC = () => {
  const mockTransactions: Transaction[] = [
    {
      id: 1,
      type: "deposit",
      title: "Deposit USDC",
      timestamp: "Today, 10:23 AM",
      amount: "+$500.00",
      isPositive: true,
    },
    {
      id: 2,
      type: "yield",
      title: "Yield Earned",
      timestamp: "Today, 8:15 AM",
      amount: "+$12.45",
      isPositive: true,
    },
    {
      id: 3,
      type: "swap",
      title: "Swap ETH → USDC",
      timestamp: "Yesterday, 4:32 PM",
      amount: "-0.5 ETH",
      isPositive: null,
    },
    {
      id: 4,
      type: "withdraw",
      title: "Withdraw DAI",
      timestamp: "Yesterday, 2:18 PM",
      amount: "-$250.00",
      isPositive: false,
    },
    {
      id: 5,
      type: "deposit",
      title: "Deposit ETH",
      timestamp: "2 days ago, 11:05 AM",
      amount: "+1.2 ETH",
      isPositive: true,
    },
    {
      id: 6,
      type: "yield",
      title: "Yield Earned",
      timestamp: "3 days ago, 9:00 AM",
      amount: "+$8.32",
      isPositive: true,
    },
  ];

  return (
    <div
      style={{
        background:
          "linear-gradient(180deg, rgba(4,20,22,0.85), rgba(6,18,20,0.75))",
        border: "1px solid rgba(6,110,110,0.15)",
        borderRadius: "18px",
        padding: "24px",
        color: "#e6ffff",
        boxShadow: "0 10px 30px rgba(2,12,14,0.6)",
        backdropFilter: "blur(6px)",
      }}
    >
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-lg font-bold text-[#dff]">Recent Transactions</h2>
      </div>

      <div className="max-h-[400px] overflow-y-auto pr-2 custom-scrollbar">
        {mockTransactions.map((transaction) => (
          <TransactionRow key={transaction.id} transaction={transaction} />
        ))}
      </div>

      <div className="mt-4 pt-3 border-t border-white/5">
        <a
          href="#"
          className="text-[#7fbfbf] hover:text-[#8ef4ef] text-sm font-semibold transition-colors"
        >
          View all history →
        </a>
      </div>

      <style jsx>{`
        .custom-scrollbar::-webkit-scrollbar {
          width: 6px;
        }
        .custom-scrollbar::-webkit-scrollbar-track {
          background: rgba(6, 110, 110, 0.1);
          border-radius: 3px;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb {
          background: rgba(127, 191, 191, 0.3);
          border-radius: 3px;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover {
          background: rgba(127, 191, 191, 0.5);
        }
      `}</style>
    </div>
  );
};

export default RecentTransactionsWidget;
