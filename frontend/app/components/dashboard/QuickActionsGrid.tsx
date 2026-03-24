"use client";

import React from "react";
import { ArrowDownCircle, ArrowUpCircle, Repeat, Link } from "lucide-react";

const actions = [
  { label: "Deposit", icon: ArrowDownCircle },
  { label: "Withdraw", icon: ArrowUpCircle },
  { label: "Swap", icon: Repeat },
  { label: "Bridge", icon: Link },
];

const QuickActionsGrid: React.FC = () => {
  return (
    <div className="grid grid-cols-2 gap-3.5">
      {actions.map((a) => {
        const Icon = a.icon as React.ElementType;
        return (
          <button
            key={a.label}
            className="flex flex-col items-center justify-center p-[18px] h-[110px] rounded-2xl bg-linear-to-b from-[rgba(6,18,20,0.52)] to-[rgba(4,14,16,0.4)] border border-[rgba(12,120,120,0.08)] text-[#e6ffff] cursor-pointer transition-all duration-120 ease-in-out hover:-translate-y-1.5 hover:shadow-[0_14px_34px_rgba(2,28,28,0.6)]"
          >
            <div className="w-14 h-14 rounded-[10px] flex items-center justify-center bg-linear-to-b from-[#05a9a9] to-[#077f7f] shadow-[0_8px_30px_rgba(7,150,150,0.18)] text-[#042525]">
              <Icon size={20} />
            </div>
            <div className="font-bold mt-2.5 text-[#dff]">{a.label}</div>
          </button>
        );
      })}
    </div>
  );
};

export default QuickActionsGrid;
