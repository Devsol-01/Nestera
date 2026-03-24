"use client";

import React from "react";

export interface PoolItem {
  id: number;
  title: string;
  subtitle: string;
  apy: number;
  staked: string;
  earnings: string;
}

const ActivePoolCard: React.FC<{ pool: PoolItem }> = ({ pool }) => {
  const initials = pool.title.split(" ")[0].slice(0, 2).toUpperCase();

  return (
    <div className="flex items-center gap-4 p-3.5 bg-[rgba(3,12,14,0.12)] rounded-xl border border-white/2">
      <div className="flex items-center gap-3 min-w-[200px]">
        <div className="w-11 h-11 rounded-[10px] bg-linear-to-b from-[#063d3d] to-[#0a6f6f] flex items-center justify-center font-bold text-[#dff] shrink-0">
          {initials}
        </div>
        <div className="flex flex-col">
          <div className="font-bold text-[#dff]">{pool.title}</div>
          <div className="text-[#90b4b4] text-[13px] mt-0.5">
            {pool.subtitle}
          </div>
        </div>
      </div>

      <div className="flex gap-6 ml-auto items-center">
        <div className="flex flex-col items-end min-w-[100px]">
          <div className="text-[12px] text-[#91b6b6]">APY</div>
          <div className="font-bold mt-1.5 text-[#dff]">{pool.apy}%</div>
        </div>
        <div className="flex flex-col items-end min-w-[100px]">
          <div className="text-[12px] text-[#91b6b6]">STAKED</div>
          <div className="font-bold mt-1.5 text-[#dff]">{pool.staked}</div>
        </div>
        <div className="flex flex-col items-end min-w-[100px]">
          <div className="text-[12px] text-[#91b6b6]">EARNINGS</div>
          <div className="font-bold mt-1.5 text-[#dff]">{pool.earnings}</div>
        </div>
      </div>

      <div className="ml-3 text-[#7fbfbf] text-lg select-none">⋯</div>
    </div>
  );
};

export default ActivePoolCard;
