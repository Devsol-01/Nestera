"use client";

import React from "react";
import ActivePoolCard, { PoolItem } from "./ActivePoolCard";

const MOCK_POOLS: PoolItem[] = [
  {
    id: 1,
    title: "USDC Flexible Savings",
    subtitle: "Stellar Network",
    apy: 12.0,
    staked: "$10,000.00",
    earnings: "$450.21",
  },
  {
    id: 2,
    title: "ETH Locked Staking",
    subtitle: "Ethereum Network",
    apy: 5.2,
    staked: "4.50 ETH",
    earnings: "0.12 ETH",
  },
];

const ActivePoolList: React.FC = () => {
  return (
    <section className="bg-linear-to-b from-[rgba(6,18,20,0.45)] to-[rgba(4,12,14,0.35)] border border-[rgba(8,120,120,0.06)] rounded-2xl p-[18px] text-[#dff]">
      <div className="flex justify-between items-center mb-3">
        <h4 className="m-0 text-base font-semibold">
          Active Savings &amp; Staking
        </h4>
        <a
          href="#"
          className="text-[#60f0ec] no-underline font-semibold hover:text-[#9ef0f0] transition-colors"
        >
          View all
        </a>
      </div>

      <div className="flex flex-col gap-3">
        {MOCK_POOLS.map((p) => (
          <ActivePoolCard key={p.id} pool={p} />
        ))}
      </div>
    </section>
  );
};

export default ActivePoolList;
