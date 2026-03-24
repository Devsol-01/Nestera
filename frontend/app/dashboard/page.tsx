import React from "react";
import NetWorthCard from "../components/dashboard/NetWorthCard";
import QuickActionsGrid from "../components/dashboard/QuickActionsGrid";
import ActivePoolList from "../components/dashboard/ActivePoolList";
import RecentTransactionsWidget from "../components/dashboard/RecentTransactionsWidget";

export default function DashboardPage() {
  return (
    <div className="w-full max-w-full overflow-x-hidden">
      {/* Top row: NetWorth (stretches) + QuickActions (fixed width) */}
      <div className="flex gap-4 md:gap-[18px] items-start flex-col md:flex-row">
        <div className="flex-1 w-full min-w-0">
          <NetWorthCard />
        </div>
        <div className="w-full md:w-[360px] md:max-w-[40%] min-w-0">
          <QuickActionsGrid />
        </div>
      </div>

      {/* Second row: ActivePoolList + RecentTransactions */}
      <div className="mt-4 md:mt-5 flex gap-4 md:gap-5 flex-col lg:flex-row">
        <div className="flex-1 w-full min-w-0">
          <ActivePoolList />
        </div>
        <div className="flex-1 w-full min-w-0">
          <RecentTransactionsWidget />
        </div>
      </div>
    </div>
  );
}
