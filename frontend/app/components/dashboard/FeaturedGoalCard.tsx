import React from 'react';
import { Plane, Calendar, ChevronRight } from 'lucide-react';
import CircularProgress from './CircularProgress';

interface FeaturedGoalCardProps {
  title: string;
  category: string;
  currentAmount: number;
  targetAmount: number;
  targetDate: string;
  status: string;
  percentage: number;
  motivationalText: string;
}

const FeaturedGoalCard: React.FC<FeaturedGoalCardProps> = ({
  title = "Summer Vacation Fund",
  category = "Travel",
  currentAmount = 7800,
  targetAmount = 10000,
  targetDate = "Aug 31, 2024",
  status = "On Track",
  percentage = 78,
  motivationalText = "You're 78% of the way there! Keep it up!",
}) => {
  return (
    <div className="relative overflow-hidden bg-linear-to-br from-[rgba(6,26,26,0.8)] to-[rgba(4,14,16,0.6)] border border-white/5 rounded-[32px] p-8 md:p-10 flex flex-col md:flex-row items-center gap-10 shadow-[0_20px_50px_rgba(0,0,0,0.3)] backdrop-blur-sm">
      {/* Decorative accent */}
      <div className="absolute top-0 left-0 w-1 h-20 bg-cyan-500 rounded-br-full" />
      
      {/* Left Section: Icon and Title */}
      <div className="flex flex-1 items-center gap-6 w-full">
        <div className="w-20 h-20 rounded-full bg-linear-to-b from-[rgba(0,212,192,0.15)] to-[rgba(0,212,192,0.05)] border border-[rgba(0,212,192,0.2)] flex items-center justify-center text-cyan-400 shrink-0 shadow-[0_0_30px_rgba(0,212,192,0.1)]">
          <Plane size={36} strokeWidth={1.5} />
        </div>
        <div className="flex flex-col gap-2">
          <div className="flex flex-wrap items-center gap-3">
            <h2 className="text-2xl md:text-[32px] font-bold text-white m-0 tracking-tight leading-tight">
              {title}
            </h2>
            <span className="px-2.5 py-1 bg-[#0e2330]/80 border border-white/10 rounded-lg text-[10px] font-bold text-cyan-400 uppercase tracking-widest whitespace-nowrap">
              {category}
            </span>
          </div>
          <p className="text-[#5e8c96] text-[15px] m-0 max-w-sm leading-relaxed">
            Saving for your dream getaway to the tropics.
          </p>
        </div>
      </div>

      {/* Middle Section: Progress Circle */}
      <div className="relative flex flex-col items-center gap-2">
        <CircularProgress 
          percentage={percentage} 
          size={140} 
          strokeWidth={12} 
          strokeColor="#00d4c0"
          backgroundColor="rgba(0, 212, 192, 0.08)"
        />
        <div className="mt-4 text-center">
            <span className="text-white font-bold block text-lg tracking-wide">
                ${currentAmount.toLocaleString()} <span className="text-[#5e8c96] font-medium">/ ${targetAmount.toLocaleString()}</span>
            </span>
        </div>
      </div>

    <div className="flex flex-col gap-6 min-w-[280px] w-full md:w-auto">
        <div className="flex flex-col gap-4">
          <div className="flex items-center gap-2 text-[#5e8c96]">
            <Calendar size={16} className="text-cyan-500/80" />
            <span className="text-sm font-medium">Target: {targetDate}</span>
          </div>
          
          <div className="inline-flex items-center px-4 py-1.5 bg-[#062020] border border-cyan-900/40 rounded-full w-fit">
             <span className="w-2 h-2 rounded-full bg-emerald-400 mr-2 shadow-[0_0_8px_rgba(52,211,153,0.8)]" />
             <span className="text-[10px] font-bold text-emerald-400 uppercase tracking-widest leading-none">{status}</span>
          </div>

          <p className="text-[#5e8c96]/80 text-[13px] leading-relaxed italic m-0">
            &ldquo;{motivationalText}&rdquo;
          </p>
        </div>

        <div className="flex items-center gap-4 mt-2">
          <button className="flex-1 md:flex-none px-6 py-3.5 bg-cyan-500 hover:bg-cyan-400 text-[#061a1a] font-bold rounded-2xl transition-all duration-300 shadow-[0_10px_20px_rgba(0,212,192,0.2)] hover:shadow-[0_15px_30px_rgba(0,212,192,0.4)] active:scale-95 cursor-pointer">
            Contribute Now
          </button>
          <button className="flex items-center gap-1 text-cyan-400 font-bold hover:text-cyan-300 transition-colors cursor-pointer group px-2">
            View Details
            <ChevronRight size={18} className="transition-transform group-hover:translate-x-1" />
          </button>
        </div>
      </div>
    </div>
  );
};

export default FeaturedGoalCard;
