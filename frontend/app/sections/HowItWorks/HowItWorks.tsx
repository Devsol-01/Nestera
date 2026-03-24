import React from 'react';

const steps = [
  {
    title: 'Connect Wallet',
    description: 'Securely link your Stellar wallet to get started with Nestera.',
    icon: (
      <svg className="w-8 h-8 text-[#00d4c0]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
      </svg>
    ),
  },
  {
    title: 'Choose a Pool',
    description: 'Find a savings pool that matches your financial goals and risk tolerance.',
    icon: (
      <svg className="w-8 h-8 text-[#00d4c0]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 6l3 1m0 0l-3 9a5.002 5.002 0 006.001 0M6 7l3 9M6 7l6-2m6 2l3-1m-3 1l-3 9a5.002 5.002 0 006.001 0M18 7l3 9m-3-9l-6-2m0-2v2m0 16V5m0 16H9m3 0h3" />
      </svg>
    ),
  },
  {
    title: 'Start Saving',
    description: 'Deposit funds and watch your savings grow securely on-chain.',
    icon: (
      <svg className="w-8 h-8 text-[#00d4c0]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
      </svg>
    ),
  },
];

const HowItWorks: React.FC = () => {
  return (
    <section className="py-20 bg-[#061a1a]" id="how-it-works">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-16">
          <h2 className="text-3xl font-extrabold text-white sm:text-4xl">
            How It Works
          </h2>
          <p className="mt-4 text-xl text-[rgba(180,210,210,0.7)]">
            Three simple steps to start saving securely on-chain.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
          {steps.map((step, index) => (
            <div
              key={index}
              className="group cursor-pointer bg-[#061a1a] border border-white/[0.06] rounded-xl p-8 transition-all duration-300 ease-in-out md:hover:-translate-y-1 md:hover:border-[rgba(0,212,192,0.25)] md:hover:shadow-[0_10px_30px_rgba(0,0,0,0.2)]"
            >
              <div className="w-16 h-16 bg-[rgba(0,212,192,0.1)] rounded-full flex items-center justify-center mb-6 mx-auto transition-transform duration-300 ease-in-out group-hover:scale-110">
                {step.icon}
              </div>
              <h3 className="text-xl font-bold text-white text-center mb-4">
                {step.title}
              </h3>
              <p className="text-[rgba(180,210,210,0.7)] text-center leading-relaxed">
                {step.description}
              </p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default HowItWorks;
