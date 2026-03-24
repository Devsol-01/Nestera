import React from 'react';

const TEAL_ACCENT = '#1ABC9C';

const steps = [
  {
    number: '01',
    title: 'Connect Wallet',
    description:
      "Connect your Stellar wallet securely to access Nestera's decentralized savings infrastructure.",
    icon: (
      <svg
        width="32"
        height="32"
        viewBox="0 0 24 24"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        aria-hidden
      >
        <path
          d="M21 12V7H5a2 2 0 0 1-2-2c0-1.1.9-2 2-2h14v7"
          stroke={TEAL_ACCENT}
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
        <path
          d="M3 5v14a2 2 0 0 0 2 2h16v-5"
          stroke={TEAL_ACCENT}
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
        <path
          d="M18 12a2 2 0 1 0 0-4 2 2 0 0 0 0 4z"
          fill={TEAL_ACCENT}
        />
      </svg>
    ),
  },
  {
    number: '02',
    title: 'Start Saving',
    description:
      'Choose flexible, locked, goal-based, or group savings and deposit stablecoins transparently on-chain.',
    icon: (
      <svg
        width="32"
        height="32"
        viewBox="0 0 24 24"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        aria-hidden
      >
        <path
          d="M19 7v3c0 2.2-1.8 4-4 4H9c-2.2 0-4-1.8-4-4V7"
          stroke={TEAL_ACCENT}
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
        <path
          d="M5 7V6a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2v1"
          stroke={TEAL_ACCENT}
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
        <path
          d="M12 11v6M9 14h6"
          stroke={TEAL_ACCENT}
          strokeWidth="2"
          strokeLinecap="round"
        />
      </svg>
    ),
  },
  {
    number: '03',
    title: 'Watch It Grow',
    description:
      'Track contributions, monitor yield, and watch your savings grow securely over time.',
    icon: (
      <svg
        width="32"
        height="32"
        viewBox="0 0 24 24"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        aria-hidden
      >
        <path
          d="M3 17l4-4 4 4 6-8 4 4"
          stroke={TEAL_ACCENT}
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
        <path
          d="M3 12v5h5"
          stroke={TEAL_ACCENT}
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
    ),
  },
];

const HowItWorks: React.FC = () => {
  return (
    <section
      className="w-full bg-[#061a1a] px-6 py-16 md:px-12 md:py-20 lg:px-16"
      aria-labelledby="how-it-works-title"
    >
      <div className="mx-auto max-w-6xl">
        <h2
          id="how-it-works-title"
          className="mb-12 text-center text-[clamp(1.75rem,4vw,2.5rem)] font-bold tracking-[-0.02em] text-white md:mb-16"
        >
          Simple steps to financial freedom
        </h2>

        <div className="relative flex flex-col gap-8 md:flex-row md:items-stretch md:gap-6 lg:gap-8">
          {/* Desktop: horizontal connector line */}
          <div
            className="absolute left-1/2 top-14 hidden h-0.5 w-2/3 -translate-x-1/2 bg-[#1ABC9C]/35 md:block"
            aria-hidden
          />

          {steps.map((step, index) => (
            <article
              key={step.number}
              className="relative z-10 flex flex-1 flex-col rounded-2xl border border-white/[0.08] bg-white/[0.03] p-6 shadow-lg transition-[border-color,box-shadow] duration-200 hover:border-[#1ABC9C]/30 hover:shadow-xl md:p-7"
            >
              <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-xl bg-[#1ABC9C]/20 md:mb-5">
                {step.icon}
              </div>
              <span className="mb-2 text-sm font-medium uppercase tracking-wider text-[#1ABC9C]/80">
                {step.number}
              </span>
              <h3 className="mb-3 text-xl font-semibold text-white md:text-[1.25rem]">
                {step.title}
              </h3>
              <p className="text-sm leading-relaxed text-[rgba(180,210,210,0.85)] md:text-[0.95rem]">
                {step.description}
              </p>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
};

export default HowItWorks;
