import React from 'react';

const trustItems = [
  {
    title: 'Transparent',
    description: 'Funds held entirely on-chain; nobody can make a mistake',
  },
  {
    title: 'Non-Custodial',
    description: 'You own your funds at all times — always',
  },
  {
    title: 'Low Fees',
    description: "Stellar's low-cost transactions save users money",
  },
  {
    title: 'No Penalty',
    description: 'No penalties or surprise charges; transparent contracts',
  },
];

const CheckIcon = () => (
  <svg
    width="24"
    height="24"
    viewBox="0 0 24 24"
    fill="none"
    xmlns="http://www.w3.org/2000/svg"
    aria-hidden="true"
  >
    <path
      d="M20 6L9 17L4 12"
      stroke="#1ABC9C"
      strokeWidth="2.5"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);

const WhyTrust: React.FC = () => {
  return (
    <section
      className="w-full bg-[#061a1a] px-6 py-16 md:px-12 md:py-20 lg:px-16"
      aria-labelledby="why-trust-title"
    >
      <div className="mx-auto max-w-4xl">
        <h2
          id="why-trust-title"
          className="mb-12 text-center text-[clamp(1.75rem,4vw,2.5rem)] font-bold tracking-[-0.02em] text-white md:mb-16"
        >
          Why Trust Nestera?
        </h2>

        <div className="flex flex-col gap-6">
          {trustItems.map((item) => (
            <div
              key={item.title}
              className="flex items-start gap-4 rounded-xl border border-white/[0.08] bg-white/[0.03] p-5 transition-colors duration-200 hover:border-[#1ABC9C]/30"
            >
              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-[#1ABC9C]/20">
                <CheckIcon />
              </div>
              <div>
                <h3 className="text-lg font-semibold text-white">
                  {item.title}
                </h3>
                <p className="mt-1 text-sm leading-relaxed text-[rgba(180,210,210,0.85)]">
                  {item.description}
                </p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default WhyTrust;
