import React from 'react';

interface ProductCardProps {
  icon: React.ReactNode;
  title: string;
  description: string;
}

const ProductCard: React.FC<ProductCardProps> = ({ icon, title, description }) => (
  <div className="bg-[#061a1a] border border-white/5 rounded-2xl p-8 flex flex-col gap-5 transition-all duration-300 cursor-pointer hover:bg-[#0a2525] hover:border-[rgba(0,212,192,0.2)] hover:-translate-y-1 hover:shadow-[0_10px_30px_rgba(0,0,0,0.2)]">
    <div className="w-11 h-11 bg-[rgba(0,212,192,0.08)] rounded-lg flex items-center justify-center text-[#00d4c0]">
      {icon}
    </div>
    <div className="flex flex-col gap-2">
      <h3 className="text-xl font-bold text-white">{title}</h3>
      <p className="text-[0.9rem] text-[rgba(180,210,210,0.65)] leading-relaxed">{description}</p>
      <a href="#" className="text-[#00d4c0] font-semibold flex items-center gap-2 text-[0.95rem] no-underline mt-3">
        Learn More <span className="text-xl">→</span>
      </a>
    </div>
  </div>
);

const SavingsProducts: React.FC = () => {
  const products = [
    {
      title: 'Flexible Savings',
      description: 'Withdraw anytime. Best for emergency funds and daily liquidity. No lock periods.',
      icon: (
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <rect x="2" y="5" width="20" height="14" rx="2" ry="2" />
          <line x1="2" y1="10" x2="22" y2="10" />
        </svg>
      ),
    },
    {
      title: 'Locked Savings',
      description: 'Higher APY for fixed terms. Commit your funds and earn more with deterministic interest.',
      icon: (
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
          <path d="M7 11V7a5 5 0 0 1 10 0v4" />
        </svg>
      ),
    },
    {
      title: 'Goal-Based',
      description: 'Set a target. Auto-save until you reach your dream purchase or financial milestone.',
      icon: (
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="10" />
          <circle cx="12" cy="12" r="6" />
          <circle cx="12" cy="12" r="2" />
        </svg>
      ),
    },
    {
      title: 'Group Savings',
      description: 'Save with friends and family. Pool funds for collective goals with shared transparent rules.',
      icon: (
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
          <circle cx="9" cy="7" r="4" />
          <path d="M23 21v-2a4 4 0 0 0-3-3.87" />
          <path d="M16 3.13a4 4 0 0 1 0 7.75" />
        </svg>
      ),
    },
  ];

  return (
    <section className="w-full py-[100px] px-12 bg-[#000d0d] font-['Inter'] max-md:py-[60px] max-md:px-6" id="savings-products">
      <div className="max-w-[1200px] mx-auto">
        <div className="flex justify-between items-end mb-[60px] gap-10 max-md:flex-col max-md:items-start max-md:gap-4 max-md:mb-10">
          <h2 className="text-[clamp(2rem,4vw,3rem)] font-extrabold text-white max-w-[500px] leading-[1.1]">
            Savings Products Tailored for You
          </h2>
          <p className="text-base text-[rgba(180,210,210,0.7)] max-w-[400px] leading-relaxed text-right max-md:text-left">
            Whether you want flexibility or higher returns, we have a pool for that.
          </p>
        </div>

        <div className="grid grid-cols-2 lg:grid-cols-2 gap-[60px] items-center max-lg:grid-cols-1 max-lg:gap-12">
          {/* MOCKUP */}
          <div className="group relative w-full rounded-3xl overflow-hidden aspect-[16/10] flex items-center justify-center bg-[#061a1a]">
            <img
              src="/mockup.png"
              alt="Nestera Mobile App Mockup"
              className="w-full h-full object-cover transition-transform duration-500 group-hover:scale-[1.02]"
            />
            <div className="absolute inset-0 bg-gradient-to-t from-[rgba(0,13,13,0.4)] to-transparent" />
            <div className="absolute bottom-6 left-6 right-6 flex justify-between items-end">
              <div className="flex flex-col gap-2">
                <span className="inline-flex px-3 py-1.5 bg-[rgba(0,212,192,0.1)] border border-[rgba(0,212,192,0.2)] rounded-lg text-sm text-[#00d4c0] w-fit">
                  Flexible Savings
                </span>
                <h3 className="text-2xl font-bold text-white">Start Saving Today</h3>
                <p className="text-[0.9rem] text-[rgba(180,210,210,0.7)] max-w-[300px]">
                  Join thousands of users growing their wealth securely on Stellar.
                </p>
              </div>
              <a href="#" className="text-[#00d4c0] font-semibold flex items-center gap-2 text-[0.95rem] no-underline">
                Start <span className="text-xl">→</span>
              </a>
            </div>
          </div>

          {/* CARDS GRID */}
          <div className="grid grid-cols-2 gap-6 max-md:grid-cols-1">
            {products.map((product, index) => (
              <ProductCard
                key={index}
                title={product.title}
                description={product.description}
                icon={product.icon}
              />
            ))}
          </div>
        </div>
      </div>
    </section>
  );
};

export default SavingsProducts;
