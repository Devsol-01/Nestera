import React from 'react';


interface HeroStat {
  label: string;
  value: string;
}

interface HeroProps {
  headline: string[];          // each string = one line of the headline
  subheadline: string;
  primaryCta: {
    label: string;
    href: string;
  };
  secondaryCta: {
    label: string;
    href: string;
  };
  imageSrc: string;
  imageAlt: string;
  stat?: HeroStat;             // optional stat card at the bottom
}

const Hero: React.FC<HeroProps> = ({
  headline,
  subheadline,
  primaryCta,
  secondaryCta,
  imageSrc,
  imageAlt,
  stat,
}) => {
  return (
    <section className="relative w-full min-h-screen bg-[#061a1a] flex items-center font-['Inter'] overflow-hidden">
      {/* Architectural solution for radial background gradient */}
      <div
        className="pointer-events-none absolute -top-[10%] -left-[5%] w-1/2 h-[70%]"
        style={{ background: 'radial-gradient(ellipse, rgba(0, 180, 160, 0.08) 0%, transparent 70%)' }}
      />

      <div className="relative z-10 w-full max-w-[1200px] mx-auto px-12 py-20 flex items-center justify-between gap-12 max-[700px]:flex-col max-[700px]:px-6 max-[700px]:py-12 max-[700px]:text-center">

        {/* ── LEFT: Text Content ── */}
        <div className="flex-1 flex flex-col gap-6 max-w-[520px] max-[700px]:items-center max-[700px]:max-w-full">
          <h1 className="text-[clamp(2.6rem,5vw,4rem)] font-extrabold leading-[1.1] tracking-[-0.02em] text-white">
            {headline.map((line, i) => (
              <React.Fragment key={i}>
                {line}
                {i < headline.length - 1 && <br />}
              </React.Fragment>
            ))}
          </h1>

          <p className="text-[0.95rem] leading-[1.7] text-[rgba(180,210,210,0.7)] max-w-[400px] max-[700px]:max-w-full">{subheadline}</p>

          <div className="flex items-center gap-[14px] flex-wrap max-[700px]:justify-center">
            <a href={primaryCta.href} className="px-7 py-[13px] bg-[#00d4c0] text-[#061a1a] font-bold text-[0.92rem] rounded-lg no-underline inline-block whitespace-nowrap transition-all duration-200 hover:bg-[#00bfad] hover:-translate-y-0.5 hover:shadow-[0_8px_24px_rgba(0,212,192,0.35)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-[#00d4c0] focus-visible:outline-offset-[3px]">
              {primaryCta.label}
            </a>
            <a href={secondaryCta.href} className="px-7 py-[13px] bg-white/5 border border-white/20 text-white font-medium text-[0.92rem] rounded-lg no-underline inline-block whitespace-nowrap transition-all duration-200 hover:border-[rgba(0,212,192,0.6)] hover:bg-[rgba(0,212,192,0.08)] hover:-translate-y-0.5 focus-visible:outline focus-visible:outline-2 focus-visible:outline-[#00d4c0]">
              {secondaryCta.label} →
            </a>
          </div>

          {/* Optional stat card */}
          {stat && (
            <div className="inline-flex items-center gap-3 bg-white/5 border border-white/10 rounded-xl px-5 py-[14px] w-fit max-[700px]:self-center">
              <div className="w-9 h-9 bg-[rgba(0,212,192,0.12)] rounded-lg flex items-center justify-center flex-shrink-0" aria-hidden="true">
                <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
                  <polyline
                    points="1,13 6,7 10,10 17,3"
                    stroke="#00d4c0"
                    strokeWidth="1.8"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                  <polyline
                    points="13,3 17,3 17,7"
                    stroke="#00d4c0"
                    strokeWidth="1.8"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                </svg>
              </div>
              <div className="flex flex-col gap-0.5">
                <span className="text-[0.72rem] font-normal text-[rgba(180,210,210,0.6)] uppercase tracking-[0.06em]">{stat.label}</span>
                <span className="text-[1.1rem] font-bold text-white">{stat.value}</span>
              </div>
            </div>
          )}
        </div>

        {/* ── RIGHT: Image ── */}
        <div className="flex-1 flex items-center justify-center max-w-[560px] max-[700px]:max-w-full max-[700px]:w-full">
          <div className="w-full max-w-[520px] bg-[#000d0d] rounded-[20px] overflow-hidden aspect-[1/0.85] flex items-center justify-center max-[700px]:max-w-full">
            <img src={imageSrc} alt={imageAlt} className="w-full h-full object-cover block" />
          </div>
        </div>

      </div>
    </section>
  );
};

export default Hero;
