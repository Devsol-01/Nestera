'use client';

import React, { useState, useRef, useEffect } from 'react';
import clsx from 'clsx';

interface FAQItem {
  question: string;
  answer: string;
}

const faqData: FAQItem[] = [
  {
    question: 'How do I get started with Nestera?',
    answer: 'Getting started with Nestera is simple. Connect your wallet, deposit your preferred stablecoin, and start earning yield immediately. No complex setup required—just a few clicks and you\'re on your way to smarter, on-chain savings.',
  },
  {
    question: 'Can I withdraw my funds at any time?',
    answer: 'Yes, you can withdraw your funds at any time without lock-up periods. Nestera is designed for flexibility, allowing you to access your savings whenever you need them while still earning competitive yields.',
  },
  {
    question: 'Is Nestera audited and safe to use on-chain?',
    answer: 'Absolutely. Nestera\'s smart contracts are thoroughly audited by leading security firms. We prioritize transparency and security, with all code verified on-chain and open for community review.',
  },
  {
    question: 'What stablecoins does Nestera currently support?',
    answer: 'Nestera currently supports major stablecoins including USDC and USDT on the Stellar network. We\'re continuously expanding our supported assets to provide you with more options for your savings strategy.',
  },
];

const FAQ: React.FC = () => {
  const [openIndex, setOpenIndex] = useState<number | null>(null);
  const contentRefs = useRef<(HTMLDivElement | null)[]>([]);
  const [heights, setHeights] = useState<number[]>([]);

  useEffect(() => {
    // Measure the height of each answer content
    const newHeights = contentRefs.current.map((ref) => {
      if (ref) {
        return ref.scrollHeight;
      }
      return 0;
    });
    setHeights(newHeights);
  }, []);

  const toggleItem = (index: number) => {
    setOpenIndex(openIndex === index ? null : index);
  };

  return (
    <section className="w-full bg-[#061a1a] py-20 px-12 font-['Inter'] max-[960px]:py-[60px] max-[960px]:px-8 max-[700px]:py-12 max-[700px]:px-6">
      <div className="max-w-[800px] mx-auto">
        <h2 className="text-[clamp(1.75rem,4vw,2.5rem)] font-bold text-[rgba(0,212,192,0.5)] text-center mb-12 tracking-[-0.02em] max-[700px]:mb-8">
          Frequently Asked Questions
        </h2>
        
        <div className="flex flex-col gap-3">
          {faqData.map((item, index) => (
            <div
              key={index}
              className={clsx(
                "border rounded-xl overflow-hidden transition-colors duration-300",
                openIndex === index
                  ? "bg-[rgba(0,212,192,0.05)] border-[rgba(0,212,192,0.5)]"
                  : "bg-white/[0.03] border-white/[0.08] hover:border-[rgba(0,212,192,0.3)]"
              )}
            >
              <button
                className="w-full flex items-center justify-between gap-4 px-6 py-5 bg-transparent border-none cursor-pointer text-left transition-colors duration-200 hover:bg-white/[0.02] focus-visible:outline focus-visible:outline-2 focus-visible:outline-[#00d4c0] focus-visible:-outline-offset-[2px] focus-visible:rounded-xl"
                onClick={() => toggleItem(index)}
                aria-expanded={openIndex === index}
                aria-controls={`faq-answer-${index}`}
              >
                <span className="text-base font-medium text-white leading-normal">{item.question}</span>
                <span className={clsx(
                  "w-8 h-8 flex items-center justify-center text-2xl font-light text-[#00d4c0] rounded-lg flex-shrink-0 transition-all duration-300",
                  openIndex === index ? "bg-[rgba(0,212,192,0.2)]" : "bg-[rgba(0,212,192,0.1)]")}
                >
                  {openIndex === index ? '×' : '+'}
                </span>
              </button>
              
              <div
                // I put the id={`faq-answer-${index}`} as against onInvalid={...} cause of errors
                id={`faq-answer-${index}`}
                className="overflow-hidden transition-[height] duration-[400ms] ease-[cubic-bezier(0.4,0,0.2,1)]"
                style={{ height: openIndex === index ? `${heights[index]}px` : '0px' }}
              >
                <div
                  className="px-6 pb-5 max-[700px]:px-5 max-[700px]:pb-4"
                  ref={(el) => {
                    contentRefs.current[index] = el;
                  }}
                >
                  <p className="text-[0.95rem] leading-[1.7] text-[rgba(180,210,210,0.8)] max-[700px]:text-[0.9rem]">{item.answer}</p>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default FAQ;
