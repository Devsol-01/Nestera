import React from "react";
import Navbar from "../components/Navbar";
import Hero from "../sections/Hero/Hero";
import HowItWorks from "../components/HowItWorks";
import WhyTrust from "../components/WhyTrust";
import SavingsProducts from "../components/SavingsProducts";
import FAQ from "../components/FAQ";
import Newsletter from "../components/Newsletter";
import Footer from "../components/Footer";

const LandingPage: React.FC = () => {
  return (
    <main>
      <Navbar />
      <Hero
        headline={["Save Smarter.", "Grow", "Together.", "On-Chain."]}
        subheadline="Decentralized savings powered by Stellar & Soroban. Secure, transparent, and built for your financial future."
        primaryCta={{ label: "Start Saving", href: "#start-saving" }}
        secondaryCta={{ label: "Explore Pools", href: "#explore-pools" }}
        imageSrc="/hero.png"
        imageAlt="Glowing crypto vault with gold coins"
        stat={{ label: "Annual Yield", value: "12% APY" }}
      />
      <HowItWorks />
      <WhyTrust />
      <SavingsProducts />
      <FAQ />
      <Newsletter />
      <Footer />
    </main>
  );
};

export default LandingPage;
