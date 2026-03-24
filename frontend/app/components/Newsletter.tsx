"use client";

import React, { useState } from "react";

const Newsletter: React.FC = () => {
  const [email, setEmail] = useState("");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (email) {
      console.log("Newsletter signup:", email);
      // Here you would typically send the email to your backend
      setEmail("");
    }
  };

  return (
    <section className="bg-[#041c1e] py-16 px-8 flex justify-center items-center w-full">
      <div className="flex justify-between items-center w-full max-w-[1200px] flex-wrap gap-8 max-md:flex-col max-md:items-stretch max-md:text-center">
        <div className="flex-1 min-w-[280px]">
          <h2 className="text-white text-2xl font-semibold mb-2 leading-tight">
            Want to receive any updates or news?
          </h2>
          <p className="text-gray-400 text-sm m-0">Sign up for our Newsletter</p>
        </div>

        <form
          className="flex gap-3 flex-1 justify-end min-w-[320px] max-md:flex-col max-md:justify-center"
          onSubmit={handleSubmit}
        >
          <div className="flex-1 max-w-[400px] max-md:max-w-full">
            <input
              type="email"
              className="w-full px-4 py-3 bg-[#020c0c] border border-[#1f3536] rounded-md text-white text-sm placeholder:text-gray-500 outline-none transition-colors duration-200 focus:border-[#00d1c1] box-border"
              placeholder="Enter your email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
          </div>
          <button
            type="submit"
            className="px-6 py-3 bg-[#00d1c1] text-[#020c0c] border-none rounded-md text-sm font-semibold cursor-pointer transition-all duration-200 hover:opacity-90 active:scale-[0.98]"
          >
            Submit
          </button>
        </form>
      </div>
    </section>
  );
};

export default Newsletter;
