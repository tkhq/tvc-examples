"use client";

import { useTurnkey, AuthState } from "@turnkey/react-wallet-kit";
import Header from "@/components/Header";
import ScreeningTool from "@/components/ScreeningTool";

export default function Home() {
  const { authState, handleLogin } = useTurnkey();

  // Show login prompt until Turnkey confirms authentication.
  if (authState !== AuthState.Authenticated) {
    return (
      <main className="min-h-screen flex items-center justify-center px-4">
        <div className="w-full max-w-md space-y-8 text-center">
          <div className="space-y-2">
            <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-accent/10 border border-accent/20 mb-2">
              <svg
                xmlns="http://www.w3.org/2000/svg"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth={1.5}
                className="w-6 h-6 text-accent"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z"
                />
              </svg>
            </div>
            <h1 className="text-2xl font-bold tracking-tight">TVC Sanctions Screener</h1>
            <p className="text-muted text-sm">
              Verifiable compliance powered by{" "}
              <span className="text-gray-300">Turnkey Verifiable Cloud</span>
            </p>
          </div>

          <div className="card space-y-4">
            <p className="text-sm text-muted">
              Sign in to screen crypto addresses against OFAC sanctions lists.
              Every result is cryptographically attested by a Nitro Enclave.
            </p>
            <button onClick={() => handleLogin()} className="btn-primary w-full">
              Log in / Sign up
            </button>
          </div>
        </div>
      </main>
    );
  }

  return (
    <div className="min-h-screen flex flex-col">
      <Header />
      <main className="flex-1 max-w-3xl mx-auto w-full px-4 py-10 space-y-8">
        <ScreeningTool />
      </main>
    </div>
  );
}
