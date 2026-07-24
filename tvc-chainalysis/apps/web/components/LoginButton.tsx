"use client";

import { useTurnkey } from "@turnkey/react-wallet-kit";

export default function LoginButton() {
  const { handleLogin } = useTurnkey();

  return (
    <button onClick={() => handleLogin()} className="btn-primary w-full">
      Log in / Sign up
    </button>
  );
}
