import type { Metadata } from "next";
import type { ReactNode } from "react";
import { Providers } from "./providers";
import "@turnkey/react-wallet-kit/styles.css";
import "./globals.css";

export const metadata: Metadata = {
  title: "TVC Sanctions Screener",
  description:
    "Verifiable sanctions screening powered by Turnkey Verifiable Cloud and Chainalysis",
};

export default function RootLayout({
  children,
}: {
  children: ReactNode;
}) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-surface">
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
