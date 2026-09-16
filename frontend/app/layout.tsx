import type { Metadata } from "next";
import { IBM_Plex_Mono, IBM_Plex_Sans } from "next/font/google";
import Link from "next/link";
import "./globals.css";

const plexSans = IBM_Plex_Sans({
  variable: "--font-plex-sans",
  subsets: ["latin"],
  weight: ["400", "500", "600"],
});

const plexMono = IBM_Plex_Mono({
  variable: "--font-plex-mono",
  subsets: ["latin"],
  weight: ["400", "500"],
});

export const metadata: Metadata = {
  title: "Security posture",
  description: "CIS benchmark findings for a monitored AWS account",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body className={`${plexSans.variable} ${plexMono.variable}`}>
        <div className="mx-auto max-w-4xl px-6 py-10">
          <header className="mb-10 flex items-baseline justify-between border-b border-rule pb-4">
            <Link href="/" className="text-base font-semibold tracking-tight">
              Security posture
            </Link>
            <nav className="flex gap-5 text-sm text-ink-soft">
              <Link href="/" className="hover:text-ink">
                Findings
              </Link>
              <Link href="/scans" className="hover:text-ink">
                Scan history
              </Link>
            </nav>
          </header>
          <main>{children}</main>
        </div>
      </body>
    </html>
  );
}