import type { Metadata, Viewport } from "next";
import Image from "next/image";
import Link from "next/link";
import "./globals.css";

export const metadata: Metadata = {
  metadataBase: new URL("https://mola-auditor.vercel.app"),
  title: "Mola — Evidence-Based Web Auditor for Developers",
  description:
    "Minimal, open-source web auditing tool for developers. Enter a website URL to discover concrete evidence-based findings across Security, Performance, SEO, and Accessibility.",
  authors: [{ name: "Md Mizan", url: "https://github.com/mizan989" }],
  icons: {
    icon: [
      { url: "/favicon.ico" },
      { url: "/favicon-32x32.png", sizes: "32x32", type: "image/png" },
      { url: "/icon-192.png", sizes: "192x192", type: "image/png" },
    ],
    apple: [{ url: "/apple-touch-icon.png", sizes: "180x180", type: "image/png" }],
  },
  openGraph: {
    title: "Mola — Evidence-Based Web Auditor",
    description: "Audit your website. Fix what actually matters with concrete developer evidence.",
    url: "https://github.com/mizan989/Mola-Web_Auditor",
    siteName: "Mola",
    images: [{ url: "/logo.png", width: 512, height: 512, alt: "Mola Logo" }],
    type: "website",
  },
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  themeColor: "#CCD0CF",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="min-h-screen flex flex-col bg-[var(--background)] text-[var(--text-primary)]">
        {/* Navbar */}
        <header className="h-[72px] px-6 sm:px-12 flex items-center justify-between border-b border-[var(--border)] bg-[var(--background)]/90 backdrop-blur-sm sticky top-0 z-50">
          <Link href="/" className="inline-flex items-center gap-3 font-extrabold tracking-tight text-lg text-[var(--text-primary)] hover:opacity-90 transition-opacity">
            <div className="w-8 h-8 rounded-lg overflow-hidden flex items-center justify-center bg-[var(--deep)] shadow-sm">
              <Image src="/logo.png" alt="Mola Logo" width={32} height={32} priority className="object-contain" />
            </div>
            <span>Mola</span>
          </Link>

          <nav className="flex items-center gap-4 sm:gap-6 text-sm font-semibold text-[var(--muted)]">
            <Link href="/#workflow" className="hover:text-[var(--text-primary)] transition-colors hidden sm:inline-block">
              Workflow
            </Link>
            <Link href="/#features" className="hover:text-[var(--text-primary)] transition-colors hidden sm:inline-block">
              Features
            </Link>
            <a
              href="https://github.com/mizan989/Mola-Web_Auditor"
              target="_blank"
              rel="noreferrer"
              className="w-9 h-9 grid place-items-center rounded-lg border border-[var(--border)] bg-white/30 hover:bg-white/60 hover:-translate-y-0.5 text-[var(--text-primary)] transition-all shadow-sm"
              aria-label="Mola GitHub Repository"
            >
              <svg className="w-4.5 h-4.5 fill-current" viewBox="0 0 24 24" aria-hidden="true">
                <path d="M12 .5A11.5 11.5 0 0 0 8.36 22.93c.58.1.79-.25.79-.56v-2.17c-3.2.7-3.87-1.35-3.87-1.35-.53-1.34-1.3-1.7-1.3-1.7-1.04-.71.08-.7.08-.7 1.15.08 1.75 1.18 1.75 1.18 1.02 1.75 2.68 1.24 3.34.95.1-.74.4-1.24.73-1.52-2.55-.29-5.23-1.28-5.23-5.7 0-1.26.45-2.29 1.18-3.1-.12-.29-.51-1.47.11-3.06 0 0 .96-.31 3.15 1.18a10.9 10.9 0 0 1 5.73 0c2.18-1.49 3.14-1.18 3.14-1.18.63 1.59.24 2.77.12 3.06.74.81 1.18 1.84 1.18 3.1 0 4.43-2.69 5.4-5.25 5.69.41.36.78 1.07.78 2.16v3.2c0 .31.21.67.8.55A11.5 11.5 0 0 0 12 .5Z" />
              </svg>
            </a>
          </nav>
        </header>

        {/* Main Content */}
        <div className="flex-1">
          {children}
        </div>

        {/* Footer */}
        <footer className="py-8 px-6 sm:px-12 border-t border-[var(--border)] flex flex-col sm:flex-row items-center justify-between gap-4 text-xs text-[var(--muted)] bg-[var(--background)]">
          <div className="flex items-center gap-3">
            <div className="w-5 h-5 rounded overflow-hidden flex items-center justify-center bg-[var(--deep)]">
              <Image src="/logo.png" alt="Mola Logo" width={20} height={20} className="object-contain" />
            </div>
            <span className="font-bold text-[var(--text-primary)]">Mola</span>
            <span>— Open-source evidence-based web auditing</span>
          </div>

          <div className="flex items-center gap-6">
            <Link href="/privacy" className="hover:text-[var(--text-primary)] transition-colors">
              Privacy
            </Link>
            <Link href="/terms" className="hover:text-[var(--text-primary)] transition-colors">
              Terms
            </Link>
            <a
              href="https://github.com/mizan989"
              target="_blank"
              rel="noreferrer"
              className="hover:text-[var(--text-primary)] transition-colors"
            >
              Built by Md Mizan
            </a>
          </div>
        </footer>
      </body>
    </html>
  );
}
