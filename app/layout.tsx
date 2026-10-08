import type { Metadata, Viewport } from "next";
import Image from "next/image";
import Link from "next/link";
import { headers } from "next/headers";
import "./globals.css";

export const metadata: Metadata = {
  metadataBase: new URL("https://mola.antideploy.app"),
  alternates: {
    canonical: "https://mola.antideploy.app",
  },
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
    url: "https://mola.antideploy.app",
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

export default async function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  // Reading headers dynamically invokes per-request rendering and allows Next.js to apply the middleware CSP nonce to internal script tags
  await headers();
  return (
    <html lang="en">
      <head>
        <link
          rel="preload"
          href="/fonts/Inter.woff2"
          as="font"
          type="font/woff2"
          crossOrigin="anonymous"
        />
        <link
          rel="preload"
          href="/fonts/JetBrainsMono.woff2"
          as="font"
          type="font/woff2"
          crossOrigin="anonymous"
        />
      </head>
      <body className="min-h-screen flex flex-col bg-[var(--background)] text-[var(--text-primary)]">
        {/* Navbar */}
        <header className="h-[72px] px-4 sm:px-12 flex items-center justify-between border-b border-[var(--border)] bg-[var(--background)]/90 backdrop-blur-sm sticky top-0 z-50">
          <Link href="/" className="inline-flex items-center gap-3 font-extrabold tracking-tight text-lg text-[var(--text-primary)] hover:opacity-90 transition-opacity">
            <div className="w-8 h-8 rounded-lg overflow-hidden flex items-center justify-center bg-[var(--deep)] shadow-sm">
              <Image src="/logo.png" alt="Mola Logo" width={32} height={32} priority className="object-contain" />
            </div>
            <span>Mola</span>
          </Link>

          <nav className="flex items-center gap-2.5 sm:gap-6 text-xs sm:text-sm font-semibold text-[var(--muted)]">
            <Link href="/#workflow" className="hover:text-[var(--text-primary)] transition-colors px-2 py-1 rounded-md hover:bg-white/30">
              Workflow
            </Link>
            <Link href="/#features" className="hover:text-[var(--text-primary)] transition-colors px-2 py-1 rounded-md hover:bg-white/30">
              Features
            </Link>
            <a
              href="https://github.com/mizan989/Mola-Web_Auditor"
              target="_blank"
              rel="noreferrer"
              className="w-8 sm:w-9 h-8 sm:h-9 grid place-items-center rounded-lg border border-[var(--border)] bg-white/30 hover:bg-white/60 hover:-translate-y-0.5 text-[var(--text-primary)] transition-all shadow-sm"
              aria-label="Mola GitHub Repository"
            >
              <svg className="w-4 sm:w-4.5 h-4 sm:h-4.5 fill-current" viewBox="0 0 24 24" aria-hidden="true">
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
        <footer className="py-8 px-6 sm:px-12 border-t border-[var(--border)] flex flex-col md:flex-row items-center justify-between gap-6 text-xs text-[var(--muted)] bg-[var(--background)]">
          <div className="flex items-center gap-3">
            <div className="w-5 h-5 rounded overflow-hidden flex items-center justify-center bg-[var(--deep)]">
              <Image src="/logo.png" alt="Mola Logo" width={20} height={20} className="object-contain" />
            </div>
            <span className="font-bold text-[var(--text-primary)]">Mola</span>
            <span>— Open-source evidence-based web auditing</span>
          </div>

          {/* Social Links (Logos Only) */}
          <div className="flex items-center gap-2.5" aria-label="Social media profiles">
            <a
              href="https://github.com/mizan989"
              target="_blank"
              rel="noreferrer"
              aria-label="GitHub Profile"
              title="GitHub"
              className="w-8 h-8 rounded-lg border border-[var(--border)] bg-white/30 hover:bg-white/70 hover:-translate-y-0.5 text-[var(--muted)] hover:text-[var(--text-primary)] transition-all grid place-items-center shadow-xs"
            >
              <svg className="w-4 h-4 fill-current" viewBox="0 0 24 24" aria-hidden="true">
                <path fillRule="evenodd" clipRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" />
              </svg>
            </a>
            <a
              href="https://instagram.com/mizan989"
              target="_blank"
              rel="noreferrer"
              aria-label="Instagram Profile"
              title="Instagram"
              className="w-8 h-8 rounded-lg border border-[var(--border)] bg-white/30 hover:bg-white/70 hover:-translate-y-0.5 text-[var(--muted)] hover:text-[var(--text-primary)] transition-all grid place-items-center shadow-xs"
            >
              <svg className="w-4 h-4 fill-current" viewBox="0 0 24 24" aria-hidden="true">
                <path d="M12 2.163c3.204 0 3.584.012 4.85.07 3.252.148 4.771 1.691 4.919 4.919.058 1.265.069 1.645.069 4.849 0 3.205-.012 3.584-.069 4.849-.149 3.225-1.664 4.771-4.919 4.919-1.266.058-1.644.07-4.85.07-3.204 0-3.584-.012-4.849-.07-3.26-.149-4.771-1.699-4.919-4.92-.058-1.265-.07-1.644-.07-4.849 0-3.204.013-3.583.07-4.849.149-3.227 1.664-4.771 4.919-4.919 1.266-.057 1.645-.069 4.849-.069zm0-2.163c-3.259 0-3.667.014-4.947.072-4.358.2-6.78 2.618-6.98 6.98-.059 1.281-.073 1.689-.073 4.948 0 3.259.014 3.668.072 4.948.2 4.358 2.618 6.78 6.98 6.98 1.281.058 1.689.072 4.948.072 3.259 0 3.668-.014 4.948-.072 4.354-.2 6.782-2.618 6.979-6.98.059-1.28.073-1.689.073-4.948 0-3.259-.014-3.667-.072-4.947-.196-4.354-2.617-6.78-6.979-6.98-1.281-.059-1.69-.073-4.949-.073zm0 5.838c-3.403 0-6.162 2.759-6.162 6.162s2.759 6.163 6.162 6.163 6.162-2.759 6.162-6.163c0-3.403-2.759-6.162-6.162-6.162zm0 10.162c-2.209 0-4-1.79-4-4 0-2.209 1.791-4 4-4s4 1.791 4 4c0 2.21-1.791 4-4 4zm6.406-11.845c-.796 0-1.441.645-1.441 1.44s.645 1.44 1.441 1.44c.795 0 1.439-.645 1.439-1.44s-.644-1.44-1.439-1.44z" />
              </svg>
            </a>
            <a
              href="https://linkedin.com/in/mizan989"
              target="_blank"
              rel="noreferrer"
              aria-label="LinkedIn Profile"
              title="LinkedIn"
              className="w-8 h-8 rounded-lg border border-[var(--border)] bg-white/30 hover:bg-white/70 hover:-translate-y-0.5 text-[var(--muted)] hover:text-[var(--text-primary)] transition-all grid place-items-center shadow-xs"
            >
              <svg className="w-4 h-4 fill-current" viewBox="0 0 24 24" aria-hidden="true">
                <path d="M19 0h-14c-2.761 0-5 2.239-5 5v14c0 2.761 2.239 5 5 5h14c2.762 0 5-2.239 5-5v-14c0-2.761-2.238-5-5-5zm-11 19h-3v-11h3v11zm-1.5-12.268c-.966 0-1.75-.79-1.75-1.764s.784-1.764 1.75-1.764 1.75.79 1.75 1.764-.783 1.764-1.75 1.764zm13.5 12.268h-3v-5.604c0-3.368-4-3.113-4 0v5.604h-3v-11h3v1.765c1.396-2.586 7-2.777 7 2.476v6.759z" />
              </svg>
            </a>
            <a
              href="https://x.com/mizan989"
              target="_blank"
              rel="noreferrer"
              aria-label="X Profile"
              title="X"
              className="w-8 h-8 rounded-lg border border-[var(--border)] bg-white/30 hover:bg-white/70 hover:-translate-y-0.5 text-[var(--muted)] hover:text-[var(--text-primary)] transition-all grid place-items-center shadow-xs"
            >
              <svg className="w-3.5 h-3.5 fill-current" viewBox="0 0 24 24" aria-hidden="true">
                <path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z" />
              </svg>
            </a>
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
