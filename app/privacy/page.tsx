import Link from "next/link";
import { ArrowLeft, ShieldCheck, Lock, EyeOff, ServerOff } from "lucide-react";

export default function PrivacyPage() {
  return (
    <main className="max-w-4xl mx-auto px-6 py-12 sm:py-16">
      <Link
        href="/"
        className="inline-flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-[var(--muted)] hover:text-[var(--text-primary)] mb-8 transition-colors"
      >
        <ArrowLeft className="w-4 h-4" /> Back to Auditor
      </Link>

      <div className="mb-10">
        <p className="text-xs font-extrabold uppercase tracking-widest text-[var(--muted)] mb-2">Transparency & Security</p>
        <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-[var(--text-primary)]">
          Privacy Policy
        </h1>
        <p className="text-sm text-[var(--muted)] mt-2">Effective Date: October 2026 · Version 1.0</p>
      </div>

      <div className="space-y-8 text-[var(--text-primary)] text-sm leading-relaxed">
        <section className="p-6 rounded-xl border border-[var(--border)] bg-white/30 backdrop-blur-sm">
          <div className="flex items-center gap-3 font-bold text-base mb-3 text-[var(--dark)]">
            <ServerOff className="w-5 h-5 text-[var(--muted)]" />
            <span>1. Zero Persistent Data Retention</span>
          </div>
          <p className="text-[var(--muted)]">
            Mola is an open-source, stateless developer auditing tool. We do not store, archive, or retain your submitted URLs, response payloads, or audit findings on persistent database disks. Once an audit scan finishes and the structured results are transmitted to your client browser, all memory allocations for the scan are immediately garbage-collected.
          </p>
        </section>

        <section className="p-6 rounded-xl border border-[var(--border)] bg-white/30 backdrop-blur-sm">
          <div className="flex items-center gap-3 font-bold text-base mb-3 text-[var(--dark)]">
            <Lock className="w-5 h-5 text-[var(--muted)]" />
            <span>2. No Account or Personal Information Required</span>
          </div>
          <p className="text-[var(--muted)]">
            You do not need to register, provide an email address, or create an account to use Mola. We do not collect names, credit cards, billing details, or authentication credentials.
          </p>
        </section>

        <section className="p-6 rounded-xl border border-[var(--border)] bg-white/30 backdrop-blur-sm">
          <div className="flex items-center gap-3 font-bold text-base mb-3 text-[var(--dark)]">
            <EyeOff className="w-5 h-5 text-[var(--muted)]" />
            <span>3. No Third-Party Trackers or Surveillance Ad-Networks</span>
          </div>
          <p className="text-[var(--muted)]">
            Mola does not run surveillance advertising scripts, pixel beacons, or invasive analytics networks. We believe developer tools should respect user privacy by default.
          </p>
        </section>

        <section className="p-6 rounded-xl border border-[var(--border)] bg-white/30 backdrop-blur-sm">
          <div className="flex items-center gap-3 font-bold text-base mb-3 text-[var(--dark)]">
            <ShieldCheck className="w-5 h-5 text-[var(--muted)]" />
            <span>4. Egress & Target Protection</span>
          </div>
          <p className="text-[var(--muted)]">
            When Mola audits a public website, it only sends standard HTTP/HTTPS GET requests to retrieve publicly reachable HTML and headers. Mola strictly blocks all private network addresses (RFC 1918), loopback interfaces, and cloud metadata endpoints to prevent SSRF abuse.
          </p>
        </section>
      </div>
    </main>
  );
}
