import Link from "next/link";
import { ArrowLeft, CheckCircle2, AlertOctagon, Terminal } from "lucide-react";

export default function TermsPage() {
  return (
    <main className="max-w-4xl mx-auto px-6 py-12 sm:py-16">
      <Link
        href="/"
        className="inline-flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-[var(--muted)] hover:text-[var(--text-primary)] mb-8 transition-colors"
      >
        <ArrowLeft className="w-4 h-4" /> Back to Auditor
      </Link>

      <div className="mb-10">
        <p className="text-xs font-extrabold uppercase tracking-widest text-[var(--muted)] mb-2">Terms of Service</p>
        <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-[var(--text-primary)]">
          Acceptable Use & Terms
        </h1>
        <p className="text-sm text-[var(--muted)] mt-2">Effective Date: October 2026 · Version 1.0</p>
      </div>

      <div className="space-y-8 text-[var(--text-primary)] text-sm leading-relaxed">
        <section className="p-6 rounded-xl border border-[var(--border)] bg-white/30 backdrop-blur-sm">
          <div className="flex items-center gap-3 font-bold text-base mb-3 text-[var(--dark)]">
            <CheckCircle2 className="w-5 h-5 text-[var(--muted)]" />
            <span>1. Authorized Purpose</span>
          </div>
          <p className="text-[var(--muted)]">
            Mola is designed for developers, engineering teams, and website owners who wish to evaluate the security configuration, SEO hygiene, performance, and accessibility posture of websites they own or are authorized to inspect.
          </p>
        </section>

        <section className="p-6 rounded-xl border border-[var(--border)] bg-white/30 backdrop-blur-sm">
          <div className="flex items-center gap-3 font-bold text-base mb-3 text-[var(--dark)]">
            <AlertOctagon className="w-5 h-5 text-[var(--muted)]" />
            <span>2. Prohibited Conduct</span>
          </div>
          <p className="text-[var(--muted)] mb-2">
            You agree not to use Mola to:
          </p>
          <ul className="list-disc pl-5 space-y-1 text-[var(--muted)]">
            <li>Execute denial-of-service floods or automated abusive crawling against third-party servers.</li>
            <li>Attempt to scan internal corporate networks, loopback IP addresses, or cloud metadata endpoints.</li>
            <li>Misrepresent Mola&apos;s findings as a formal cybersecurity certification or guarantee of zero vulnerabilities.</li>
          </ul>
        </section>

        <section className="p-6 rounded-xl border border-[var(--border)] bg-white/30 backdrop-blur-sm">
          <div className="flex items-center gap-3 font-bold text-base mb-3 text-[var(--dark)]">
            <Terminal className="w-5 h-5 text-[var(--muted)]" />
            <span>3. Disclaimer of Warranties</span>
          </div>
          <p className="text-[var(--muted)]">
            Mola is provided &ldquo;as is&rdquo; without warranties of any kind. Mola inspects observable public HTTP responses and HTML markup. It is not an invasive penetration testing suite and does not test for zero-day vulnerabilities, server-side code execution bugs, or deep cryptographic weaknesses.
          </p>
        </section>
      </div>
    </main>
  );
}
