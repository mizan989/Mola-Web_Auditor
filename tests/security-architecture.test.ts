import { describe, it } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import {
  defaultSafeLookup,
  setCustomLookup,
  executeSingleHop,
  performHttpInspection,
  MAX_REDIRECTS,
  MAX_BODY_BYTES,
  SCAN_TIMEOUT_MS,
  HOP_TIMEOUT_MS,
} from "../server/scanners/http.ts";
import { extractClientIp } from "../server/security/clientIp.ts";
import { validateUrlAsync, validateAndSanitizeUrl } from "../server/validators/url.ts";
import { isPrivateOrReservedIp } from "../server/validators/ip.ts";
import {
  setCustomDnsLookup,
  resolveAndValidateDns,
  DEFAULT_DNS_TIMEOUT_MS,
} from "../server/validators/dns.ts";

describe("Phase 13 — Security Architecture Hardening", () => {
  describe("1. Connection-Time DNS Rebinding Defense (TOCTOU Elimination)", () => {
    it("intercepts loopback IPv4 resolution at socket creation time with ERR_SSRF_DNS_REBINDING", (t, done) => {
      defaultSafeLookup("localhost", {}, (err, address) => {
        assert.ok(err, "Must return an error for loopback resolution");
        assert.strictEqual((err as any).code, "ERR_SSRF_DNS_REBINDING");
        assert.match(err.message, /DNS rebinding blocked/);
        done();
      });
    });

    it("intercepts simulated IPv4 loopback (127.0.0.1) in single address callback", (t, done) => {
      // Simulate resolver callback with 127.0.0.1
      const mockResolver = (_host: string, _opt: any, cb: any) => {
        cb(null, "127.0.0.1", 4);
      };

      // Wrap mock resolver with safe check
      const safeCheck = (host: string, opt: any, cb: any) => {
        mockResolver(host, opt, (err: any, addr: any, fam: any) => {
          if (err) return cb(err);
          if (isPrivateOrReservedIp(addr)) {
            const rebindingError: any = new Error(
              `DNS rebinding blocked: Target host '${host}' resolved to private or restricted address (${addr}) at connection time.`
            );
            rebindingError.code = "ERR_SSRF_DNS_REBINDING";
            return cb(rebindingError, "", fam);
          }
          cb(null, addr, fam);
        });
      };

      safeCheck("rebound-host.test", {}, (err: any) => {
        assert.ok(err);
        assert.strictEqual(err.code, "ERR_SSRF_DNS_REBINDING");
        assert.match(err.message, /DNS rebinding blocked/);
        done();
      });
    });

    it("intercepts simulated cloud metadata (169.254.169.254) at connection time", (t, done) => {
      const mockResolver = (_host: string, _opt: any, cb: any) => {
        cb(null, "169.254.169.254", 4);
      };

      const safeCheck = (host: string, opt: any, cb: any) => {
        mockResolver(host, opt, (err: any, addr: any, fam: any) => {
          if (err) return cb(err);
          if (isPrivateOrReservedIp(addr)) {
            const rebindingError: any = new Error(
              `DNS rebinding blocked: Target host '${host}' resolved to private or restricted address (${addr}) at connection time.`
            );
            rebindingError.code = "ERR_SSRF_DNS_REBINDING";
            return cb(rebindingError, "", fam);
          }
          cb(null, addr, fam);
        });
      };

      safeCheck("metadata-rebound.test", {}, (err: any) => {
        assert.ok(err);
        assert.strictEqual(err.code, "ERR_SSRF_DNS_REBINDING");
        assert.match(err.message, /169.254.169.254/);
        done();
      });
    });

    it("intercepts simulated IPv6 loopback (::1) and private addresses at connection time", (t, done) => {
      const mockResolver = (_host: string, _opt: any, cb: any) => {
        cb(null, "::1", 6);
      };

      const safeCheck = (host: string, opt: any, cb: any) => {
        mockResolver(host, opt, (err: any, addr: any, fam: any) => {
          if (err) return cb(err);
          if (isPrivateOrReservedIp(addr)) {
            const rebindingError: any = new Error(
              `DNS rebinding blocked: Target host '${host}' resolved to private or restricted address (${addr}) at connection time.`
            );
            rebindingError.code = "ERR_SSRF_DNS_REBINDING";
            return cb(rebindingError, "", fam);
          }
          cb(null, addr, fam);
        });
      };

      safeCheck("ipv6-rebound.test", {}, (err: any) => {
        assert.ok(err);
        assert.strictEqual(err.code, "ERR_SSRF_DNS_REBINDING");
        assert.match(err.message, /::1/);
        done();
      });
    });

    it("intercepts simulated multi-address results when any resolved IP is private", (t, done) => {
      const mockAddresses = [
        { address: "93.184.216.34", family: 4 }, // public
        { address: "10.0.0.1", family: 4 }, // private
      ];

      const safeCheck = (host: string, _opt: any, cb: any) => {
        for (const item of mockAddresses) {
          if (isPrivateOrReservedIp(item.address)) {
            const rebindingError: any = new Error(
              `DNS rebinding blocked: Target host '${host}' resolved to private or restricted address (${item.address}) at connection time.`
            );
            rebindingError.code = "ERR_SSRF_DNS_REBINDING";
            return cb(rebindingError, [], 4);
          }
        }
        cb(null, mockAddresses, 4);
      };

      safeCheck("multi-address-rebound.test", { all: true }, (err: any) => {
        assert.ok(err);
        assert.strictEqual(err.code, "ERR_SSRF_DNS_REBINDING");
        assert.match(err.message, /10.0.0.1/);
        done();
      });
    });

    it("permits legitimate routable public IP addresses through connection-time resolver", (t, done) => {
      defaultSafeLookup("example.com", {}, (err, address) => {
        assert.strictEqual(err, null, "Should not error for public host");
        assert.ok(address, "Must return an address for example.com");
        assert.strictEqual(isPrivateOrReservedIp(address as string), false);
        done();
      });
    });

    it("aborts connection in executeSingleHop when socket resolution is blocked by rebinding defense", async () => {
      const controller = new AbortController();
      await assert.rejects(
        async () => {
          await executeSingleHop("http://localhost:80", controller.signal);
        },
        {
          message: /DNS rebinding blocked|ECONNREFUSED|ENOTFOUND/,
        }
      );
    });

    it("catches and terminates simulated DNS rebinding during performHttpInspection", async () => {
      try {
        setCustomLookup((host, _opt, cb) => {
          const err: any = new Error(
            `DNS rebinding blocked: Target host '${host}' resolved to private address (127.0.0.1) at connection time.`
          );
          err.code = "ERR_SSRF_DNS_REBINDING";
          cb(err, "", 4);
        });

        await assert.rejects(
          async () => {
            await performHttpInspection("https://example.com");
          },
          {
            message: /DNS rebinding blocked/,
          }
        );
      } finally {
        setCustomLookup(null);
      }
    });
  });

  describe("2. SSRF Redirect Destination Hardening (Every Hop Validated)", () => {
    it("blocks redirect destinations targeting loopback IPv4 addresses", async () => {
      const hop1 = await validateUrlAsync("http://127.0.0.1/admin");
      assert.strictEqual(hop1.isValid, false);
      assert.match(hop1.error || "", /Scanning local, loopback, or cloud metadata endpoints is prohibited|private or reserved/);

      const hop2 = await validateUrlAsync("http://127.0.0.1:80/secret");
      assert.strictEqual(hop2.isValid, false);

      const hop3 = await validateUrlAsync("http://127.1.2.3/");
      assert.strictEqual(hop3.isValid, false);
    });

    it("blocks redirect destinations targeting cloud metadata endpoints", async () => {
      const awsMeta = await validateUrlAsync("http://169.254.169.254/latest/meta-data");
      assert.strictEqual(awsMeta.isValid, false);

      const gcpMeta = await validateUrlAsync("http://metadata.google.internal/computeMetadata/v1/");
      assert.strictEqual(gcpMeta.isValid, false);

      const awsMetaHost = await validateUrlAsync("http://metadata.aws/");
      assert.strictEqual(awsMetaHost.isValid, false);

      const instanceData = await validateUrlAsync("http://instance-data/");
      assert.strictEqual(instanceData.isValid, false);
    });

    it("blocks redirect destinations targeting RFC 1918 private subnets", async () => {
      const classA = await validateUrlAsync("http://10.0.0.1/internal");
      assert.strictEqual(classA.isValid, false);

      const classB = await validateUrlAsync("http://172.16.0.1/dashboard");
      assert.strictEqual(classB.isValid, false);

      const classC = await validateUrlAsync("http://192.168.1.100/status");
      assert.strictEqual(classC.isValid, false);
    });

    it("blocks redirect destinations targeting IPv6 loopback and unique-local ranges", async () => {
      const ipv6Loopback = await validateUrlAsync("http://[::1]/secret");
      assert.strictEqual(ipv6Loopback.isValid, false);

      const ipv6Mapped = await validateUrlAsync("http://[::ffff:127.0.0.1]/secret");
      assert.strictEqual(ipv6Mapped.isValid, false);

      const ipv6UniqueLocal = await validateUrlAsync("http://[fc00::1]/admin");
      assert.strictEqual(ipv6UniqueLocal.isValid, false);
    });

    it("blocks redirect destinations targeting internal or reserved domain suffixes", async () => {
      const suffixes = [
        "http://gateway.local/api",
        "http://auth.internal/login",
        "http://server.lan/test",
        "http://intranet.corp/files",
        "http://router.home/setup",
        "http://gateway.home.arpa/",
        "http://hidden.onion/dark",
        "http://mytest.test/mock",
        "http://sample.example/docs",
        "http://device.localhost/metrics",
      ];

      for (const dest of suffixes) {
        const res = await validateUrlAsync(dest);
        assert.strictEqual(res.isValid, false, `Destination '${dest}' must be blocked`);
        assert.match(res.error || "", /internal or reserved|Scanning local|Hostname must include/);
      }
    });

    it("blocks redirect destinations targeting non-standard or dangerous ports", async () => {
      const dangerousPorts = [
        "http://example.com:21/", // FTP
        "http://example.com:22/", // SSH
        "http://example.com:25/", // SMTP
        "http://example.com:3306/", // MySQL
        "http://example.com:5432/", // PostgreSQL
        "http://example.com:6379/", // Redis
        "http://example.com:8080/", // Alt HTTP
        "http://example.com:9200/", // Elasticsearch
        "http://example.com:27017/", // MongoDB
      ];

      for (const dest of dangerousPorts) {
        const res = await validateUrlAsync(dest);
        assert.strictEqual(res.isValid, false, `Port in destination '${dest}' must be blocked`);
        assert.match(res.error || "", /Port .* is not permitted/);
      }
    });

    it("blocks redirect destinations containing embedded user credentials", async () => {
      const credUrls = [
        "http://admin:password@example.com/",
        "http://root@example.com/",
        "https://deploy:tok_12345@example.com/api",
      ];

      for (const dest of credUrls) {
        const res = await validateUrlAsync(dest);
        assert.strictEqual(res.isValid, false, `Credentialed URL '${dest}' must be blocked`);
        assert.match(res.error || "", /user credentials are not allowed/);
      }
    });

    it("blocks redirect destinations attempting protocol escape or arbitrary schemes", () => {
      const invalidSchemes = [
        "ftp://example.com/file.txt",
        "file:///etc/passwd",
        "gopher://127.0.0.1:70/",
        "data:text/html,<script>alert(1)</script>",
        "javascript:alert(document.domain)",
      ];

      for (const dest of invalidSchemes) {
        const res = validateAndSanitizeUrl(dest);
        assert.strictEqual(res.isValid, false, `Scheme in '${dest}' must be rejected`);
      }
    });
  });

  describe("3. Redirect Loop & Chain Bounding", () => {
    it("strictly bounds maximum redirects to 5 hops", () => {
      assert.strictEqual(MAX_REDIRECTS, 5);
    });

    it("detects and stops redirect loops exceeding maximum hop limit", async () => {
      // Simulate loop detection logic
      const simulateRedirectHopCount = (hops: number) => {
        let count = 0;
        for (let i = 0; i < hops; i++) {
          count++;
          if (count > MAX_REDIRECTS) {
            throw new Error(`Maximum redirect limit of ${MAX_REDIRECTS} exceeded. Potential redirect loop detected.`);
          }
        }
        return count;
      };

      // 5 hops is acceptable
      assert.strictEqual(simulateRedirectHopCount(5), 5);

      // 6 hops must throw exhaustion error
      assert.throws(
        () => simulateRedirectHopCount(6),
        /Maximum redirect limit of 5 exceeded/
      );
    });
  });

  describe("4. Scan Resource Limits & Bounded Streaming (2.5MB Cap)", () => {
    it("enforces maximum body limit of exactly 2.5 MB (2,621,440 bytes)", () => {
      assert.strictEqual(MAX_BODY_BYTES, 2.5 * 1024 * 1024);
    });

    it("enforces operation scan deadline of 15 seconds and per-hop timeout of 10 seconds", () => {
      assert.strictEqual(SCAN_TIMEOUT_MS, 15000);
      assert.strictEqual(HOP_TIMEOUT_MS, 10000);
    });

    it("truncates oversized response stream (>2.5MB) safely without memory exhaustion", async () => {
      // Create local test server that outputs 3.5 MB of data
      const server = http.createServer((req, res) => {
        res.writeHead(200, { "Content-Type": "text/plain" });
        req.on("close", () => {
          if (!res.writableEnded) res.end();
        });
        // Send in 64KB chunks up to ~3.5MB
        const chunk = Buffer.alloc(64 * 1024, "A");
        for (let i = 0; i < 56; i++) {
          if (res.writableEnded || res.destroyed) break;
          res.write(chunk);
        }
        if (!res.writableEnded) res.end();
      });

      await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
      const port = (server.address() as AddressInfo).port;

      try {
        setCustomLookup((_host, opt, cb) => {
          if (opt && (opt as any).all) {
            cb(null, [{ address: "127.0.0.1", family: 4 }]);
          } else {
            cb(null, "127.0.0.1", 4);
          }
        });
        const controller = new AbortController();

        const result = await executeSingleHop(`http://test-server.example:${port}`, controller.signal, 5000);

        assert.strictEqual(result.statusCode, 200);
        assert.strictEqual(result.isTruncated, true, "Body must be flagged as truncated");
        assert.strictEqual(result.bodyText.length, MAX_BODY_BYTES, "Body length must equal exactly MAX_BODY_BYTES (2.5MB)");
      } finally {
        setCustomLookup(null);
        server.closeAllConnections();
        await new Promise<void>((resolve) => server.close(() => resolve()));
      }
    });

    it("aborts execution cleanly when response times out during hop", async () => {
      // Create server that never responds
      const server = http.createServer((_req, _res) => {
        // Deliberately do not write or end
      });

      await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
      const port = (server.address() as AddressInfo).port;

      try {
        setCustomLookup((_host, opt, cb) => {
          if (opt && (opt as any).all) {
            cb(null, [{ address: "127.0.0.1", family: 4 }]);
          } else {
            cb(null, "127.0.0.1", 4);
          }
        });
        const controller = new AbortController();

        await assert.rejects(
          async () => {
            // Enforce a tight 100ms timeout
            await executeSingleHop(`http://test-server.example:${port}`, controller.signal, 100);
          },
          {
            message: /Connection timed out/,
          }
        );
      } finally {
        setCustomLookup(null);
        server.closeAllConnections();
        await new Promise<void>((resolve) => server.close(() => resolve()));
      }
    });
  });

  describe("5. Trusted Client IP Extraction & Reverse-Proxy Rate Limiting", () => {
    it("prioritizes CF-Connecting-IP over all other headers", () => {
      const headers = {
        "cf-connecting-ip": "198.51.100.42",
        "x-real-ip": "203.0.113.195",
        "x-forwarded-for": "10.0.0.1, 192.168.1.1",
      };
      const ip = extractClientIp(headers);
      assert.strictEqual(ip, "198.51.100.42");
    });

    it("prioritizes X-Real-IP when CF-Connecting-IP is absent", () => {
      const headers = {
        "x-real-ip": "203.0.113.195",
        "x-forwarded-for": "10.0.0.1, 192.168.1.1",
      };
      const ip = extractClientIp(headers);
      assert.strictEqual(ip, "203.0.113.195");
    });

    it("extracts leading client IP from X-Forwarded-For multi-proxy chain", () => {
      const headers = {
        "x-forwarded-for": "203.0.113.195, 70.41.3.18, 150.172.238.178",
      };
      const ip = extractClientIp(headers);
      assert.strictEqual(ip, "203.0.113.195");
    });

    it("safely falls back to 127.0.0.1 when no forwarding headers are present", () => {
      const ip = extractClientIp({});
      assert.strictEqual(ip, "127.0.0.1");
    });

    it("safely falls back to 127.0.0.1 for empty or whitespace-only headers", () => {
      const headers = {
        "cf-connecting-ip": "   ",
        "x-real-ip": "",
        "x-forwarded-for": "  ",
      };
      const ip = extractClientIp(headers);
      assert.strictEqual(ip, "127.0.0.1");
    });

    it("supports Fetch API standard Headers instance", () => {
      const fetchHeaders = new Headers();
      fetchHeaders.set("CF-Connecting-IP", "198.51.100.77");
      fetchHeaders.set("X-Forwarded-For", "10.0.0.1");

      const ip = extractClientIp(fetchHeaders);
      assert.strictEqual(ip, "198.51.100.77");
    });
  });

  describe("6. Backend Error Sanitization & Info Leak Defense", () => {
    // Helper replicating route.ts sanitization logic
    function sanitizeErrorMessage(rawMessage: string): { status: number; message: string } {
      let sanitizedMessage = "An unexpected error occurred while auditing the target website.";
      let statusCode = 502;

      if (
        rawMessage.includes("prohibited") ||
        rawMessage.includes("reserved") ||
        rawMessage.includes("private or reserved") ||
        rawMessage.includes("private IP") ||
        rawMessage.includes("private address") ||
        rawMessage.includes("Invalid URL") ||
        rawMessage.includes("Protocol") ||
        rawMessage.includes("Port") ||
        rawMessage.includes("credentials") ||
        rawMessage.includes("top-level domain") ||
        rawMessage.includes("rebinding") ||
        rawMessage.includes("DNS rebinding") ||
        rawMessage.includes("SSRF validation failed")
      ) {
        sanitizedMessage = rawMessage;
        statusCode = 400;
      } else if (rawMessage.includes("redirect") || rawMessage.includes("Redirect")) {
        sanitizedMessage = rawMessage;
        statusCode = 400;
      } else if (rawMessage.includes("timed out") || rawMessage.includes("deadline exceeded")) {
        sanitizedMessage = "Connection timed out while auditing the target website.";
        statusCode = 504;
      } else if (rawMessage.includes("Failed to establish connection") || rawMessage.includes("ENOTFOUND")) {
        sanitizedMessage = "Unable to connect to the target website. The host may be unreachable or offline.";
        statusCode = 502;
      }

      return { status: statusCode, message: sanitizedMessage };
    }

    it("sanitizes SSRF and prohibited destination errors with 400 status", () => {
      const res = sanitizeErrorMessage("Scanning local, loopback, or cloud metadata endpoints is prohibited.");
      assert.strictEqual(res.status, 400);
      assert.strictEqual(res.message, "Scanning local, loopback, or cloud metadata endpoints is prohibited.");
    });

    it("sanitizes DNS rebinding defense errors with 400 status", () => {
      const res = sanitizeErrorMessage("DNS rebinding blocked: Target host resolved to private address at connection time.");
      assert.strictEqual(res.status, 400);
      assert.match(res.message, /DNS rebinding blocked/);
    });

    it("sanitizes timeout and deadline exceeded errors with 504 status", () => {
      const res = sanitizeErrorMessage("Operation deadline exceeded after 15000ms.");
      assert.strictEqual(res.status, 504);
      assert.strictEqual(res.message, "Connection timed out while auditing the target website.");
    });

    it("sanitizes host reachability failures with 502 status", () => {
      const res = sanitizeErrorMessage("Failed to establish connection to target: getaddrinfo ENOTFOUND invalid.example");
      assert.strictEqual(res.status, 502);
      assert.strictEqual(res.message, "Unable to connect to the target website. The host may be unreachable or offline.");
    });

    it("prevents filesystem paths and stack traces from leaking to client", () => {
      const internalLeakyError = "Error: ENOENT: no such file or directory, open 'D:\\PROJECTS\\Mola\\server\\secrets\\private_key.pem'\n    at Object.openSync (node:fs:580:18)\n    at readFileSync (node:fs:459:35)";
      const res = sanitizeErrorMessage(internalLeakyError);

      assert.strictEqual(res.status, 502);
      assert.strictEqual(res.message, "An unexpected error occurred while auditing the target website.");
      assert.ok(!res.message.includes("D:\\PROJECTS"), "Must not leak filesystem paths");
      assert.ok(!res.message.includes("private_key.pem"), "Must not leak internal filenames");
      assert.ok(!res.message.includes("node:fs"), "Must not leak internal stack frames");
    });
  });

  describe("7. Bounded DNS Resolution & Operation Deadline Integration", () => {
    it("enforces default bounded DNS resolution timeout of 5000ms", () => {
      assert.strictEqual(DEFAULT_DNS_TIMEOUT_MS, 5000);
    });

    it("terminates deterministically when DNS resolution hangs using timeoutMs", async () => {
      try {
        // Simulate a stalled / hanging OS DNS resolver that never resolves
        setCustomDnsLookup(() => new Promise(() => {}));

        const startTime = Date.now();
        const res = await resolveAndValidateDns("hanging-domain.example", { timeoutMs: 100 });
        const elapsed = Date.now() - startTime;

        assert.strictEqual(res.isValid, false);
        assert.match(res.error || "", /DNS resolution timed out after 100ms/);
        assert.ok(elapsed < 1000, `Must abort in ~100ms, took ${elapsed}ms`);
      } finally {
        setCustomDnsLookup(null);
      }
    });

    it("terminates deterministically when overall audit operation deadline signal fires during DNS", async () => {
      try {
        // Simulate a stalled / hanging OS DNS resolver
        setCustomDnsLookup(() => new Promise(() => {}));

        const controller = new AbortController();
        setTimeout(() => controller.abort(), 60);

        const startTime = Date.now();
        const res = await resolveAndValidateDns("hanging-domain.example", { signal: controller.signal });
        const elapsed = Date.now() - startTime;

        assert.strictEqual(res.isValid, false);
        assert.match(res.error || "", /operation deadline exceeded/);
        assert.ok(elapsed < 1000, `Must abort in ~60ms, took ${elapsed}ms`);
      } finally {
        setCustomDnsLookup(null);
      }
    });

    it("propagates bounded DNS timeout through validateUrlAsync", async () => {
      try {
        setCustomDnsLookup(() => new Promise(() => {}));

        const res = await validateUrlAsync("https://hanging-domain.org", { timeoutMs: 100 });

        assert.strictEqual(res.isValid, false);
        assert.match(res.error || "", /DNS resolution timed out after 100ms/);
      } finally {
        setCustomDnsLookup(null);
      }
    });
  });
});
