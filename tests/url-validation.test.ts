import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { validateAndSanitizeUrl } from "../server/validators/url.ts";

describe("URL Validation (ISSUE-001, ISSUE-002, ISSUE-003)", () => {
  describe("Valid Public URLs", () => {
    it("allows standard public HTTPS URLs", () => {
      const res = validateAndSanitizeUrl("https://example.com");
      assert.equal(res.isValid, true);
      assert.equal(res.hostname, "example.com");
      assert.equal(res.normalizedUrl, "https://example.com/");
    });

    it("allows standard public HTTP URLs", () => {
      const res = validateAndSanitizeUrl("http://example.org/path?query=1");
      assert.equal(res.isValid, true);
      assert.equal(res.hostname, "example.org");
    });

    it("automatically prepends https:// to naked domains", () => {
      const res = validateAndSanitizeUrl("github.com");
      assert.equal(res.isValid, true);
      assert.equal(res.normalizedUrl, "https://github.com/");
    });

    it("allows standard explicit ports 80 and 443", () => {
      const res80 = validateAndSanitizeUrl("http://example.com:80");
      assert.equal(res80.isValid, true);

      const res443 = validateAndSanitizeUrl("https://example.com:443");
      assert.equal(res443.isValid, true);
    });
  });

  describe("Disallowed Protocols", () => {
    it("rejects non-HTTP/HTTPS protocols", () => {
      assert.equal(validateAndSanitizeUrl("ftp://example.com").isValid, false);
      assert.equal(validateAndSanitizeUrl("file:///etc/passwd").isValid, false);
      assert.equal(validateAndSanitizeUrl("gopher://example.com").isValid, false);
      assert.equal(validateAndSanitizeUrl("javascript:alert(1)").isValid, false);
    });
  });

  describe("Port Restrictions", () => {
    it("rejects non-standard ports", () => {
      assert.equal(validateAndSanitizeUrl("https://example.com:8080").isValid, false);
      assert.equal(validateAndSanitizeUrl("http://example.com:3000").isValid, false);
      assert.equal(validateAndSanitizeUrl("https://example.com:22").isValid, false);
      assert.equal(validateAndSanitizeUrl("https://example.com:6379").isValid, false);
    });
  });

  describe("Credentials in URL", () => {
    it("rejects URLs containing embedded credentials", () => {
      const res = validateAndSanitizeUrl("https://admin:secret@example.com");
      assert.equal(res.isValid, false);
      assert.match(res.error || "", /credentials/i);
    });
  });

  describe("Forbidden Hosts and Suffixes", () => {
    it("rejects loopback and cloud metadata hostnames", () => {
      assert.equal(validateAndSanitizeUrl("http://localhost").isValid, false);
      assert.equal(validateAndSanitizeUrl("http://127.0.0.1").isValid, false);
      assert.equal(validateAndSanitizeUrl("http://169.254.169.254").isValid, false);
      assert.equal(validateAndSanitizeUrl("http://metadata.google.internal").isValid, false);
    });

    it("rejects internal and reserved domain suffixes", () => {
      assert.equal(validateAndSanitizeUrl("http://app.local").isValid, false);
      assert.equal(validateAndSanitizeUrl("http://database.internal").isValid, false);
      assert.equal(validateAndSanitizeUrl("http://nas.lan").isValid, false);
      assert.equal(validateAndSanitizeUrl("http://secret.corp").isValid, false);
      assert.equal(validateAndSanitizeUrl("http://gateway.home.arpa").isValid, false);
    });

    it("rejects single-label internal hostnames without TLD", () => {
      assert.equal(validateAndSanitizeUrl("http://internaldb").isValid, false);
      assert.equal(validateAndSanitizeUrl("http://k8s-service").isValid, false);
    });
  });

  describe("Direct IP Hostnames", () => {
    it("rejects private IPv4 hostnames", () => {
      assert.equal(validateAndSanitizeUrl("http://192.168.1.1").isValid, false);
      assert.equal(validateAndSanitizeUrl("http://10.0.0.1").isValid, false);
      assert.equal(validateAndSanitizeUrl("http://172.16.0.1").isValid, false);
    });

    it("allows public IPv4 hostnames", () => {
      assert.equal(validateAndSanitizeUrl("http://93.184.216.34").isValid, true);
    });
  });

  describe("Input Length Limit", () => {
    it("rejects URLs exceeding 2048 characters", () => {
      const longUrl = "https://example.com/" + "a".repeat(2050);
      const res = validateAndSanitizeUrl(longUrl);
      assert.equal(res.isValid, false);
      assert.match(res.error || "", /maximum permitted length/i);
    });
  });
});
