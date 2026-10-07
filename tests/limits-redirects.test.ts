import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  MAX_REDIRECTS,
  MAX_BODY_BYTES,
  SCAN_TIMEOUT_MS,
} from "../server/scanners/http.ts";
import { validateUrlAsync } from "../server/validators/url.ts";

describe("Scan Resource Limits & Redirect SSRF Defense (ISSUE-001, ISSUE-006, ISSUE-012, ISSUE-013, ISSUE-014)", () => {
  it("enforces a strict maximum redirect limit of 5 hops", () => {
    assert.equal(MAX_REDIRECTS, 5, "Maximum redirects must be capped at 5");
  });

  it("enforces a hard body size limit of 2.5MB to protect memory", () => {
    assert.equal(MAX_BODY_BYTES, 2.5 * 1024 * 1024, "Response body must be capped at 2.5MB");
  });

  it("enforces an operation-level scan deadline of 15 seconds", () => {
    assert.equal(SCAN_TIMEOUT_MS, 15000, "Operation deadline must be capped at 15000ms");
  });

  it("blocks SSRF redirect hops targeting localhost, loopback, or private IPs", async () => {
    const localhostHop = await validateUrlAsync("http://localhost/admin");
    assert.equal(localhostHop.isValid, false, "Localhost redirect hop must be blocked");

    const loopbackHop = await validateUrlAsync("http://127.0.0.1:80/secret");
    assert.equal(loopbackHop.isValid, false, "Loopback redirect hop must be blocked");

    const cloudMetaHop = await validateUrlAsync("http://169.254.169.254/latest/meta-data");
    assert.equal(cloudMetaHop.isValid, false, "Cloud metadata redirect hop must be blocked");

    const privateRangeHop = await validateUrlAsync("http://192.168.1.100/internal");
    assert.equal(privateRangeHop.isValid, false, "Private IP redirect hop must be blocked");
  });

  it("blocks redirect hops targeting non-standard web ports", async () => {
    const redisHop = await validateUrlAsync("http://example.com:6379");
    assert.equal(redisHop.isValid, false, "Redis port redirect hop must be blocked");

    const sshHop = await validateUrlAsync("http://example.com:22");
    assert.equal(sshHop.isValid, false, "SSH port redirect hop must be blocked");
  });
});
