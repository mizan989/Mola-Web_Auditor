import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  isPrivateOrReservedIp,
  isPrivateOrReservedIPv4,
  isPrivateOrReservedIPv6,
} from "../server/validators/ip.ts";

describe("IP Validation (ISSUE-003)", () => {
  describe("IPv4 Blocking", () => {
    it("blocks IPv4 loopback (127.0.0.0/8)", () => {
      assert.equal(isPrivateOrReservedIPv4("127.0.0.1"), true);
      assert.equal(isPrivateOrReservedIPv4("127.255.255.255"), true);
      assert.equal(isPrivateOrReservedIPv4("127.1.2.3"), true);
    });

    it("blocks IPv4 RFC 1918 private ranges", () => {
      // 10.0.0.0/8
      assert.equal(isPrivateOrReservedIPv4("10.0.0.1"), true);
      assert.equal(isPrivateOrReservedIPv4("10.255.255.255"), true);
      // 172.16.0.0/12
      assert.equal(isPrivateOrReservedIPv4("172.16.0.1"), true);
      assert.equal(isPrivateOrReservedIPv4("172.31.255.255"), true);
      assert.equal(isPrivateOrReservedIPv4("172.20.10.5"), true);
      // 192.168.0.0/16
      assert.equal(isPrivateOrReservedIPv4("192.168.0.1"), true);
      assert.equal(isPrivateOrReservedIPv4("192.168.1.254"), true);
    });

    it("blocks IPv4 link-local and cloud metadata (169.254.0.0/16)", () => {
      assert.equal(isPrivateOrReservedIPv4("169.254.169.254"), true);
      assert.equal(isPrivateOrReservedIPv4("169.254.1.1"), true);
    });

    it("blocks carrier-grade NAT (100.64.0.0/10)", () => {
      assert.equal(isPrivateOrReservedIPv4("100.64.0.1"), true);
      assert.equal(isPrivateOrReservedIPv4("100.127.255.255"), true);
    });

    it("blocks multicast, broadcast, and reserved (224.0.0.0/4, 240.0.0.0/4)", () => {
      assert.equal(isPrivateOrReservedIPv4("224.0.0.1"), true);
      assert.equal(isPrivateOrReservedIPv4("240.0.0.1"), true);
      assert.equal(isPrivateOrReservedIPv4("255.255.255.255"), true);
      assert.equal(isPrivateOrReservedIPv4("0.0.0.0"), true);
    });

    it("allows routable public IPv4 addresses", () => {
      assert.equal(isPrivateOrReservedIPv4("1.1.1.1"), false);
      assert.equal(isPrivateOrReservedIPv4("8.8.8.8"), false);
      assert.equal(isPrivateOrReservedIPv4("93.184.216.34"), false);
      assert.equal(isPrivateOrReservedIPv4("142.250.190.46"), false);
      assert.equal(isPrivateOrReservedIPv4("172.15.255.255"), false);
      assert.equal(isPrivateOrReservedIPv4("172.32.0.1"), false);
    });
  });

  describe("IPv6 Blocking", () => {
    it("blocks IPv6 loopback and unspecified", () => {
      assert.equal(isPrivateOrReservedIPv6("::1"), true);
      assert.equal(isPrivateOrReservedIPv6("::"), true);
    });

    it("blocks IPv6 unique local addresses (fc00::/7)", () => {
      assert.equal(isPrivateOrReservedIPv6("fc00::1"), true);
      assert.equal(isPrivateOrReservedIPv6("fd12:3456:789a::1"), true);
    });

    it("blocks IPv6 link-local addresses (fe80::/10)", () => {
      assert.equal(isPrivateOrReservedIPv6("fe80::1"), true);
      assert.equal(isPrivateOrReservedIPv6("fe80::dead:beef:cafe:babe"), true);
    });

    it("blocks IPv4-mapped IPv6 pointing to private addresses", () => {
      assert.equal(isPrivateOrReservedIPv6("::ffff:127.0.0.1"), true);
      assert.equal(isPrivateOrReservedIPv6("::ffff:192.168.1.1"), true);
      assert.equal(isPrivateOrReservedIPv6("::ffff:10.0.0.1"), true);
      assert.equal(isPrivateOrReservedIPv6("::ffff:169.254.169.254"), true);
    });

    it("allows IPv4-mapped IPv6 pointing to public addresses", () => {
      assert.equal(isPrivateOrReservedIPv6("::ffff:8.8.8.8"), false);
      assert.equal(isPrivateOrReservedIPv6("::ffff:93.184.216.34"), false);
    });

    it("allows routable public IPv6 addresses", () => {
      assert.equal(isPrivateOrReservedIPv6("2606:4700:4700::1111"), false);
      assert.equal(isPrivateOrReservedIPv6("2001:4860:4860::8888"), false);
    });
  });

  describe("Universal Validator", () => {
    it("correctly identifies private and public strings", () => {
      assert.equal(isPrivateOrReservedIp("127.0.0.1"), true);
      assert.equal(isPrivateOrReservedIp("10.0.0.1"), true);
      assert.equal(isPrivateOrReservedIp("::1"), true);
      assert.equal(isPrivateOrReservedIp("93.184.216.34"), false);
      assert.equal(isPrivateOrReservedIp("2606:4700:4700::1111"), false);
      assert.equal(isPrivateOrReservedIp("invalid-ip"), true);
      assert.equal(isPrivateOrReservedIp(""), true);
    });
  });
});
