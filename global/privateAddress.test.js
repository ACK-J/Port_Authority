/**
 * Node-runnable unit tests for global/privateAddress.js covering the
 * URL-filter bypass classes from the security submission.
 *
 * Run: node global/privateAddress.test.js
 */
import {
    isLocalRequestUrl,
    isLiteralIpHostname,
    isPrivateAddress,
    hostnameSuggestsIpRebinding,
    isUnspecifiedAddress,
} from "./privateAddress.js";

let passed = 0;
let failed = 0;

function assert(condition, message) {
    if (condition) {
        passed += 1;
        return;
    }
    failed += 1;
    console.error(`FAIL: ${message}`);
}

function assertBlock(urlString, reason) {
    const url = new URL(urlString);
    assert(
        isLocalRequestUrl(url) === true,
        `expected BLOCK for ${urlString} (${reason}); hostname=${url.hostname}`
    );
}

function assertAllow(urlString, reason) {
    const url = new URL(urlString);
    assert(
        isLocalRequestUrl(url) === false,
        `expected ALLOW for ${urlString} (${reason}); hostname=${url.hostname}`
    );
}

// --- IPv6 loopback / ULA / link-local (PoC) ---
assertBlock("http://[::1]/", "IPv6 loopback");
assertBlock("http://[::1]:22/", "IPv6 loopback with port");
assertBlock("ws://[::1]:6463/", "WebSocket IPv6 loopback");
assertBlock("wss://[::1]:443/", "WSS IPv6 loopback");
assertBlock("ftp://[::1]/", "FTP IPv6 loopback");
assertBlock("http://[0:0:0:0:0:0:0:1]/", "expanded IPv6 loopback");
assertBlock("http://[fc00::1]/", "ULA fc00::/7");
assertBlock("http://[fd00::1]/", "ULA fd00::/7");
assertBlock("http://[fe80::1]/", "link-local fe80::/10");
assert(isPrivateAddress("fe80::1%eth0") === true, "link-local with zone id");
assertBlock("http://[FE80::ABCD]/", "link-local case-insensitive");

// --- IPv4-mapped IPv6 (PoC + URL-normalized hex form) ---
assertBlock("http://[::ffff:127.0.0.1]/", "IPv4-mapped dotted (URL may normalize)");
assertBlock("http://[::ffff:7f00:1]/", "IPv4-mapped hex hextets");
assertBlock("http://[0:0:0:0:0:ffff:127.0.0.1]/", "expanded IPv4-mapped dotted");
assertBlock("http://[0:0:0:0:0:ffff:7f00:1]/", "expanded IPv4-mapped hex");
assertBlock("http://[::ffff:0a00:1]/", "IPv4-mapped 10.0.0.1");
assertBlock("http://[::ffff:c0a8:1]/", "IPv4-mapped 192.168.0.1");
assertAllow("http://[::ffff:808:808]/", "IPv4-mapped public 8.8.8.8");
assertAllow("http://[::ffff:8.8.8.8]/", "IPv4-mapped public dotted");

// --- Deprecated IPv4-compatible IPv6 ---
assertBlock("http://[::127.0.0.1]/", "IPv4-compatible loopback dotted");
assertBlock("http://[::7f00:1]/", "IPv4-compatible loopback hex");
assertBlock("http://[::]/", "IPv6 unspecified");

// --- Alternate IPv4 encodings (normalized by URL parser) ---
assertBlock("http://2130706433/", "32-bit integer 127.0.0.1");
assertBlock("http://2130706433:631/", "integer loopback with port");
assertBlock("http://0x7f000001/", "hex 127.0.0.1");
assertBlock("http://0x7f000001:5432/", "hex loopback with port");
assertBlock("http://0x7f.1/", "dotted hex 127.0.0.1");
assertBlock("http://0177.0.0.1/", "octal-ish 127.0.0.1");
assertBlock("http://0177.0.0.1:6379/", "octal loopback with port");
assertBlock("http://127.1/", "short-form 127.0.0.1");
assertBlock("http://127.1:8080/", "short-form with port");
assertBlock("http://127.0.1/", "3-octet short-form");
assertBlock("http://167772161/", "integer 10.0.0.1");

// --- Standard private IPv4 ranges ---
assertBlock("http://127.0.0.1/", "loopback");
assertBlock("http://127.255.255.255/", "loopback top");
assertBlock("http://10.0.0.1/", "10/8");
assertBlock("http://172.16.0.1/", "172.16/12 low");
assertBlock("http://172.31.255.255/", "172.16/12 high");
assertBlock("http://192.168.1.1/", "192.168/16");
assertBlock("http://169.254.1.1/", "link-local");
assertBlock("http://0.0.0.0/", "unspecified");
assertBlock("http://0.1.2.3/", "0/8");
assertBlock("http://localhost/", "localhost token");
assertBlock("http://localhost./", "localhost trailing dot");

// --- Previously missing ranges ---
assertBlock("http://100.64.0.1/", "CGNAT 100.64/10 low");
assertBlock("http://100.127.255.255/", "CGNAT 100.64/10 high");
assertAllow("http://100.63.255.255/", "below CGNAT");
assertAllow("http://100.128.0.0/", "above CGNAT");
assertBlock("http://198.18.0.1/", "benchmarking 198.18/15 low");
assertBlock("http://198.19.255.255/", "benchmarking 198.18/15 high");
assertAllow("http://198.17.0.1/", "below benchmarking");
assertAllow("http://198.20.0.1/", "above benchmarking");

// --- Public / non-local (must not false-positive) ---
assertAllow("http://8.8.8.8/", "public IPv4");
assertAllow("http://1.1.1.1/", "public IPv4");
assertAllow("http://172.32.0.1/", "just outside 172.16/12");
assertAllow("http://11.0.0.1/", "just outside 10/8");
assertAllow("http://example.com/", "public domain");
assertAllow("http://localhost.example.com/", "localhost subdomain must not match");
assertAllow("http://[2001:db8::1]/", "documentation IPv6");
assertAllow("http://[2001:4860:4860::8888]/", "public IPv6");
assertAllow("http://127.0.0.1.nip.io/", "public name (DNS path gated by rebinding heuristic)");

// --- Protocol filter ---
assertAllow("chrome://[::1]/", "unsupported protocol");
assert(
    (() => {
        try {
            // data: has no meaningful host; ensure we don't throw
            return isLocalRequestUrl(new URL("https://example.com/")) === false;
        } catch {
            return false;
        }
    })(),
    "https public domain allow"
);

// --- isPrivateAddress direct (DNS-resolved forms) ---
assert(isPrivateAddress("127.0.0.1") === true, "direct 127.0.0.1");
assert(isPrivateAddress("::1") === true, "direct ::1");
assert(isPrivateAddress("::ffff:7f00:1") === true, "direct mapped hex");
assert(isPrivateAddress("[::ffff:127.0.0.1]") === true, "bracketed mapped");
assert(isPrivateAddress("100.64.1.2") === true, "direct CGNAT");
assert(isPrivateAddress("198.18.0.1") === true, "direct benchmarking");
assert(isPrivateAddress("8.8.8.8") === false, "direct public");
assert(isPrivateAddress("2001:4860:4860::8888") === false, "direct public IPv6");

// --- isLiteralIpHostname ---
assert(isLiteralIpHostname("127.0.0.1") === true, "literal v4");
assert(isLiteralIpHostname("8.8.8.8") === true, "literal public v4");
assert(isLiteralIpHostname("[::1]") === true, "literal v6 bracketed");
assert(isLiteralIpHostname("::ffff:7f00:1") === true, "literal mapped");
assert(isLiteralIpHostname("example.com") === false, "domain not literal");
assert(isLiteralIpHostname("127.0.0.1.nip.io") === false, "nip.io not literal");

// --- DNS rebinding gating (false-positive prevention) ---
assert(hostnameSuggestsIpRebinding("csp.withgoogle.com") === false, "google CSP not rebind-like");
assert(hostnameSuggestsIpRebinding("www.google.com") === false, "google www not rebind-like");
assert(hostnameSuggestsIpRebinding("example.com") === false, "example.com not rebind-like");
assert(hostnameSuggestsIpRebinding("127.0.0.1.nip.io") === true, "nip.io rebind");
assert(hostnameSuggestsIpRebinding("192.168.1.1.sslip.io") === true, "sslip.io rebind");
assert(hostnameSuggestsIpRebinding("10.0.0.1.attacker.example") === true, "embedded LAN IP");
assert(hostnameSuggestsIpRebinding("2130706433.example.com") === true, "embedded integer IP");
assert(hostnameSuggestsIpRebinding("localtest.me") === true, "apex helper domain");
assert(hostnameSuggestsIpRebinding("foo.localtest.me") === true, "localtest.me helper");
assert(hostnameSuggestsIpRebinding("nip.io") === true, "apex nip.io");

assert(isUnspecifiedAddress("0.0.0.0") === true, "unspecified v4");
assert(isUnspecifiedAddress("::") === true, "unspecified v6");
assert(isUnspecifiedAddress("::ffff:0:0") === true, "unspecified mapped");
assert(isUnspecifiedAddress("127.0.0.1") === false, "loopback is not unspecified");
assert(isUnspecifiedAddress("8.8.8.8") === false, "public is not unspecified");

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
