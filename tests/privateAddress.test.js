/**
 * Node-runnable unit tests for global/privateAddress.js covering the
 * URL-filter bypass classes from the security submission and regression cases.
 *
 * Run via: node tests/run.js
 */
import {
    isLocalRequestUrl,
    isLiteralIpHostname,
    isPrivateAddress,
    hostnameSuggestsIpRebinding,
    isUnspecifiedAddress,
    normalizeHostname,
} from "../global/privateAddress.js";
import { suite, assert, assertEqual } from "./harness.js";

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

export async function run() {
    suite("IPv6 loopback / ULA / link-local");
    assertBlock("http://[::1]/", "IPv6 loopback");
    assertBlock("http://[::1]:22/", "IPv6 loopback with port");
    assertBlock("ws://[::1]:6463/", "WebSocket IPv6 loopback");
    assertBlock("wss://[::1]:443/", "WSS IPv6 loopback");
    assertBlock("ftp://[::1]/", "FTP IPv6 loopback");
    assertBlock("ftps://[::1]/", "FTPS IPv6 loopback");
    assertBlock("https://[::1]/", "HTTPS IPv6 loopback");
    assertBlock("http://[0:0:0:0:0:0:0:1]/", "expanded IPv6 loopback");
    assertBlock("http://[fc00::1]/", "ULA fc00::/7");
    assertBlock("http://[fd00::1]/", "ULA fd00::/7");
    assertBlock("http://[fd12:3456:789a:1::1]/", "ULA nested");
    assertBlock("http://[fe80::1]/", "link-local fe80::/10");
    assert(isPrivateAddress("fe80::1%eth0") === true, "link-local with zone id");
    assertBlock("http://[FE80::ABCD]/", "link-local case-insensitive");
    assertBlock("http://[fe9f::1]/", "link-local fe9f still in fe80::/10");
    assertBlock("http://[febf::1]/", "top of link-local fe80::/10");
    assertAllow("http://[fec0::1]/", "just outside link-local fe80::/10");

    suite("IPv4-mapped IPv6");
    assertBlock("http://[::ffff:127.0.0.1]/", "IPv4-mapped dotted (URL may normalize)");
    assertBlock("http://[::ffff:7f00:1]/", "IPv4-mapped hex hextets");
    assertBlock("http://[0:0:0:0:0:ffff:127.0.0.1]/", "expanded IPv4-mapped dotted");
    assertBlock("http://[0:0:0:0:0:ffff:7f00:1]/", "expanded IPv4-mapped hex");
    assertBlock("http://[::ffff:0a00:1]/", "IPv4-mapped 10.0.0.1");
    assertBlock("http://[::ffff:c0a8:1]/", "IPv4-mapped 192.168.0.1");
    assertBlock("http://[::ffff:a9fe:1]/", "IPv4-mapped 169.254.0.1");
    assertBlock("http://[::ffff:6440:1]/", "IPv4-mapped CGNAT 100.64.0.1");
    assertAllow("http://[::ffff:808:808]/", "IPv4-mapped public 8.8.8.8");
    assertAllow("http://[::ffff:8.8.8.8]/", "IPv4-mapped public dotted");
    assertAllow("http://[::ffff:0101:0101]/", "IPv4-mapped public 1.1.1.1");

    suite("Deprecated IPv4-compatible IPv6");
    assertBlock("http://[::127.0.0.1]/", "IPv4-compatible loopback dotted");
    assertBlock("http://[::7f00:1]/", "IPv4-compatible loopback hex");
    assertBlock("http://[::10.0.0.1]/", "IPv4-compatible 10/8");
    assertBlock("http://[::]/", "IPv6 unspecified");

    suite("Alternate IPv4 encodings");
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
    assertBlock("http://3232235521/", "integer 192.168.0.1");

    suite("Standard private IPv4 ranges");
    assertBlock("http://127.0.0.1/", "loopback");
    assertBlock("http://127.255.255.255/", "loopback top");
    assertBlock("http://10.0.0.1/", "10/8");
    assertBlock("http://10.255.255.255/", "10/8 top");
    assertBlock("http://172.16.0.1/", "172.16/12 low");
    assertBlock("http://172.31.255.255/", "172.16/12 high");
    assertBlock("http://192.168.1.1/", "192.168/16");
    assertBlock("http://192.168.255.255/", "192.168/16 top");
    assertBlock("http://169.254.1.1/", "link-local");
    assertBlock("http://0.0.0.0/", "unspecified");
    assertBlock("http://0.1.2.3/", "0/8");
    assertBlock("http://localhost/", "localhost token");
    assertBlock("http://localhost./", "localhost trailing dot");
    assertBlock("http://LOCALHOST/", "localhost case-insensitive via URL");

    suite("CGNAT and benchmarking ranges");
    assertBlock("http://100.64.0.1/", "CGNAT 100.64/10 low");
    assertBlock("http://100.127.255.255/", "CGNAT 100.64/10 high");
    assertAllow("http://100.63.255.255/", "below CGNAT");
    assertAllow("http://100.128.0.0/", "above CGNAT");
    assertBlock("http://198.18.0.1/", "benchmarking 198.18/15 low");
    assertBlock("http://198.19.255.255/", "benchmarking 198.18/15 high");
    assertAllow("http://198.17.0.1/", "below benchmarking");
    assertAllow("http://198.20.0.1/", "above benchmarking");

    suite("Public / non-local must not false-positive");
    assertAllow("http://8.8.8.8/", "public IPv4");
    assertAllow("http://1.1.1.1/", "public IPv4");
    assertAllow("http://172.32.0.1/", "just outside 172.16/12");
    assertAllow("http://172.15.255.255/", "just below 172.16/12");
    assertAllow("http://11.0.0.1/", "just outside 10/8");
    assertAllow("http://9.255.255.255/", "just below 10/8");
    assertAllow("http://example.com/", "public domain");
    assertAllow("http://localhost.example.com/", "localhost subdomain must not match");
    assertAllow("http://notlocalhost/", "near-localhost name");
    assertAllow("http://[2001:db8::1]/", "documentation IPv6");
    assertAllow("http://[2001:4860:4860::8888]/", "public IPv6");
    assertAllow("http://[2606:4700:4700::1111]/", "Cloudflare IPv6");
    assertAllow("http://127.0.0.1.nip.io/", "public name (DNS path gated by rebinding heuristic)");

    suite("Protocol filter");
    assertAllow("chrome://[::1]/", "unsupported protocol");
    assertAllow("about:blank", "about protocol");
    assert(
        isLocalRequestUrl(new URL("https://example.com/")) === false,
        "https public domain allow"
    );
    assertBlock("ws://127.0.0.1:6463/", "Discord-style websocket scan");
    assertBlock("wss://192.168.0.1:443/", "secure websocket LAN");

    suite("isPrivateAddress direct");
    assert(isPrivateAddress("127.0.0.1") === true, "direct 127.0.0.1");
    assert(isPrivateAddress("::1") === true, "direct ::1");
    assert(isPrivateAddress("::ffff:7f00:1") === true, "direct mapped hex");
    assert(isPrivateAddress("[::ffff:127.0.0.1]") === true, "bracketed mapped");
    assert(isPrivateAddress("100.64.1.2") === true, "direct CGNAT");
    assert(isPrivateAddress("198.18.0.1") === true, "direct benchmarking");
    assert(isPrivateAddress("8.8.8.8") === false, "direct public");
    assert(isPrivateAddress("2001:4860:4860::8888") === false, "direct public IPv6");
    assert(isPrivateAddress("") === false, "empty string");
    assert(isPrivateAddress("not-an-ip") === false, "garbage");
    assert(isPrivateAddress(null) === false, "null");
    assert(isPrivateAddress(undefined) === false, "undefined");
    assert(isPrivateAddress("999.999.999.999") === false, "invalid octets");
    assert(isPrivateAddress("127.0.0") === false, "incomplete v4");
    assert(isPrivateAddress("::gggg") === false, "invalid hextet");

    suite("isLiteralIpHostname");
    assert(isLiteralIpHostname("127.0.0.1") === true, "literal v4");
    assert(isLiteralIpHostname("8.8.8.8") === true, "literal public v4");
    assert(isLiteralIpHostname("[::1]") === true, "literal v6 bracketed");
    assert(isLiteralIpHostname("::ffff:7f00:1") === true, "literal mapped");
    assert(isLiteralIpHostname("example.com") === false, "domain not literal");
    assert(isLiteralIpHostname("127.0.0.1.nip.io") === false, "nip.io not literal");
    assert(isLiteralIpHostname("localhost") === false, "localhost is not an IP literal");

    suite("DNS rebinding gating");
    assert(hostnameSuggestsIpRebinding("csp.withgoogle.com") === false, "google CSP not rebind-like");
    assert(hostnameSuggestsIpRebinding("www.google.com") === false, "google www not rebind-like");
    assert(hostnameSuggestsIpRebinding("example.com") === false, "example.com not rebind-like");
    assert(hostnameSuggestsIpRebinding("ads.example.net") === false, "ordinary ads host");
    assert(hostnameSuggestsIpRebinding("127.0.0.1.nip.io") === true, "nip.io rebind");
    assert(hostnameSuggestsIpRebinding("192.168.1.1.sslip.io") === true, "sslip.io rebind");
    assert(hostnameSuggestsIpRebinding("10.0.0.1.xip.io") === true, "xip.io rebind");
    assert(hostnameSuggestsIpRebinding("10.0.0.1.attacker.example") === true, "embedded LAN IP");
    assert(hostnameSuggestsIpRebinding("2130706433.example.com") === true, "embedded integer IP");
    assert(hostnameSuggestsIpRebinding("0x7f000001.example.com") === true, "embedded hex IP");
    assert(hostnameSuggestsIpRebinding("localtest.me") === true, "apex helper domain");
    assert(hostnameSuggestsIpRebinding("foo.localtest.me") === true, "localtest.me helper");
    assert(hostnameSuggestsIpRebinding("nip.io") === true, "apex nip.io");
    assert(hostnameSuggestsIpRebinding("foo.lvh.me") === true, "lvh.me helper");
    assert(hostnameSuggestsIpRebinding("app.vcap.me") === true, "vcap.me helper");
    assert(hostnameSuggestsIpRebinding("site.lacolhost.com") === true, "lacolhost.com helper");
    assert(hostnameSuggestsIpRebinding("::1") === false, "v6 literal not rebind heuristic");

    suite("isUnspecifiedAddress");
    assert(isUnspecifiedAddress("0.0.0.0") === true, "unspecified v4");
    assert(isUnspecifiedAddress("::") === true, "unspecified v6");
    assert(isUnspecifiedAddress("::ffff:0:0") === true, "unspecified mapped");
    assert(isUnspecifiedAddress("[::]") === true, "bracketed unspecified");
    assert(isUnspecifiedAddress("127.0.0.1") === false, "loopback is not unspecified");
    assert(isUnspecifiedAddress("8.8.8.8") === false, "public is not unspecified");
    assert(isUnspecifiedAddress("::1") === false, "loopback v6 is not unspecified");

    suite("normalizeHostname");
    assertEqual(normalizeHostname("Example.COM."), "example.com", "strips trailing dots + lowercases");
    assertEqual(normalizeHostname("[::1]"), "::1", "strips IPv6 brackets");
    assertEqual(normalizeHostname("host.example..."), "host.example", "strips multiple trailing dots");
}
