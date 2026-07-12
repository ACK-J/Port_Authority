import {
    extractURLHost,
    isHostAllowlisted,
    normalizeAllowlistEntry,
    isCIDRAllowlistEntry,
    isIPOrCIDREntry,
    hostMatchesAllowlistEntry,
    requestMatchesAllowlist,
    ipInCIDR,
} from "../global/allowlist.js";
import { suite, assert, assertEqual, assertRejects } from "./harness.js";

export async function run() {
    suite("extractURLHost parsing");
    assertEqual(extractURLHost("https://example.com/path"), "example.com", "full https URL");
    assertEqual(extractURLHost("http://example.com"), "example.com", "http URL");
    assertEqual(extractURLHost("example.com"), "example.com", "bare domain");
    assertEqual(extractURLHost("  example.com  "), "example.com", "trims whitespace");
    assertEqual(extractURLHost("discord.com/invite/abcdefg"), "discord.com", "path without protocol");
    assertEqual(extractURLHost("example.com:8080"), "example.com:8080", "non-default port kept");
    assertEqual(extractURLHost("https://example.com:443/"), "example.com", "default https port dropped");
    assertEqual(extractURLHost("http://example.com:80/"), "example.com", "default http port dropped");
    assertEqual(extractURLHost("https://sub.domain.example.co.uk/x"), "sub.domain.example.co.uk", "multi-level domain");
    assertEqual(extractURLHost("http://127.0.0.1:3000/"), "127.0.0.1:3000", "IPv4 with port");
    assertEqual(extractURLHost("127.0.0.1"), "127.0.0.1", "bare IPv4");
    assertEqual(extractURLHost("127.0.0.1:3000"), "127.0.0.1:3000", "bare IPv4 with port");
    assertEqual(extractURLHost("http://[::1]:8080/"), "[::1]:8080", "IPv6 with port");
    assertEqual(extractURLHost("::1"), "[::1]", "bare IPv6 gets brackets");
    assertEqual(extractURLHost("[::1]"), "[::1]", "already-bracketed IPv6");
    assertEqual(extractURLHost("HTTPS://EXAMPLE.COM/Path"), "example.com", "hostname lowercased by URL");

    suite("extractURLHost rejects invalid input");
    await assertRejects(() => Promise.resolve(extractURLHost("")), "empty string throws");
    await assertRejects(() => Promise.resolve(extractURLHost("://")), "protocol-only throws");
    await assertRejects(() => Promise.resolve(extractURLHost("http://")), "empty host throws");

    suite("normalizeAllowlistEntry domains and IPs");
    assertEqual(normalizeAllowlistEntry("discord.com"), "discord.com", "domain");
    assertEqual(normalizeAllowlistEntry("https://example.com"), "example.com", "full URL with scheme");
    assertEqual(normalizeAllowlistEntry("https://example.com/path"), "example.com", "full URL with path");
    assertEqual(normalizeAllowlistEntry("discord.com/invite/abc"), "discord.com", "bare host with path");
    assertEqual(normalizeAllowlistEntry("http://127.0.0.1:3000/"), "127.0.0.1:3000", "IP URL with port and trailing slash");
    assertEqual(normalizeAllowlistEntry("127.0.0.1"), "127.0.0.1", "IPv4");
    assertEqual(normalizeAllowlistEntry("127.0.0.1:8080"), "127.0.0.1:8080", "IPv4 with port");
    assertEqual(normalizeAllowlistEntry("::1"), "[::1]", "IPv6");
    assertEqual(normalizeAllowlistEntry("192.168.1.0/24"), "192.168.1.0/24", "IPv4 CIDR preserved");
    assertEqual(normalizeAllowlistEntry("10.0.0.0/8"), "10.0.0.0/8", "IPv4 /8 CIDR");
    assertEqual(normalizeAllowlistEntry("fe80::/10"), "fe80::/10", "IPv6 CIDR");
    assertEqual(normalizeAllowlistEntry("[fe80::]/10"), "fe80::/10", "bracketed IPv6 CIDR normalized");
    assertEqual(normalizeAllowlistEntry("http://192.168.1.0/24"), "192.168.1.0/24", "scheme-prefixed CIDR");
    assertEqual(normalizeAllowlistEntry("192.168.1.0/24/"), "192.168.1.0/24", "CIDR with trailing slash");
    assertEqual(normalizeAllowlistEntry("https://10.0.0.0/8"), "10.0.0.0/8", "https-prefixed CIDR");
    assertEqual(normalizeAllowlistEntry("example.com/24"), "example.com", "domain with path-like slash is not CIDR");
    assertEqual(normalizeAllowlistEntry("not-a-cidr/24"), "not-a-cidr", "non-IP slash is treated as host/path");
    await assertRejects(() => Promise.resolve(normalizeAllowlistEntry("")), "empty throws");
    await assertRejects(() => Promise.resolve(normalizeAllowlistEntry("192.168.1.0/33")), "bad IPv4 prefix throws");
    await assertRejects(() => Promise.resolve(normalizeAllowlistEntry("fe80::/129")), "bad IPv6 prefix throws");
    await assertRejects(() => Promise.resolve(normalizeAllowlistEntry("http://192.168.1.0/33")), "scheme + bad prefix throws");


    suite("isCIDRAllowlistEntry / isIPOrCIDREntry");
    assert(isCIDRAllowlistEntry("192.168.1.0/24") === true, "IPv4 CIDR");
    assert(isCIDRAllowlistEntry("0.0.0.0/0") === true, "IPv4 /0");
    assert(isCIDRAllowlistEntry("fe80::/10") === true, "IPv6 CIDR");
    assert(isCIDRAllowlistEntry("192.168.1.0") === false, "IP alone not CIDR");
    assert(isCIDRAllowlistEntry("example.com") === false, "domain not CIDR");
    assert(isCIDRAllowlistEntry("192.168.1.0/33") === false, "invalid prefix");
    assert(isIPOrCIDREntry("127.0.0.1") === true, "portless IPv4");
    assert(isIPOrCIDREntry("127.0.0.1:8080") === false, "IPv4 with port is not open IP entry");
    assert(isIPOrCIDREntry("192.168.1.0/24") === true, "CIDR is IP-or-CIDR");
    assert(isIPOrCIDREntry("example.com") === false, "domain is not IP-or-CIDR");
    assert(isIPOrCIDREntry("[::1]") === true, "portless IPv6");
    assert(isIPOrCIDREntry("[::1]:8080") === false, "IPv6 with port is not open IP entry");

    suite("ipInCIDR");
    assert(ipInCIDR("192.168.1.50", "192.168.1.0/24") === true, "in /24");
    assert(ipInCIDR("192.168.2.50", "192.168.1.0/24") === false, "out of /24");
    assert(ipInCIDR("10.1.2.3", "10.0.0.0/8") === true, "in /8");
    assert(ipInCIDR("11.0.0.1", "10.0.0.0/8") === false, "out of /8");
    assert(ipInCIDR("127.0.0.1", "127.0.0.0/8") === true, "loopback /8");
    assert(ipInCIDR("8.8.8.8", "0.0.0.0/0") === true, "everything in /0");
    assert(ipInCIDR("192.168.1.1", "192.168.1.1/32") === true, "exact /32");
    assert(ipInCIDR("192.168.1.2", "192.168.1.1/32") === false, "other /32");
    assert(ipInCIDR("fe80::1", "fe80::/10") === true, "IPv6 link-local in /10");
    assert(ipInCIDR("2001:db8::1", "fe80::/10") === false, "doc IPv6 not in fe80::/10");
    assert(ipInCIDR("example.com", "192.168.1.0/24") === false, "domain not in CIDR");

    suite("isHostAllowlisted exact match semantics");
    assert(isHostAllowlisted("example.com", ["example.com"]) === true, "exact match");
    assert(isHostAllowlisted("example.com", ["other.com", "example.com"]) === true, "match in list");
    assert(isHostAllowlisted("example.com", []) === false, "empty list");
    assert(isHostAllowlisted("sub.example.com", ["example.com"]) === false, "subdomain not implied");
    assert(isHostAllowlisted("example.com", ["sub.example.com"]) === false, "parent not matched by child entry");
    assert(isHostAllowlisted("example.com:8443", ["example.com"]) === false, "port-sensitive domain");
    assert(isHostAllowlisted("example.com:8443", ["example.com:8443"]) === true, "host:port exact");
    assert(isHostAllowlisted("Example.Com", ["example.com"]) === false, "case-sensitive host compare (URL.host is lowercase)");

    suite("isHostAllowlisted IP address matching (issue #66)");
    assert(isHostAllowlisted("127.0.0.1", ["127.0.0.1"]) === true, "exact IPv4");
    assert(isHostAllowlisted("127.0.0.1:8080", ["127.0.0.1"]) === true, "portless IP matches any port");
    assert(isHostAllowlisted("127.0.0.1:3000", ["127.0.0.1"]) === true, "portless IP matches other port");
    assert(isHostAllowlisted("127.0.0.1:8080", ["127.0.0.1:8080"]) === true, "IP:port exact");
    assert(isHostAllowlisted("127.0.0.1:3000", ["127.0.0.1:8080"]) === false, "IP:port is port-sensitive");
    assert(isHostAllowlisted("10.0.0.1:8080", ["127.0.0.1"]) === false, "different IP not matched");
    assert(isHostAllowlisted("localhost:3000", ["127.0.0.1"]) === true, "localhost matches 127.0.0.1 entry");
    assert(isHostAllowlisted("127.0.0.1:3000", ["localhost"]) === false, "localhost entry is domain-exact (no port wildcard)");
    assert(hostMatchesAllowlistEntry("[::1]:8080", "[::1]") === true, "portless IPv6 matches any port");
    assert(hostMatchesAllowlistEntry("[::1]:8080", "[::1]:8080") === true, "IPv6:port exact");
    assert(hostMatchesAllowlistEntry("[::1]:3000", "[::1]:8080") === false, "IPv6:port is port-sensitive");
    assert(
        requestMatchesAllowlist("evil.example", "[::1]:80", ["[::1]"]) === true,
        "portless IPv6 entry matches destination"
    );
    assert(hostMatchesAllowlistEntry("[::ffff:127.0.0.1]:80", "127.0.0.1") === true, "IPv4-mapped loopback matches 127.0.0.1");
    assert(hostMatchesAllowlistEntry("[::ffff:7f00:1]:80", "127.0.0.1") === true, "IPv4-mapped hex loopback matches 127.0.0.1");
    assert(isHostAllowlisted("[::ffff:192.168.1.50]:8006", ["192.168.1.0/24"]) === true, "IPv4-mapped address matches IPv4 CIDR");

    suite("isHostAllowlisted CIDR matching (issue #64)");
    assert(isHostAllowlisted("192.168.1.50:8006", ["192.168.1.0/24"]) === true, "Proxmox-like origin in /24");
    assert(isHostAllowlisted("192.168.2.50:8006", ["192.168.1.0/24"]) === false, "outside /24");
    assert(isHostAllowlisted("10.0.5.1", ["10.0.0.0/8"]) === true, "in /8");
    assert(isHostAllowlisted("fe80::abcd:1", ["fe80::/10"]) === true, "IPv6 in CIDR");

    suite("requestMatchesAllowlist origin vs destination");
    assert(
        requestMatchesAllowlist("evil.example", "127.0.0.1:80", ["127.0.0.1"]) === true,
        "IP entry matches destination from untrusted origin"
    );
    assert(
        requestMatchesAllowlist("evil.example", "10.0.0.1:80", ["127.0.0.1"]) === false,
        "IP entry does not match other destination"
    );
    assert(
        requestMatchesAllowlist("evil.example", "127.0.0.1:80", ["discord.com"]) === false,
        "domain entry does not match destinations"
    );
    assert(
        requestMatchesAllowlist("discord.com", "127.0.0.1:80", ["discord.com"]) === true,
        "domain entry matches origin"
    );
    assert(
        requestMatchesAllowlist("", "127.0.0.1:80", ["127.0.0.1"]) === true,
        "file:// empty origin still matches IP destination"
    );
    assert(
        requestMatchesAllowlist("evil.example", "192.168.1.50:8008", ["192.168.1.0/24"]) === true,
        "CIDR entry matches destination"
    );
    assert(
        requestMatchesAllowlist("192.168.1.50:8006", "192.168.1.50:8008", ["192.168.1.0/24"]) === true,
        "CIDR matches Proxmox origin"
    );

    suite("review-fix regressions");
    // Bug: any '/' was treated as CIDR and rejected valid URLs/paths
    assertEqual(normalizeAllowlistEntry("https://discord.com/invite/x"), "discord.com", "URL with path not rejected as CIDR");
    assertEqual(normalizeAllowlistEntry("http://127.0.0.1:8080/status"), "127.0.0.1:8080", "IP URL with path extracts host:port");
    // Bug: scheme-prefixed / trailing-slash CIDR silently truncated to bare IP
    assertEqual(normalizeAllowlistEntry("http://192.168.1.0/24"), "192.168.1.0/24", "scheme CIDR keeps prefix");
    assertEqual(normalizeAllowlistEntry("192.168.1.0/24/"), "192.168.1.0/24", "trailing slash CIDR keeps prefix");
    assert(normalizeAllowlistEntry("http://192.168.1.0/24") !== "192.168.1.0", "scheme CIDR is not truncated to host");
    // Bug: IPv4-mapped literals did not match IPv4/CIDR allowlist entries
    assert(ipInCIDR("::ffff:192.168.1.50", "192.168.1.0/24") === true, "mapped IPv6 in IPv4 CIDR");
    assert(ipInCIDR("[::ffff:7f00:1]", "127.0.0.0/8") === true, "mapped hex loopback in 127/8");
    assert(
        requestMatchesAllowlist("evil.example", "[::ffff:127.0.0.1]:80", ["127.0.0.1"]) === true,
        "mapped loopback destination matches IPv4 allowlist"
    );
    // Bug: portless IPv6 must not rely on host===hostname (bracket differences)
    assert(isIPOrCIDREntry("[::1]") === true, "bracketed IPv6 is portless IP entry");
    assert(isIPOrCIDREntry("[::1]:8080") === false, "IPv6 with port is not a destination wildcard entry");
    assert(hostMatchesAllowlistEntry("[::1]:65535", "[::1]") === true, "IPv6 portless matches high port");
    // Bug: ::1 must not unwrap to 0.0.0.1 via deprecated IPv4-compatible ::/96
    assert(hostMatchesAllowlistEntry("0.0.0.1:80", "[::1]") === false, "::1 allowlist must not match 0.0.0.1");
    assert(hostMatchesAllowlistEntry("[::1]:80", "0.0.0.1") === false, "0.0.0.1 allowlist must not match ::1");
    assert(ipInCIDR("::1", "0.0.0.0/8") === false, "::1 is not in 0.0.0.0/8 via false unwrap");
    assert(hostMatchesAllowlistEntry("[::1]:8080", "[::1]") === true, "::1 still matches itself on any port");
}
