import { extractURLHost, isHostAllowlisted } from "../global/allowlist.js";
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
    assertEqual(extractURLHost("http://[::1]:8080/"), "[::1]:8080", "IPv6 with port");
    assertEqual(extractURLHost("HTTPS://EXAMPLE.COM/Path"), "example.com", "hostname lowercased by URL");

    suite("extractURLHost rejects invalid input");
    await assertRejects(() => Promise.resolve(extractURLHost("")), "empty string throws");
    await assertRejects(() => Promise.resolve(extractURLHost("://")), "protocol-only throws");
    await assertRejects(() => Promise.resolve(extractURLHost("http://")), "empty host throws");

    suite("isHostAllowlisted exact match semantics");
    assert(isHostAllowlisted("example.com", ["example.com"]) === true, "exact match");
    assert(isHostAllowlisted("example.com", ["other.com", "example.com"]) === true, "match in list");
    assert(isHostAllowlisted("example.com", []) === false, "empty list");
    assert(isHostAllowlisted("sub.example.com", ["example.com"]) === false, "subdomain not implied");
    assert(isHostAllowlisted("example.com", ["sub.example.com"]) === false, "parent not matched by child entry");
    assert(isHostAllowlisted("example.com:8443", ["example.com"]) === false, "port-sensitive");
    assert(isHostAllowlisted("example.com:8443", ["example.com:8443"]) === true, "host:port exact");
    assert(isHostAllowlisted("Example.Com", ["example.com"]) === false, "case-sensitive host compare (URL.host is lowercase)");
}
