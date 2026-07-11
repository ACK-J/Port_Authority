/**
 * Exhaustive coverage of evaluateRequest decision paths used by background.js.
 */
import {
    evaluateRequest,
    THREATMETRIX_CNAME,
    THREATMETRIX_SUFFIXES,
    matchesThreatMetrixHost,
    normalizeHostname,
    createDnsResultCache,
} from "../global/requestFilter.js";
import { suite, assert, assertEqual } from "./harness.js";

function req(overrides = {}) {
    return {
        thirdParty: true,
        originUrl: "https://evil.example/",
        url: "http://127.0.0.1:8080/",
        tabId: 1,
        ...overrides,
    };
}

function deps(overrides = {}) {
    return {
        getAllowedDomains: async () => [],
        resolveDns: async () => ({ addresses: ["93.184.216.34"], canonicalName: "example.com" }),
        ...overrides,
    };
}

export async function run() {
    suite("first-party and allowlist short circuits");
    {
        const result = await evaluateRequest(req({ thirdParty: false }), deps());
        assertEqual(result.cancel, false, "first-party not cancelled");
        assertEqual(result.reason, "first-party", "first-party reason");
    }
    {
        const result = await evaluateRequest(
            req({ originUrl: "https://trusted.example/" }),
            deps({ getAllowedDomains: async () => ["trusted.example"] })
        );
        assertEqual(result.cancel, false, "allowlisted host allowed");
        assertEqual(result.reason, "allowlisted", "allowlisted reason");
    }
    {
        // Subdomains are NOT implicitly allowlisted
        const result = await evaluateRequest(
            req({ originUrl: "https://sub.trusted.example/" }),
            deps({ getAllowedDomains: async () => ["trusted.example"] })
        );
        assertEqual(result.cancel, true, "subdomain of allowlisted host still blocked for local IP");
        assertEqual(result.reason, "portscan", "still portscan for local target");
    }
    {
        const result = await evaluateRequest(
            req({ originUrl: "https://trusted.example:8443/" }),
            deps({ getAllowedDomains: async () => ["trusted.example:8443"] })
        );
        assertEqual(result.cancel, false, "allowlist matches host:port exactly");
    }

    suite("malformed URLs fail open");
    {
        const result = await evaluateRequest(req({ originUrl: "not a url" }), deps());
        assertEqual(result.cancel, false, "bad origin fails open");
        assertEqual(result.reason, "unparseable-origin", "unparseable origin reason");
    }
    {
        const result = await evaluateRequest(req({ url: "http://[bad" }), deps());
        assertEqual(result.cancel, false, "bad request URL fails open");
        assertEqual(result.reason, "unparseable-url", "unparseable url reason");
    }

    suite("literal private hosts are blocked as port scans");
    const localTargets = [
        "http://127.0.0.1/",
        "http://127.0.0.1:22/",
        "http://10.0.0.5:445/",
        "http://192.168.1.1:80/",
        "http://172.16.0.1:8080/",
        "http://[::1]:6463/",
        "ws://127.0.0.1:6463/",
        "wss://192.168.0.1:443/",
        "ftp://10.0.0.1/",
        "http://localhost/",
        "http://169.254.1.1/",
        "http://100.64.0.1/",
        "http://198.18.0.1/",
        "http://0x7f000001/",
        "http://2130706433/",
        "http://[::ffff:127.0.0.1]/",
        "http://[fc00::1]/",
        "http://[fe80::1]/",
    ];
    for (const url of localTargets) {
        const result = await evaluateRequest(req({ url }), deps());
        assert(result.cancel === true && result.reason === "portscan", `block portscan for ${url}`);
        assert(result.url instanceof URL, `url object returned for ${url}`);
    }

    suite("literal public IPs are allowed without DNS");
    {
        let dnsCalled = false;
        const result = await evaluateRequest(
            req({ url: "http://8.8.8.8/" }),
            deps({
                resolveDns: async () => {
                    dnsCalled = true;
                    return { addresses: [], canonicalName: "" };
                },
            })
        );
        assertEqual(result.cancel, false, "public literal allowed");
        assertEqual(result.reason, "literal-ip", "literal-ip reason");
        assert(dnsCalled === false, "DNS must not be called for literal IPs");
    }
    {
        const result = await evaluateRequest(req({ url: "http://[2001:4860:4860::8888]/" }), deps());
        assertEqual(result.cancel, false, "public IPv6 literal allowed");
        assertEqual(result.reason, "literal-ip", "literal-ip for v6");
    }

    suite("DNS rebinding hosts that resolve privately are blocked");
    {
        const result = await evaluateRequest(
            req({ url: "http://127.0.0.1.nip.io/" }),
            deps({
                resolveDns: async () => ({
                    addresses: ["127.0.0.1"],
                    canonicalName: "127.0.0.1.nip.io",
                }),
            })
        );
        assertEqual(result.cancel, true, "nip.io private resolve blocked");
        assertEqual(result.reason, "portscan", "rebinding portscan reason");
    }
    {
        const result = await evaluateRequest(
            req({ url: "http://192.168.1.50.sslip.io:8080/" }),
            deps({
                resolveDns: async () => ({
                    addresses: ["192.168.1.50"],
                    canonicalName: "192.168.1.50.sslip.io",
                }),
            })
        );
        assertEqual(result.cancel, true, "sslip.io private resolve blocked");
    }
    {
        const result = await evaluateRequest(
            req({ url: "http://10.0.0.1.attacker.example/" }),
            deps({
                resolveDns: async () => ({
                    addresses: ["10.0.0.1"],
                    canonicalName: "10.0.0.1.attacker.example",
                }),
            })
        );
        assertEqual(result.cancel, true, "embedded-IP hostname blocked");
    }
    {
        const result = await evaluateRequest(
            req({ url: "http://foo.localtest.me/" }),
            deps({
                resolveDns: async () => ({
                    addresses: ["127.0.0.1"],
                    canonicalName: "foo.localtest.me",
                }),
            })
        );
        assertEqual(result.cancel, true, "localtest.me helper blocked");
    }

    suite("DNS sinkholes on ordinary domains must NOT look like port scans");
    {
        const result = await evaluateRequest(
            req({ url: "https://ads.tracker.example/pixel.gif" }),
            deps({
                resolveDns: async () => ({
                    addresses: ["0.0.0.0"],
                    canonicalName: "ads.tracker.example",
                }),
            })
        );
        assertEqual(result.cancel, false, "0.0.0.0 sinkhole on ordinary domain allowed");
        assertEqual(result.reason, "clean", "sinkhole is clean not portscan");
    }
    {
        const result = await evaluateRequest(
            req({ url: "https://csp.withgoogle.com/something" }),
            deps({
                resolveDns: async () => ({
                    addresses: ["127.0.0.1"],
                    canonicalName: "csp.withgoogle.com",
                }),
            })
        );
        assertEqual(result.cancel, false, "127.0.0.1 sinkhole on google CSP allowed");
    }
    {
        // Even for rebinding-like names, unspecified addresses are skipped
        const result = await evaluateRequest(
            req({ url: "http://127.0.0.1.nip.io/" }),
            deps({
                resolveDns: async () => ({
                    addresses: ["0.0.0.0", "::"],
                    canonicalName: "127.0.0.1.nip.io",
                }),
            })
        );
        assertEqual(result.cancel, false, "rebinding name with only unspecified answers allowed");
    }
    {
        // Mixed answers: skip unspecified, block on private
        const result = await evaluateRequest(
            req({ url: "http://127.0.0.1.nip.io/" }),
            deps({
                resolveDns: async () => ({
                    addresses: ["0.0.0.0", "127.0.0.1"],
                    canonicalName: "127.0.0.1.nip.io",
                }),
            })
        );
        assertEqual(result.cancel, true, "rebinding name blocked when any private answer remains");
    }

    suite("ThreatMetrix suffix matching (host + CNAME, trailing-dot safe)");
    assert(Array.isArray(THREATMETRIX_SUFFIXES), "suffix list is an array");
    assert(THREATMETRIX_SUFFIXES.includes("online-metrix.net"), "includes online-metrix.net");
    assert(THREATMETRIX_SUFFIXES.includes("threatmetrix.com"), "includes threatmetrix.com");
    assert(THREATMETRIX_SUFFIXES.includes("lexisnexisrisk.com"), "includes lexisnexisrisk.com");
    assert(THREATMETRIX_SUFFIXES.includes("lnrsoftware.com"), "includes lnrsoftware.com");

    assertEqual(normalizeHostname("H.Online-Metrix.NET."), "h.online-metrix.net", "normalize strips trailing dots + lowercases");
    assertEqual(normalizeHostname("example.com"), "example.com", "normalize leaves bare host");

    const positiveHosts = [
        "online-metrix.net",
        "h.online-metrix.net",
        "CUSTOMER.online-metrix.net",
        "h-us.online-metrix.net.",
        "threatmetrix.com",
        "www.threatmetrix.com",
        "lexisnexisrisk.com",
        "www.lexisnexisrisk.com.",
        "lnrsoftware.com",
        "www.lnrsoftware.com",
    ];
    for (const host of positiveHosts) {
        assert(matchesThreatMetrixHost(host) === true, `match ThreatMetrix host ${host}`);
        assert(THREATMETRIX_CNAME.test(host) === true, `compat wrapper matches ${host}`);
    }

    const negativeHosts = [
        "evil-online-metrix.net",
        "online-metrix.net.evil.com",
        "notthreatmetrix.com",
        "api.threatmetrix.com.evil.example",
        "example.com",
        "metrix.net",
        "",
    ];
    for (const host of negativeHosts) {
        assert(matchesThreatMetrixHost(host) === false, `reject lookalike ${JSON.stringify(host)}`);
    }

    {
        // Direct host match — no DNS (threatmetrix.com resolves; api. does not)
        let dnsCalled = false;
        const result = await evaluateRequest(
            req({ url: "https://threatmetrix.com/" }),
            deps({
                resolveDns: async () => {
                    dnsCalled = true;
                    return { addresses: ["203.0.113.1"], canonicalName: "threatmetrix.com" };
                },
            })
        );
        assertEqual(result.cancel, true, "threatmetrix.com host blocked");
        assertEqual(result.reason, "threatmetrix", "threatmetrix reason for direct host");
        assert(dnsCalled === false, "DNS skipped for known ThreatMetrix host");
    }
    {
        let dnsCalled = false;
        const result = await evaluateRequest(
            req({ url: "https://h.online-metrix.net/script.js" }),
            deps({
                resolveDns: async () => {
                    dnsCalled = true;
                    return { addresses: [], canonicalName: "" };
                },
            })
        );
        assertEqual(result.cancel, true, "online-metrix.net host blocked without DNS");
        assert(dnsCalled === false, "no DNS for online-metrix.net host");
    }
    {
        let dnsCalled = false;
        const result = await evaluateRequest(
            req({ url: "https://www.lexisnexisrisk.com/" }),
            deps({
                resolveDns: async () => {
                    dnsCalled = true;
                    return { addresses: [], canonicalName: "" };
                },
            })
        );
        assertEqual(result.cancel, true, "lexisnexisrisk.com host blocked without DNS");
        assert(dnsCalled === false, "no DNS for lexisnexisrisk.com host");
    }
    {
        const result = await evaluateRequest(
            req({ url: "https://cdn.customer-brand.com/tmx.js" }),
            deps({
                resolveDns: async () => ({
                    addresses: ["203.0.113.10"],
                    canonicalName: "abc123.online-metrix.net",
                }),
            })
        );
        assertEqual(result.cancel, true, "ThreatMetrix CNAME blocked");
        assertEqual(result.reason, "threatmetrix", "threatmetrix reason");
    }
    {
        // Trailing-dot canonical name must still match
        const result = await evaluateRequest(
            req({ url: "https://cdn.customer-brand.com/tmx.js" }),
            deps({
                resolveDns: async () => ({
                    addresses: ["203.0.113.10"],
                    canonicalName: "abc123.online-metrix.net.",
                }),
            })
        );
        assertEqual(result.cancel, true, "trailing-dot CNAME still blocked");
        assertEqual(result.reason, "threatmetrix", "trailing-dot threatmetrix reason");
    }
    {
        const result = await evaluateRequest(
            req({ url: "https://cdn.customer-brand.com/tmx.js" }),
            deps({
                resolveDns: async () => ({
                    addresses: ["203.0.113.10"],
                    canonicalName: "edge.threatmetrix.com.",
                }),
            })
        );
        assertEqual(result.cancel, true, "threatmetrix.com CNAME blocked");
    }
    {
        // Rebinding check runs before ThreatMetrix; private rebind wins
        const result = await evaluateRequest(
            req({ url: "http://127.0.0.1.nip.io/" }),
            deps({
                resolveDns: async () => ({
                    addresses: ["127.0.0.1"],
                    canonicalName: "x.online-metrix.net",
                }),
            })
        );
        assertEqual(result.reason, "portscan", "portscan takes precedence over threatmetrix");
    }
    {
        // Public A record + ThreatMetrix CNAME still blocked
        const result = await evaluateRequest(
            req({ url: "https://shop.example/checkout" }),
            deps({
                resolveDns: async () => ({
                    addresses: ["203.0.113.50"],
                    canonicalName: "shop.online-metrix.net",
                }),
            })
        );
        assertEqual(result.cancel, true, "public IP + TMX CNAME still blocked");
        assertEqual(result.reason, "threatmetrix", "TMX reason when public A");
    }

    suite("DNS result LRU cache");
    {
        const cache = createDnsResultCache(2);
        let resolveCount = 0;
        const resolveDns = async (hostname) => {
            resolveCount += 1;
            return { addresses: ["203.0.113.1"], canonicalName: hostname };
        };

        await evaluateRequest(
            req({ url: "https://cdn.a.example/x.js" }),
            deps({ resolveDns, dnsCache: cache })
        );
        await evaluateRequest(
            req({ url: "https://cdn.a.example/y.js" }),
            deps({ resolveDns, dnsCache: cache })
        );
        assertEqual(resolveCount, 1, "second request to same host uses cache");
        assertEqual(cache.size, 1, "cache holds one entry");

        await evaluateRequest(
            req({ url: "https://cdn.b.example/x.js" }),
            deps({ resolveDns, dnsCache: cache })
        );
        await evaluateRequest(
            req({ url: "https://cdn.c.example/x.js" }),
            deps({ resolveDns, dnsCache: cache })
        );
        assertEqual(cache.size, 2, "LRU max size enforced");
        assertEqual(resolveCount, 3, "three distinct hosts resolved");

        // a.example was evicted; resolving again increments count
        await evaluateRequest(
            req({ url: "https://cdn.a.example/z.js" }),
            deps({ resolveDns, dnsCache: cache })
        );
        assertEqual(resolveCount, 4, "evicted host re-resolves");
    }
    {
        // Rebinding-like hosts must not use the cache
        const cache = createDnsResultCache();
        let resolveCount = 0;
        const resolveDns = async () => {
            resolveCount += 1;
            return {
                addresses: resolveCount === 1 ? ["8.8.8.8"] : ["127.0.0.1"],
                canonicalName: "127.0.0.1.nip.io",
            };
        };

        const first = await evaluateRequest(
            req({ url: "http://127.0.0.1.nip.io/" }),
            deps({ resolveDns, dnsCache: cache })
        );
        const second = await evaluateRequest(
            req({ url: "http://127.0.0.1.nip.io/" }),
            deps({ resolveDns, dnsCache: cache })
        );
        assertEqual(first.cancel, false, "first public answer allowed");
        assertEqual(second.cancel, true, "second private answer blocked (no cache)");
        assertEqual(resolveCount, 2, "rebinding host resolved twice");
        assertEqual(cache.size, 0, "rebinding hosts not stored in cache");
    }
    {
        // Cached ThreatMetrix CNAME decision reused
        const cache = createDnsResultCache();
        let resolveCount = 0;
        const resolveDns = async () => {
            resolveCount += 1;
            return {
                addresses: ["203.0.113.10"],
                canonicalName: "cust.online-metrix.net",
            };
        };
        const first = await evaluateRequest(
            req({ url: "https://branded-tracker.example/a.js" }),
            deps({ resolveDns, dnsCache: cache })
        );
        const second = await evaluateRequest(
            req({ url: "https://branded-tracker.example/b.js" }),
            deps({ resolveDns, dnsCache: cache })
        );
        assertEqual(first.reason, "threatmetrix", "first CNAME block");
        assertEqual(second.reason, "threatmetrix", "cached CNAME block");
        assertEqual(resolveCount, 1, "CNAME path cached after first resolve");
    }

    suite("DNS failure fails open");
    {
        const result = await evaluateRequest(
            req({ url: "https://temporarily-down.example/" }),
            deps({
                resolveDns: async () => {
                    throw new Error("NS_ERROR_UNKNOWN_HOST");
                },
            })
        );
        assertEqual(result.cancel, false, "DNS failure fails open");
        assertEqual(result.reason, "dns-failure", "dns-failure reason");
    }
    {
        // Known suffix still blocked even if resolveDns would throw
        const result = await evaluateRequest(
            req({ url: "https://threatmetrix.com/" }),
            deps({
                resolveDns: async () => {
                    throw new Error("should not be called");
                },
            })
        );
        assertEqual(result.cancel, true, "known suffix blocked without DNS on failure path");
        assertEqual(result.reason, "threatmetrix", "threatmetrix without DNS");
    }

    suite("clean public third-party requests");
    {
        const result = await evaluateRequest(
            req({ url: "https://cdn.example.com/app.js" }),
            deps({
                resolveDns: async () => ({
                    addresses: ["93.184.216.34"],
                    canonicalName: "cdn.example.com",
                }),
            })
        );
        assertEqual(result.cancel, false, "normal CDN allowed");
        assertEqual(result.reason, "clean", "clean reason");
    }

    suite("allowlisted origin skips even ThreatMetrix and local targets");
    {
        const result = await evaluateRequest(
            req({
                originUrl: "https://bank.example/",
                url: "https://tmx.bank.example/script.js",
            }),
            deps({
                getAllowedDomains: async () => ["bank.example"],
                resolveDns: async () => ({
                    addresses: ["203.0.113.1"],
                    canonicalName: "bank.online-metrix.net",
                }),
            })
        );
        assertEqual(result.cancel, false, "allowlist bypasses threatmetrix");
        assertEqual(result.reason, "allowlisted", "allowlisted before DNS");
    }
    {
        const result = await evaluateRequest(
            req({
                originUrl: "https://bank.example/",
                url: "https://threatmetrix.com/",
            }),
            deps({
                getAllowedDomains: async () => ["bank.example"],
            })
        );
        assertEqual(result.cancel, false, "allowlist bypasses direct ThreatMetrix host");
        assertEqual(result.reason, "allowlisted", "allowlisted before host match");
    }
}
