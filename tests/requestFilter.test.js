/**
 * Exhaustive coverage of evaluateRequest decision paths used by background.js.
 */
import { evaluateRequest, THREATMETRIX_CNAME } from "../global/requestFilter.js";
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

    suite("ThreatMetrix CNAME blocking");
    assert(THREATMETRIX_CNAME.test("online-metrix.net") === true, "apex online-metrix.net");
    assert(THREATMETRIX_CNAME.test("h.online-metrix.net") === true, "subdomain online-metrix.net");
    assert(THREATMETRIX_CNAME.test("CUSTOMER.online-metrix.net") === true, "case insensitive");
    assert(THREATMETRIX_CNAME.test("evil-online-metrix.net") === false, "suffix lookalike rejected");
    assert(THREATMETRIX_CNAME.test("online-metrix.net.evil.com") === false, "appended domain rejected");
    assert(THREATMETRIX_CNAME.test("example.com") === false, "ordinary domain");

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
}
