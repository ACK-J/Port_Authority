/**
 * Decision logic for whether a third-party request should be blocked.
 * Kept free of badge/notification/storage side effects so it can be unit tested.
 */
import {
    isLocalRequestUrl,
    isLiteralIpHostname,
    isPrivateAddress,
    hostnameSuggestsIpRebinding,
    isUnspecifiedAddress,
} from "./privateAddress.js";

/**
 * LexisNexis / ThreatMetrix infrastructure suffixes.
 * Auditable list — prefer appending verified domains here over regex sprawl.
 * Matched as exact host or subdomain via {@link matchesThreatMetrixHost}.
 */
export const THREATMETRIX_SUFFIXES = Object.freeze([
    "online-metrix.net",
    "threatmetrix.com",
    "lexisnexisrisk.com",
    "lnrsoftware.com",
]);

/**
 * Strip trailing dots (FQDN form) and lowercase for stable suffix compares.
 * browser.dns.resolve may or may not normalize trailing dots; do not rely on it.
 * @param {string} hostname
 * @returns {string}
 */
export function normalizeHostname(hostname) {
    return String(hostname ?? "").replace(/\.+$/u, "").toLowerCase();
}

/**
 * True when hostname is one of {@link THREATMETRIX_SUFFIXES} or a subdomain thereof.
 * @param {string} hostname
 * @returns {boolean}
 */
export function matchesThreatMetrixHost(hostname) {
    const host = normalizeHostname(hostname);
    if (!host) return false;

    for (const suffix of THREATMETRIX_SUFFIXES) {
        if (host === suffix || host.endsWith(`.${suffix}`)) {
            return true;
        }
    }
    return false;
}

/**
 * @deprecated Prefer {@link matchesThreatMetrixHost} / {@link THREATMETRIX_SUFFIXES}.
 * Kept as a thin wrapper for any external callers of the old regex export.
 */
export const THREATMETRIX_CNAME = {
    test(value) {
        return matchesThreatMetrixHost(value);
    },
};

/**
 * Session-scoped LRU map of hostname → DNS resolve result.
 * Not persisted — avoids a new on-disk privacy surface.
 *
 * @param {number} [maxSize=256]
 * @returns {{
 *   get: (key: string) => DnsResolveResult | undefined,
 *   set: (key: string, value: DnsResolveResult) => void,
 *   clear: () => void,
 *   get size(): number,
 * }}
 */
export function createDnsResultCache(maxSize = 256) {
    /** @type {Map<string, DnsResolveResult>} */
    const map = new Map();

    return {
        get(key) {
            if (!map.has(key)) return undefined;
            const value = map.get(key);
            // Refresh insertion order (most-recently used at the end).
            map.delete(key);
            map.set(key, value);
            return value;
        },
        set(key, value) {
            if (map.has(key)) map.delete(key);
            map.set(key, value);
            while (map.size > maxSize) {
                const oldest = map.keys().next().value;
                map.delete(oldest);
            }
        },
        clear() {
            map.clear();
        },
        get size() {
            return map.size;
        },
    };
}

/**
 * @typedef {object} DnsResolveResult
 * @property {string[]} [addresses]
 * @property {string} [canonicalName]
 */

/**
 * @typedef {object} RequestFilterDeps
 * @property {() => Promise<string[]>} getAllowedDomains
 * @property {(hostname: string) => Promise<DnsResolveResult>} resolveDns
 * @property {{ get: (key: string) => DnsResolveResult | undefined, set: (key: string, value: DnsResolveResult) => void }} [dnsCache]
 *   Optional in-memory LRU of successful DNS results for this Firefox session.
 */

/**
 * @typedef {object} FilterAllow
 * @property {false} cancel
 * @property {string} [reason]
 */

/**
 * @typedef {object} FilterBlock
 * @property {true} cancel
 * @property {"portscan" | "threatmetrix"} reason
 * @property {URL} url
 */

/**
 * Evaluate a webRequest-like detail object and decide whether to cancel it.
 *
 * Callers are responsible for first-party short-circuiting if desired; this
 * function still accepts `thirdParty` and allows first-party requests.
 *
 * @param {{
 *   thirdParty?: boolean,
 *   originUrl?: string,
 *   url: string,
 * }} requestDetails
 * @param {RequestFilterDeps} deps
 * @returns {Promise<FilterAllow | FilterBlock>}
 */
export async function evaluateRequest(requestDetails, deps) {
    const { getAllowedDomains, resolveDns, dnsCache } = deps;

    if (!requestDetails.thirdParty) {
        return { cancel: false, reason: "first-party" };
    }

    let originUrl;
    try {
        originUrl = new URL(requestDetails.originUrl);
    } catch {
        return { cancel: false, reason: "unparseable-origin" };
    }

    const allowedDomains = await getAllowedDomains();
    if (allowedDomains.some((domain) => originUrl.host === domain)) {
        return { cancel: false, reason: "allowlisted" };
    }

    let url;
    try {
        url = new URL(requestDetails.url);
    } catch {
        return { cancel: false, reason: "unparseable-url" };
    }

    if (isLocalRequestUrl(url)) {
        return { cancel: true, reason: "portscan", url };
    }

    // Literal public (or already-classified) IPs: no DNS follow-up.
    if (isLiteralIpHostname(url.hostname)) {
        return { cancel: false, reason: "literal-ip" };
    }

    // Known LexisNexis / ThreatMetrix hosts: block without a DNS side-channel.
    if (matchesThreatMetrixHost(url.hostname)) {
        return { cancel: true, reason: "threatmetrix", url };
    }

    // DNS is still needed for (1) rebinding-like private A/AAAA answers and
    // (2) customer-specific CNAMEs into ThreatMetrix infrastructure.
    // Rebinding-like names skip the session cache so a later private answer
    // is not masked by an earlier public one.
    const useCache = Boolean(dnsCache) && !hostnameSuggestsIpRebinding(url.hostname);
    let resolving = useCache ? dnsCache.get(url.hostname) : undefined;

    if (!resolving) {
        try {
            resolving = await resolveDns(url.hostname);
        } catch {
            // Explicit fail-open: a resolver outage must not break browsing.
            // Known ThreatMetrix suffixes are already handled without DNS above.
            return { cancel: false, reason: "dns-failure" };
        }
        if (useCache) {
            dnsCache.set(url.hostname, resolving);
        }
    }

    // Only treat private DNS answers as port scans for rebinding-like names.
    // Content blockers sinkhole ordinary domains to 0.0.0.0 / 127.0.0.1.
    if (hostnameSuggestsIpRebinding(url.hostname)) {
        for (const address of resolving.addresses ?? []) {
            if (isUnspecifiedAddress(address)) continue;
            if (isPrivateAddress(address)) {
                return { cancel: true, reason: "portscan", url };
            }
        }
    }

    if (matchesThreatMetrixHost(resolving.canonicalName ?? "")) {
        return { cancel: true, reason: "threatmetrix", url };
    }

    return { cancel: false, reason: "clean" };
}
