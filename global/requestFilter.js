/**
 * Decision logic for whether a request should be blocked.
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
 * Resolve DNS with optional session cache. Rebinding-like names skip the cache.
 * @param {string} hostname
 * @param {RequestFilterDeps} deps
 * @param {boolean} skipCache
 * @returns {Promise<{ ok: true, resolving: DnsResolveResult } | { ok: false }>}
 */
async function resolveWithOptionalCache(hostname, deps, skipCache) {
    const { resolveDns, dnsCache } = deps;
    const useCache = Boolean(dnsCache) && !skipCache;
    let resolving = useCache ? dnsCache.get(hostname) : undefined;

    if (!resolving) {
        try {
            resolving = await resolveDns(hostname);
        } catch {
            return { ok: false };
        }
        if (useCache) {
            dnsCache.set(hostname, resolving);
        }
    }

    return { ok: true, resolving };
}

/**
 * Evaluate a webRequest-like detail object and decide whether to cancel it.
 *
 * Port-scan filtering applies to third-party requests only. ThreatMetrix
 * matching also runs for same-site cross-subdomain requests — customer
 * endpoints like `tmx.bestbuy.com` share the site's eTLD+1 so Firefox sets
 * `thirdParty: false`, but they CNAME into LexisNexis infrastructure.
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
    const { getAllowedDomains } = deps;
    const isThirdParty = Boolean(requestDetails.thirdParty);

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

    const requestHost = normalizeHostname(url.hostname);
    const originHost = normalizeHostname(originUrl.hostname);
    const sameHost = requestHost === originHost;

    // Same-host first-party resources (page's own assets): allow without DNS.
    if (!isThirdParty && sameHost) {
        return { cancel: false, reason: "first-party" };
    }

    // Port-scan / private-address checks only for third-party requests.
    if (isThirdParty) {
        if (isLocalRequestUrl(url)) {
            return { cancel: true, reason: "portscan", url };
        }

        // Literal public (or already-classified) IPs: no DNS follow-up.
        if (isLiteralIpHostname(url.hostname)) {
            return { cancel: false, reason: "literal-ip" };
        }
    } else if (isLiteralIpHostname(url.hostname)) {
        // Same-site but literal IP host — not a TMX hostname path.
        return { cancel: false, reason: "first-party" };
    }

    // Known LexisNexis / ThreatMetrix hosts: block without a DNS side-channel.
    // Applies to first- and third-party (direct infrastructure hits).
    if (matchesThreatMetrixHost(url.hostname)) {
        return { cancel: true, reason: "threatmetrix", url };
    }

    // DNS is needed for:
    //  (1) third-party rebinding-like private A/AAAA answers
    //  (2) customer-specific CNAMEs into ThreatMetrix (including same-site
    //      branded hosts such as tmx.bestbuy.com → h-bestbuy.online-metrix.net)
    const needsRebindingCheck = isThirdParty && hostnameSuggestsIpRebinding(url.hostname);
    const resolved = await resolveWithOptionalCache(url.hostname, deps, needsRebindingCheck);
    if (!resolved.ok) {
        // Explicit fail-open: a resolver outage must not break browsing.
        // Known ThreatMetrix suffixes are already handled without DNS above.
        return { cancel: false, reason: "dns-failure" };
    }
    const { resolving } = resolved;

    if (needsRebindingCheck) {
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

    return { cancel: false, reason: isThirdParty ? "clean" : "first-party" };
}
