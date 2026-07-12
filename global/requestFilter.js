/**
 * Decision logic for whether a request should be blocked.
 * Kept free of badge/notification/storage side effects so it can be unit tested.
 */
import { requestMatchesAllowlist, isCompiledAllowlist, compileAllowlist } from "./allowlist.js";
import {
    isLocalRequestUrl,
    isLiteralIpHostname,
    isPrivateAddress,
    hostnameSuggestsIpRebinding,
    isUnspecifiedAddress,
    normalizeHostname,
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
 * True when hostname is one of {@link THREATMETRIX_SUFFIXES} or a subdomain thereof.
 * @param {string} hostname
 * @param {string} [normalizedHostname] Optional precomputed {@link normalizeHostname} result
 * @returns {boolean}
 */
export function matchesThreatMetrixHost(hostname, normalizedHostname) {
    const host = normalizedHostname ?? normalizeHostname(hostname);
    if (!host) return false;

    for (const suffix of THREATMETRIX_SUFFIXES) {
        if (host === suffix || host.endsWith(`.${suffix}`)) {
            return true;
        }
    }
    return false;
}

/**
 * Session-scoped LRU map of hostname → DNS resolve result.
 * Not persisted — avoids a new on-disk privacy surface.
 *
 * Also tracks in-flight resolves so a request stampede to the same host
 * (common on SPAs) shares one `browser.dns.resolve` instead of N.
 *
 * @param {number} [maxSize=256]
 * @returns {{
 *   get: (key: string) => DnsResolveResult | undefined,
 *   set: (key: string, value: DnsResolveResult) => void,
 *   getInflight: (key: string) => Promise<DnsResolveResult> | undefined,
 *   setInflight: (key: string, promise: Promise<DnsResolveResult>) => void,
 *   clearInflight: (key: string) => void,
 *   clear: () => void,
 *   get size(): number,
 *   get inflightSize(): number,
 * }}
 */
export function createDnsResultCache(maxSize = 256) {
    /** @type {Map<string, DnsResolveResult>} */
    const map = new Map();
    /** @type {Map<string, Promise<DnsResolveResult>>} */
    const inflight = new Map();

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
        getInflight(key) {
            return inflight.get(key);
        },
        setInflight(key, promise) {
            inflight.set(key, promise);
        },
        clearInflight(key) {
            inflight.delete(key);
        },
        clear() {
            map.clear();
            inflight.clear();
        },
        get size() {
            return map.size;
        },
        get inflightSize() {
            return inflight.size;
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
 * @property {() => (string[]|import("./allowlist.js").CompiledAllowlist)|Promise<string[]|import("./allowlist.js").CompiledAllowlist>} [getAllowedDomains]
 * @property {string[]|import("./allowlist.js").CompiledAllowlist} [allowedDomains] Sync allowlist when already available
 * @property {(hostname: string) => Promise<DnsResolveResult>} resolveDns
 * @property {{
 *   get: (key: string) => DnsResolveResult | undefined,
 *   set: (key: string, value: DnsResolveResult) => void,
 *   getInflight?: (key: string) => Promise<DnsResolveResult> | undefined,
 *   setInflight?: (key: string, promise: Promise<DnsResolveResult>) => void,
 *   clearInflight?: (key: string) => void,
 * }} [dnsCache]
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
 * @property {string} [originHost]
 */

/**
 * @typedef {object} FilterNeedsDns
 * @property {"needs-dns"} phase
 * @property {URL} url
 * @property {URL} originUrl
 * @property {string} requestHost
 * @property {boolean} isThirdParty
 * @property {boolean} needsRebindingCheck
 */

/**
 * Resolve DNS with optional session cache. Rebinding-like names skip the cache
 * (and in-flight coalescing) so each lookup can observe a rebound answer.
 * @param {string} hostname
 * @param {RequestFilterDeps} deps
 * @param {boolean} skipCache
 * @returns {Promise<{ ok: true, resolving: DnsResolveResult } | { ok: false }>}
 */
const DNS_TIMEOUT_MS = 8000;

/** Reject if `promise` does not settle within `ms`. */
function withTimeout(promise, ms) {
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error("dns-timeout")), ms);
        Promise.resolve(promise).then(
            (value) => {
                clearTimeout(timer);
                resolve(value);
            },
            (error) => {
                clearTimeout(timer);
                reject(error);
            }
        );
    });
}

async function resolveWithOptionalCache(hostname, deps, skipCache) {
    const { resolveDns, dnsCache } = deps;
    const useCache = Boolean(dnsCache) && !skipCache;

    if (useCache) {
        const cached = dnsCache.get(hostname);
        if (cached) return { ok: true, resolving: cached };

        const pending = dnsCache.getInflight?.(hostname);
        if (pending) {
            try {
                return { ok: true, resolving: await pending };
            } catch {
                return { ok: false };
            }
        }
    }

    // Bound hung resolver waits so cancel()/inflight maps cannot pin request
    // details indefinitely if dns.resolve never settles.
    const resolvePromise = withTimeout(resolveDns(hostname), DNS_TIMEOUT_MS);

    if (useCache) {
        dnsCache.setInflight?.(hostname, resolvePromise);
    }

    try {
        const resolving = await resolvePromise;
        if (useCache) {
            dnsCache.set(hostname, resolving);
        }
        return { ok: true, resolving };
    } catch {
        return { ok: false };
    } finally {
        if (useCache) {
            dnsCache.clearInflight?.(hostname);
        }
    }
}

/**
 * @param {string[]|import("./allowlist.js").CompiledAllowlist|null|undefined} allowedDomains
 */
function asCompiledAllowlist(allowedDomains) {
    if (isCompiledAllowlist(allowedDomains)) return allowedDomains;
    return compileAllowlist(Array.isArray(allowedDomains) ? allowedDomains : []);
}

/**
 * Synchronous pre-DNS evaluation. Returns a final decision or `{ phase: "needs-dns" }`.
 *
 * @param {{
 *   thirdParty?: boolean,
 *   originUrl?: string,
 *   url: string,
 * }} requestDetails
 * @param {string[]|import("./allowlist.js").CompiledAllowlist} allowedDomains
 * @returns {FilterAllow | FilterBlock | FilterNeedsDns}
 */
export function evaluateRequestSync(requestDetails, allowedDomains) {
    const isThirdParty = Boolean(requestDetails.thirdParty);
    const compiled = asCompiledAllowlist(allowedDomains);

    let originUrl;
    try {
        originUrl = new URL(requestDetails.originUrl);
    } catch {
        return { cancel: false, reason: "unparseable-origin" };
    }

    let url;
    try {
        url = new URL(requestDetails.url);
    } catch {
        return { cancel: false, reason: "unparseable-url" };
    }

    // Domains match the page origin only. IP/CIDR entries also match destinations
    // so allowlisting 127.0.0.1 works for scans from file:// or other pages.
    if (requestMatchesAllowlist(originUrl.host, url.host, compiled)) {
        return { cancel: false, reason: "allowlisted" };
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
        if (isLocalRequestUrl(url, requestHost)) {
            return { cancel: true, reason: "portscan", url, originHost: originUrl.host };
        }

        // Literal public (or already-classified) IPs: no DNS follow-up.
        if (isLiteralIpHostname(requestHost)) {
            return { cancel: false, reason: "literal-ip" };
        }
    } else if (isLiteralIpHostname(requestHost)) {
        // Same-site but literal IP host — not a TMX hostname path.
        return { cancel: false, reason: "first-party" };
    }

    // Known LexisNexis / ThreatMetrix hosts: block without a DNS side-channel.
    // Applies to first- and third-party (direct infrastructure hits).
    if (matchesThreatMetrixHost(requestHost, requestHost)) {
        return { cancel: true, reason: "threatmetrix", url, originHost: originUrl.host };
    }

    // DNS is needed for rebinding checks and customer-specific TMX CNAMEs.
    const needsRebindingCheck = isThirdParty && hostnameSuggestsIpRebinding(requestHost, requestHost);
    return {
        phase: "needs-dns",
        url,
        originUrl,
        requestHost,
        isThirdParty,
        needsRebindingCheck,
    };
}

/**
 * Finish evaluation after a DNS resolve for a {@link evaluateRequestSync} needs-dns result.
 * @param {FilterNeedsDns} pending
 * @param {{ ok: true, resolving: DnsResolveResult } | { ok: false }} resolved
 * @returns {FilterAllow | FilterBlock}
 */
export function finishEvaluateRequestWithDns(pending, resolved) {
    if (!resolved.ok) {
        // Explicit fail-open: a resolver outage must not break browsing.
        // Known ThreatMetrix suffixes are already handled without DNS above.
        return { cancel: false, reason: "dns-failure" };
    }
    const { resolving } = resolved;
    const { url, requestHost, isThirdParty, needsRebindingCheck, originUrl } = pending;

    if (needsRebindingCheck) {
        for (const address of resolving.addresses ?? []) {
            if (isUnspecifiedAddress(address)) continue;
            if (isPrivateAddress(address)) {
                return { cancel: true, reason: "portscan", url, originHost: originUrl.host };
            }
        }
    }

    if (matchesThreatMetrixHost(resolving.canonicalName ?? "")) {
        return { cancel: true, reason: "threatmetrix", url, originHost: originUrl.host };
    }

    return { cancel: false, reason: isThirdParty ? "clean" : "first-party" };
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
    const allowedDomains =
        deps.allowedDomains !== undefined
            ? deps.allowedDomains
            : await deps.getAllowedDomains();

    const early = evaluateRequestSync(requestDetails, allowedDomains);
    if (!early.phase) {
        return early;
    }

    const resolved = await resolveWithOptionalCache(
        early.requestHost,
        deps,
        early.needsRebindingCheck
    );
    return finishEvaluateRequestWithDns(early, resolved);
}

/**
 * Resolve DNS for a sync needs-dns pending result (used by background cancel).
 * @param {FilterNeedsDns} pending
 * @param {RequestFilterDeps} deps
 * @returns {Promise<FilterAllow | FilterBlock>}
 */
export async function evaluateRequestDnsPhase(pending, deps) {
    const resolved = await resolveWithOptionalCache(
        pending.requestHost,
        deps,
        pending.needsRebindingCheck
    );
    return finishEvaluateRequestWithDns(pending, resolved);
}
