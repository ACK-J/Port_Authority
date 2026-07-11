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

/** Matches ThreatMetrix CNAME targets (online-metrix.net and its subdomains only). */
export const THREATMETRIX_CNAME = /(?:^|\.)online-metrix[.]net$/i;

/**
 * @typedef {object} DnsResolveResult
 * @property {string[]} [addresses]
 * @property {string} [canonicalName]
 */

/**
 * @typedef {object} RequestFilterDeps
 * @property {() => Promise<string[]>} getAllowedDomains
 * @property {(hostname: string) => Promise<DnsResolveResult>} resolveDns
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
    const { getAllowedDomains, resolveDns } = deps;

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

    let resolving;
    try {
        resolving = await resolveDns(url.hostname);
    } catch {
        // Fail open — temporary DNS failures must not break browsing.
        return { cancel: false, reason: "dns-failure" };
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

    if (THREATMETRIX_CNAME.test(resolving.canonicalName ?? "")) {
        return { cancel: true, reason: "threatmetrix", url };
    }

    return { cancel: false, reason: "clean" };
}
