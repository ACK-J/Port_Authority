/**
 * Returns whether a URL hostname represents an IP address (IPv4 or IPv6).
 * @param {string} hostname A URL.hostname value (IPv6 may include brackets)
 */
export function isIPAddress(hostname) {
    const bare = hostname.startsWith("[") ? hostname.slice(1, -1) : hostname;
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(bare)) {
        return true;
    }
    return bare.includes(":");
}

/**
 * Returns whether an origin host matches an allowlist entry.
 * Domains require an exact host match. IP addresses without an explicit port
 * also match the same address on any port (e.g. 127.0.0.1 matches 127.0.0.1:8080).
 * @param {string} originHost A URL.host value from the request origin
 * @param {string} allowlistEntry A stored allowlist entry
 */
export function hostMatchesAllowlistEntry(originHost, allowlistEntry) {
    if (originHost === allowlistEntry) {
        return true;
    }

    let originUrl;
    let entryUrl;
    try {
        originUrl = new URL(`http://${originHost}/`);
        entryUrl = new URL(`http://${allowlistEntry}/`);
    } catch {
        return false;
    }

    if (entryUrl.host === entryUrl.hostname && isIPAddress(entryUrl.hostname)) {
        return originUrl.hostname === entryUrl.hostname;
    }

    return false;
}
