/**
 * Helpers for the domain allowlist used by settings UI and request filtering.
 */

/**
 * Get a well-formed host to match against from a user-supplied URL-like string.
 * @param {string} url A URL-like value (eg `https://example.com/path`, `discord.com`, `example.com:8080`)
 * @returns {string} Host portion including port when non-default (eg `example.com`, `example.com:8080`)
 * @throws {TypeError} When the input cannot be parsed as a URL
 */
export function extractURLHost(url) {
    url = url.trim();

    // URL() requires a protocol; callers often paste bare domains.
    if (!/^\w*:\/\//.test(url)) {
        url = "http://" + url;
    }

    return new URL(url).host;
}

/**
 * Exact host match against the allowlist (subdomains are not implicitly allowed).
 * @param {string} originHost `URL.host` of the requesting page
 * @param {string[]} allowedDomains
 */
export function isHostAllowlisted(originHost, allowedDomains) {
    return allowedDomains.some((domain) => originHost === domain);
}
