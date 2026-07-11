/**
 * Detects when a network request targets a non-routable/local address.
 * Uses the URL API for parsing instead of regex on raw URL strings.
 */

const LOCAL_REQUEST_PROTOCOLS = new Set([
    "http:", "https:", "ws:", "wss:", "ftp:", "ftps:",
]);

function isPrivateIPv4(ip) {
    const parts = ip.split(".").map(Number);
    if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) return false;
    const [a, b] = parts;
    return (
        a === 127 ||
        a === 10 ||
        (a === 172 && b >= 16 && b <= 31) ||
        (a === 192 && b === 168) ||
        (a === 169 && b === 254) ||
        (a === 0 && parts.every((p) => p === 0))
    );
}

function parseIPv4MappedSuffix(normalized) {
    const shortForm = normalized.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/);
    if (shortForm) return shortForm[1];

    const longForm = normalized.match(/(?:^|:)(?:0+:){0,5}ffff:(\d{1,3}(?:\.\d{1,3}){3})$/);
    if (longForm) return longForm[1];

    return null;
}

function isPrivateIPv6(ip) {
    const normalized = ip.toLowerCase().split("%")[0];

    if (normalized === "::1" || normalized === "0:0:0:0:0:0:0:1") {
        return true;
    }

    const mapped = parseIPv4MappedSuffix(normalized);
    if (mapped) return isPrivateIPv4(mapped);

    const firstSegment = normalized.split(":").find((segment) => segment.length > 0);
    if (!firstSegment) return false;

    const firstHextet = parseInt(firstSegment, 16);
    if (Number.isNaN(firstHextet)) return false;

    // fe80::/10 link-local, fc00::/7 unique local (ULA)
    return (
        (firstHextet >= 0xfe80 && firstHextet <= 0xfebf) ||
        (firstHextet >= 0xfc00 && firstHextet <= 0xfdff)
    );
}

export function isPrivateAddress(ip) {
    if (ip.includes(":")) return isPrivateIPv6(ip);
    if (ip.includes(".")) return isPrivateIPv4(ip);
    return false;
}

function normalizeHostname(hostname) {
    let host = hostname;
    if (host.startsWith("[") && host.endsWith("]")) {
        host = host.slice(1, -1);
    }
    if (host.endsWith(".")) {
        host = host.slice(0, -1);
    }
    return host.toLowerCase();
}

/**
 * Returns true when `url` targets a local/private address over a supported protocol.
 * @param {URL} url Parsed request URL
 */
export function isLocalRequestUrl(url) {
    if (!LOCAL_REQUEST_PROTOCOLS.has(url.protocol)) return false;

    const hostname = normalizeHostname(url.hostname);
    if (hostname === "localhost") return true;

    return isPrivateAddress(hostname);
}
