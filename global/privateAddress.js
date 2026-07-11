/**
 * Detects IP addresses in non-routable/private ranges that local_filter would
 * block when they appear literally in a request URL.
 */

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
