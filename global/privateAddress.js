/**
 * Detects when a network request targets a non-routable/local address.
 * Uses the URL API for parsing instead of regex on raw URL strings, then
 * classifies the parsed hostname (and DNS-resolved addresses) against
 * private/loopback/link-local ranges for both IPv4 and IPv6.
 */

const LOCAL_REQUEST_PROTOCOLS = new Set([
    "http:", "https:", "ws:", "wss:", "ftp:", "ftps:",
]);

/** @returns {number[]|null} four octets, or null if not a dotted IPv4 literal */
function parseIPv4Octets(ip) {
    const parts = ip.split(".");
    if (parts.length !== 4) return null;
    const octets = parts.map(Number);
    if (octets.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
        return null;
    }
    return octets;
}

/**
 * RFC 1918, loopback, link-local, CGNAT (RFC 6598), benchmarking (RFC 2544),
 * and "this network" 0.0.0.0/8.
 */
function isPrivateIPv4(ip) {
    const parts = parseIPv4Octets(ip);
    if (!parts) return false;
    const [a, b] = parts;
    return (
        a === 0 || // 0.0.0.0/8
        a === 10 || // 10.0.0.0/8
        a === 127 || // 127.0.0.0/8
        (a === 100 && b >= 64 && b <= 127) || // 100.64.0.0/10 CGNAT
        (a === 169 && b === 254) || // 169.254.0.0/16 link-local
        (a === 172 && b >= 16 && b <= 31) || // 172.16.0.0/12
        (a === 192 && b === 168) || // 192.168.0.0/16
        (a === 198 && (b === 18 || b === 19)) // 198.18.0.0/15 benchmarking
    );
}

/**
 * Expand an IPv6 literal to eight numeric hextets.
 * Accepts compressed form, zone IDs, and dotted IPv4 tails (::ffff:127.0.0.1).
 * @returns {number[]|null}
 */
function expandIPv6(ip) {
    let addr = ip.toLowerCase().split("%")[0];

    // Convert a trailing dotted-quad into two hextets before expansion.
    const v4Tail = addr.match(/^(.*:)(\d{1,3}(?:\.\d{1,3}){3})$/);
    if (v4Tail) {
        const octets = v4Tail[2].split(".").map(Number);
        if (octets.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
            return null;
        }
        const h1 = ((octets[0] << 8) | octets[1]).toString(16);
        const h2 = ((octets[2] << 8) | octets[3]).toString(16);
        addr = `${v4Tail[1]}${h1}:${h2}`;
    }

    if ((addr.match(/::/g) || []).length > 1) return null;

    let left;
    let right;
    if (addr.includes("::")) {
        [left, right = ""] = addr.split("::");
    } else {
        left = addr;
        right = "";
    }

    const leftParts = left === "" ? [] : left.split(":");
    const rightParts = right === "" ? [] : right.split(":");
    if (leftParts.some((p) => p === "") || rightParts.some((p) => p === "")) {
        return null;
    }

    const missing = 8 - leftParts.length - rightParts.length;
    if (missing < 0) return null;
    if (!addr.includes("::") && missing !== 0) return null;

    const full = [
        ...leftParts,
        ...Array(missing).fill("0"),
        ...rightParts,
    ];
    if (full.length !== 8) return null;

    const hextets = full.map((h) => parseInt(h || "0", 16));
    if (hextets.some((n) => Number.isNaN(n) || n < 0 || n > 0xffff)) {
        return null;
    }
    return hextets;
}

function ipv4FromHextets(hi, lo) {
    return [
        (hi >> 8) & 0xff,
        hi & 0xff,
        (lo >> 8) & 0xff,
        lo & 0xff,
    ].join(".");
}

function isIpv4MappedHextets(hextets) {
    return (
        hextets[0] === 0 &&
        hextets[1] === 0 &&
        hextets[2] === 0 &&
        hextets[3] === 0 &&
        hextets[4] === 0 &&
        hextets[5] === 0xffff
    );
}

function isIpv4CompatibleHextets(hextets) {
    return (
        hextets[0] === 0 &&
        hextets[1] === 0 &&
        hextets[2] === 0 &&
        hextets[3] === 0 &&
        hextets[4] === 0 &&
        hextets[5] === 0
    );
}

function isPrivateIPv6(ip) {
    const hextets = expandIPv6(ip);
    if (!hextets) return false;

    // :: unspecified
    if (hextets.every((h) => h === 0)) return true;

    // ::1 loopback
    if (hextets.every((h, i) => (i === 7 ? h === 1 : h === 0))) return true;

    // IPv4-mapped ::ffff:0:0/96 and deprecated IPv4-compatible ::/96
    if (isIpv4MappedHextets(hextets) || isIpv4CompatibleHextets(hextets)) {
        return isPrivateIPv4(ipv4FromHextets(hextets[6], hextets[7]));
    }

    // fe80::/10 link-local, fc00::/7 unique local (ULA)
    return (
        (hextets[0] & 0xffc0) === 0xfe80 ||
        (hextets[0] & 0xfe00) === 0xfc00
    );
}

export function isPrivateAddress(ip) {
    if (typeof ip !== "string" || ip.length === 0) return false;
    // DNS and some callers may pass bracketed literals.
    const normalized = normalizeHostname(ip);
    if (normalized.includes(":")) return isPrivateIPv6(normalized);
    if (normalized.includes(".")) return isPrivateIPv4(normalized);
    return false;
}

/**
 * Normalize a hostname or IP literal for stable compares.
 * Strips IPv6 brackets, trailing FQDN dots, and lowercases.
 * @param {string} hostname
 * @returns {string}
 */
export function normalizeHostname(hostname) {
    let host = String(hostname ?? "");
    if (host.startsWith("[") && host.endsWith("]")) {
        host = host.slice(1, -1);
    }
    return host.replace(/\.+$/u, "").toLowerCase();
}

/** True when `hostname` is an IPv4/IPv6 literal (not a domain name). */
export function isLiteralIpHostname(hostname) {
    const host = normalizeHostname(hostname);
    if (host.includes(":")) return expandIPv6(host) !== null;
    return parseIPv4Octets(host) !== null;
}

/**
 * Returns true when `url` targets a local/private address over a supported protocol.
 * Alternate IPv4 encodings (integer/hex/octal/short-form) are normalized by the
 * URL parser into dotted-decimal before this check runs.
 * @param {URL} url Parsed request URL
 */
export function isLocalRequestUrl(url) {
    if (!LOCAL_REQUEST_PROTOCOLS.has(url.protocol)) return false;

    const hostname = normalizeHostname(url.hostname);
    if (hostname === "localhost") return true;

    return isPrivateAddress(hostname);
}

/** 0.0.0.0 or :: — common DNS sinkhole answers, not useful scan targets. */
export function isUnspecifiedAddress(ip) {
    const normalized = normalizeHostname(ip);
    if (normalized === "::" || normalized === "0:0:0:0:0:0:0:0") return true;

    const mapped = normalized.includes(":") ? expandIPv6(normalized) : null;
    if (mapped) {
        if (isIpv4MappedHextets(mapped)) {
            return mapped[6] === 0 && mapped[7] === 0;
        }
        return mapped.every((h) => h === 0);
    }

    const octets = parseIPv4Octets(normalized);
    return octets !== null && octets.every((o) => o === 0);
}

/**
 * Hostnames that embed an IP (or use known local-resolution helpers) are the
 * practical DNS-rebinding vectors for port scans (e.g. 127.0.0.1.nip.io).
 * Ordinary domains must not get private-IP DNS blocking — content blockers
 * sinkhole trackers to 0.0.0.0/127.0.0.1 and would look like "port scans".
 */
export function hostnameSuggestsIpRebinding(hostname) {
    const host = normalizeHostname(hostname);
    if (host.includes(":")) return false; // literals handled elsewhere

    if (/(?:^|\.)(?:\d{1,3}\.){3}\d{1,3}(?:\.|$)/.test(host)) return true;
    if (/(?:^|\.)(?:0x[0-9a-f]+|\d{8,10})(?:\.|$)/i.test(host)) return true;
    if (
        /(?:^|\.)(?:nip\.io|sslip\.io|xip\.io|localtest\.me|lvh\.me|vcap\.me|lacolhost\.com)$/i.test(
            host
        )
    ) {
        return true;
    }
    return false;
}

