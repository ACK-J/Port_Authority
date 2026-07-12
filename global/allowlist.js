/**
 * Helpers for the domain/IP/CIDR allowlist used by settings UI and request filtering.
 */
import {
    isLiteralIpHostname,
    normalizeHostname,
    parseIPv4Octets,
    expandIPv6,
} from "./privateAddress.js";

/**
 * Get a well-formed host to match against from a user-supplied URL-like string.
 * @param {string} url A URL-like value (eg `https://example.com/path`, `discord.com`, `example.com:8080`)
 * @returns {string} Host portion including port when non-default (eg `example.com`, `example.com:8080`)
 * @throws {TypeError} When the input cannot be parsed as a URL
 */
export function extractURLHost(url) {
    url = url.trim();

    // URL() requires a protocol; callers often paste bare domains / IPs.
    if (!/^\w*:\/\//.test(url)) {
        const pathStart = url.indexOf("/");
        const hostPort = pathStart === -1 ? url : url.slice(0, pathStart);
        const path = pathStart === -1 ? "" : url.slice(pathStart);

        // Bare IPv6 needs brackets. Domain:port and IPv4:port must not be bracketed.
        // IPv6 always has at least two colons (`::1`, `2001:db8::1`); hostname:port has one.
        const isIPv4WithOptionalPort = /^(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?$/.test(hostPort);
        const colonCount = (hostPort.match(/:/g) || []).length;
        const isBareIPv6 = !hostPort.startsWith("[") && !isIPv4WithOptionalPort && colonCount >= 2;

        url = isBareIPv6 ? `http://[${hostPort}]${path}` : `http://${hostPort}${path}`;
    }

    return new URL(url).host;
}

/**
 * True when `entry` is a valid IPv4 or IPv6 CIDR allowlist value.
 * @param {string} entry
 */
export function isCIDRAllowlistEntry(entry) {
    const slashIndex = entry.lastIndexOf("/");
    if (slashIndex <= 0 || slashIndex === entry.length - 1) {
        return false;
    }

    const network = entry.slice(0, slashIndex);
    const prefix = Number(entry.slice(slashIndex + 1));
    if (!Number.isInteger(prefix)) {
        return false;
    }

    const bareNetwork = normalizeHostname(network);
    const octets = parseIPv4Octets(bareNetwork);
    if (octets) {
        return prefix >= 0 && prefix <= 32;
    }

    if (bareNetwork.includes(":")) {
        return prefix >= 0 && prefix <= 128 && expandIPv6(bareNetwork) !== null;
    }

    return false;
}

/**
 * True when an allowlist entry is an IP address (no port) or a CIDR range.
 * Domain entries and host:port IP entries return false.
 * @param {string} entry
 */
export function isIPOrCIDREntry(entry) {
    if (isCIDRAllowlistEntry(entry)) {
        return true;
    }

    try {
        const entryUrl = new URL(`http://${entry}/`);
        return entryUrl.host === entryUrl.hostname && isLiteralIpHostname(entryUrl.hostname);
    } catch {
        return false;
    }
}

/**
 * Normalize and validate a user-supplied allowlist entry.
 * Accepts domains, IP addresses (with optional port), and CIDR ranges.
 * @param {string} input
 * @returns {string}
 * @throws {Error} When the entry is empty or invalid
 */
export function normalizeAllowlistEntry(input) {
    input = String(input ?? "").trim();
    if (!input) {
        throw new Error("empty allowlist entry");
    }

    // CIDR must be accepted before URL parsing — otherwise `192.168.1.0/24`
    // becomes host `192.168.1.0` with path `/24`.
    if (input.includes("/")) {
        if (!isCIDRAllowlistEntry(input)) {
            throw new Error("invalid CIDR notation");
        }
        const slashIndex = input.lastIndexOf("/");
        const network = normalizeHostname(input.slice(0, slashIndex));
        const prefix = input.slice(slashIndex + 1);
        // Store IPv6 networks without brackets for stable compares.
        return `${network}/${prefix}`;
    }

    return extractURLHost(input);
}

/**
 * Treat `localhost` as loopback for IP allowlist comparisons.
 * @param {string} hostname
 */
function normalizeLoopbackHostname(hostname) {
    const bare = normalizeHostname(hostname);
    return bare === "localhost" ? "127.0.0.1" : bare;
}

function hostnameFromHost(host) {
    try {
        return new URL(`http://${host}/`).hostname;
    } catch {
        return host;
    }
}

function ipv4ToInt(ip) {
    const parts = parseIPv4Octets(ip);
    if (!parts) return null;
    return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

function ipv6ToBigInt(ip) {
    const hextets = expandIPv6(ip);
    if (!hextets) return null;

    let value = 0n;
    for (const part of hextets) {
        value = (value << 16n) + BigInt(part);
    }
    return value;
}

/**
 * True when `ip` falls within the CIDR network.
 * @param {string} ip Hostname/IP without port (brackets optional)
 * @param {string} cidr e.g. `192.168.1.0/24` or `fe80::/10`
 */
export function ipInCIDR(ip, cidr) {
    const bareIp = normalizeHostname(ip);
    const slashIndex = cidr.lastIndexOf("/");
    if (slashIndex <= 0) return false;

    const network = normalizeHostname(cidr.slice(0, slashIndex));
    const prefix = Number(cidr.slice(slashIndex + 1));
    if (!Number.isInteger(prefix)) return false;

    const ipInt = ipv4ToInt(bareIp);
    const networkInt = ipv4ToInt(network);
    if (ipInt !== null && networkInt !== null) {
        if (prefix < 0 || prefix > 32) return false;
        const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
        return (ipInt & mask) === (networkInt & mask);
    }

    const ipBig = ipv6ToBigInt(bareIp);
    const networkBig = ipv6ToBigInt(network);
    if (ipBig !== null && networkBig !== null) {
        if (prefix < 0 || prefix > 128) return false;
        const mask = prefix === 0 ? 0n : ((1n << 128n) - 1n) << BigInt(128 - prefix);
        return (ipBig & mask) === (networkBig & mask);
    }

    return false;
}

/**
 * Returns whether an origin/request host matches a single allowlist entry.
 * Domains require an exact `URL.host` match (subdomains are not implied).
 * IP addresses without an explicit port also match the same address on any port
 * (e.g. `127.0.0.1` matches `127.0.0.1:8080`). CIDR entries match any IP in range.
 * `localhost` is treated as equivalent to `127.0.0.1`.
 * @param {string} host `URL.host` of the page origin or request target
 * @param {string} allowlistEntry A stored allowlist entry
 */
export function hostMatchesAllowlistEntry(host, allowlistEntry) {
    if (host === allowlistEntry) {
        return true;
    }

    if (isCIDRAllowlistEntry(allowlistEntry)) {
        const hostname = normalizeLoopbackHostname(hostnameFromHost(host));
        return ipInCIDR(hostname, allowlistEntry);
    }

    let hostUrl;
    let entryUrl;
    try {
        hostUrl = new URL(`http://${host}/`);
        entryUrl = new URL(`http://${allowlistEntry}/`);
    } catch {
        return false;
    }

    const hostHostname = normalizeLoopbackHostname(hostUrl.hostname);
    const entryHostname = normalizeLoopbackHostname(entryUrl.hostname);

    // Portless IP entry: match the same address on any port.
    if (entryUrl.host === entryUrl.hostname && isLiteralIpHostname(entryUrl.hostname)) {
        return hostHostname === entryHostname;
    }

    return false;
}

/**
 * Exact host match against the allowlist (subdomains are not implicitly allowed).
 * Also honors portless IP entries and CIDR ranges for the given host.
 * @param {string} originHost `URL.host` of the requesting page
 * @param {string[]} allowedDomains
 */
export function isHostAllowlisted(originHost, allowedDomains) {
    return allowedDomains.some((entry) => hostMatchesAllowlistEntry(originHost, entry));
}

/**
 * Whether a request should bypass blocking based on the allowlist.
 * Domain entries only match the page origin. IP and CIDR entries also match
 * request destinations so trusted addresses can be reached (e.g. from file://).
 * @param {string} originHost `URL.host` of the requesting page
 * @param {string|null|undefined} requestHost `URL.host` of the request target
 * @param {string[]} allowlist
 */
export function requestMatchesAllowlist(originHost, requestHost, allowlist) {
    return allowlist.some((entry) => {
        if (hostMatchesAllowlistEntry(originHost, entry)) {
            return true;
        }

        if (!requestHost || !isIPOrCIDREntry(entry)) {
            return false;
        }

        return hostMatchesAllowlistEntry(requestHost, entry);
    });
}
