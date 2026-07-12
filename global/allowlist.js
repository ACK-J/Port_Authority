/**
 * Helpers for the domain/IP/CIDR allowlist used by settings UI and request filtering.
 *
 * Parsing is URL-first via the URL API. CIDR is a special case because the URL
 * standard treats `/24` as a pathname, not a prefix length — so after a successful
 * URL parse we optionally interpret an exact single numeric path segment as a
 * CIDR prefix when the hostname is an IP literal.
 */
import {
    isLiteralIpHostname,
    normalizeHostname,
    parseIPv4Octets,
    expandIPv6,
    unwrapIpv4MappedAddress,
} from "./privateAddress.js";

function isAllDigits(value) {
    if (!value) return false;
    for (let i = 0; i < value.length; i++) {
        const code = value.charCodeAt(i);
        if (code < 48 || code > 57) return false;
    }
    return true;
}

function countChar(value, ch) {
    let n = 0;
    for (let i = 0; i < value.length; i++) {
        if (value[i] === ch) n++;
    }
    return n;
}

/**
 * Parse a user paste into a URL. Bare hosts/CIDRs get an `http://` scheme;
 * bare IPv6 literals are bracketed so URL() accepts them.
 * @param {string} input
 * @returns {URL}
 */
function parseAllowlistUrl(input) {
    input = input.trim();
    const looksAbsolute = input.indexOf("://") > 0;

    try {
        const direct = new URL(input);
        // Only trust absolute URLs that actually have a host. Some engines (notably
        // Node) accept bare strings like `example.com:8080` or `fe80::/10` as
        // opaque URLs with an empty host — those must use the bare-host path.
        if (direct.host) {
            return direct;
        }
        if (looksAbsolute) {
            throw new TypeError("Invalid URL");
        }
    } catch (error) {
        // Scheme-bearing input that failed to parse must not be reinterpreted as
        // a bare host (e.g. `http://` → `http://http//`).
        if (looksAbsolute) {
            throw error instanceof TypeError ? error : new TypeError("Invalid URL");
        }
        // Otherwise fall through and treat as a bare host / CIDR / IPv6 literal.
    }

    const pathStart = input.indexOf("/");
    const hostPort = pathStart === -1 ? input : input.slice(0, pathStart);
    const path = pathStart === -1 ? "" : input.slice(pathStart);

    if (hostPort.startsWith("[")) {
        return new URL(`http://${hostPort}${path}`);
    }

    // Bare IPv6 has ≥2 colons. IPv4/hostname:port has at most one.
    // (URL() rejects `http://::1` without brackets.)
    if (countChar(hostPort, ":") >= 2) {
        return new URL(`http://[${hostPort}]${path}`);
    }

    return new URL(`http://${hostPort}${path}`);
}

/**
 * Get a well-formed host to match against from a user-supplied URL-like string.
 * @param {string} url A URL-like value (eg `https://example.com/path`, `discord.com`, `example.com:8080`)
 * @returns {string} Host portion including port when non-default (eg `example.com`, `example.com:8080`)
 * @throws {TypeError} When the input cannot be parsed as a URL
 */
export function extractURLHost(url) {
    return parseAllowlistUrl(url).host;
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
        // Use `.port` (not host===hostname): IPv6 brackets can make host≠hostname
        // in some URL implementations.
        return entryUrl.port === "" && isLiteralIpHostname(entryUrl.hostname);
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

    const parsed = parseAllowlistUrl(input);
    const cidr = cidrFromParsedUrl(parsed);
    if (cidr) {
        return cidr;
    }
    return parsed.host;
}

/**
 * If `parsed` is an IP URL whose path is exactly a prefix length (`/24`),
 * return normalized `network/prefix`. Extra path segments are not CIDR.
 * @param {URL} parsed
 * @returns {string|null}
 */
function cidrFromParsedUrl(parsed) {
    const bareNetwork = normalizeHostname(parsed.hostname);
    if (!isLiteralIpHostname(bareNetwork)) {
        return null;
    }

    const segments = parsed.pathname.split("/").filter((part) => part.length > 0);
    if (segments.length !== 1 || !isAllDigits(segments[0])) {
        return null;
    }

    const candidate = `${bareNetwork}/${segments[0]}`;
    if (isCIDRAllowlistEntry(candidate)) {
        return candidate;
    }

    // Exact `ip/N` with an out-of-range prefix is a CIDR typo, not a page path.
    throw new Error("invalid CIDR notation");
}

/**
 * Canonical hostname for IP allowlist compares: unwrap mapped IPv6, map localhost → 127.0.0.1.
 * @param {string} hostname
 */
function canonicalizeAllowlistHostname(hostname) {
    const unwrapped = unwrapIpv4MappedAddress(hostname);
    return unwrapped === "localhost" ? "127.0.0.1" : unwrapped;
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
    const bareIp = canonicalizeAllowlistHostname(ip);
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
        const hostname = canonicalizeAllowlistHostname(hostnameFromHost(host));
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

    const hostHostname = canonicalizeAllowlistHostname(hostUrl.hostname);
    const entryHostname = canonicalizeAllowlistHostname(entryUrl.hostname);

    // Portless IP entry: match the same address on any port.
    // Check `.port` rather than host===hostname — IPv6 bracket handling differs
    // across URL implementations (Node keeps brackets on hostname; some browsers omit them).
    if (entryUrl.port === "" && isLiteralIpHostname(entryUrl.hostname)) {
        return hostHostname === entryHostname;
    }

    return false;
}

/**
 * @typedef {object} CompiledCidr
 * @property {string} cidr
 * @property {4|6} version
 * @property {number|null} networkInt
 * @property {bigint|null} networkBig
 * @property {number} prefix
 * @property {number|null} maskInt
 * @property {bigint|null} maskBig
 */

/**
 * @typedef {object} CompiledAllowlist
 * @property {true} __compiled
 * @property {Set<string>} exactHosts Exact `URL.host` entries (domains and host:port)
 * @property {Set<string>} portlessIps Canonical portless IP literals
 * @property {CompiledCidr[]} cidrs Pre-parsed CIDR ranges
 */

/**
 * Preclassify allowlist entries so hot-path matching avoids per-request URL/CIDR re-parsing.
 * @param {string[]|null|undefined} entries
 * @returns {CompiledAllowlist}
 */
export function compileAllowlist(entries) {
    /** @type {Set<string>} */
    const exactHosts = new Set();
    /** @type {Set<string>} */
    const portlessIps = new Set();
    /** @type {CompiledCidr[]} */
    const cidrs = [];

    if (!Array.isArray(entries)) {
        return { __compiled: true, exactHosts, portlessIps, cidrs };
    }

    for (const entry of entries) {
        if (typeof entry !== "string" || !entry) continue;

        if (isCIDRAllowlistEntry(entry)) {
            const slashIndex = entry.lastIndexOf("/");
            const network = normalizeHostname(entry.slice(0, slashIndex));
            const prefix = Number(entry.slice(slashIndex + 1));
            const networkInt = ipv4ToInt(network);
            if (networkInt !== null) {
                const maskInt = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
                cidrs.push({
                    cidr: entry,
                    version: 4,
                    networkInt,
                    networkBig: null,
                    prefix,
                    maskInt,
                    maskBig: null,
                });
                continue;
            }
            const networkBig = ipv6ToBigInt(network);
            if (networkBig !== null) {
                const maskBig =
                    prefix === 0 ? 0n : ((1n << 128n) - 1n) << BigInt(128 - prefix);
                cidrs.push({
                    cidr: entry,
                    version: 6,
                    networkInt: null,
                    networkBig,
                    prefix,
                    maskInt: null,
                    maskBig,
                });
            }
            continue;
        }

        try {
            const entryUrl = new URL(`http://${entry}/`);
            if (entryUrl.port === "" && isLiteralIpHostname(entryUrl.hostname)) {
                portlessIps.add(canonicalizeAllowlistHostname(entryUrl.hostname));
                continue;
            }
        } catch {
            // Fall through to exact-host storage.
        }

        exactHosts.add(entry);
    }

    return { __compiled: true, exactHosts, portlessIps, cidrs };
}

/**
 * @param {unknown} value
 * @returns {value is CompiledAllowlist}
 */
export function isCompiledAllowlist(value) {
    return Boolean(value && typeof value === "object" && value.__compiled === true);
}

/**
 * @param {string} host
 * @returns {string} Canonical hostname for IP/CIDR compares
 */
function canonicalHostnameFromHost(host) {
    let hostname;
    try {
        hostname = new URL(`http://${host}/`).hostname;
    } catch {
        // Bare IPv6 without brackets (e.g. fe80::1) is not a valid URL authority.
        hostname = host;
    }
    return canonicalizeAllowlistHostname(hostname);
}

/**
 * @param {string} hostname Canonical hostname (no port)
 * @param {CompiledAllowlist} compiled
 * @returns {boolean}
 */
function ipOrCidrMatchesCompiled(hostname, compiled) {
    if (compiled.portlessIps.has(hostname)) {
        return true;
    }

    for (const rule of compiled.cidrs) {
        if (rule.version === 4) {
            const ipInt = ipv4ToInt(hostname);
            if (ipInt !== null && (ipInt & rule.maskInt) === (rule.networkInt & rule.maskInt)) {
                return true;
            }
            continue;
        }
        const ipBig = ipv6ToBigInt(hostname);
        if (ipBig !== null && (ipBig & rule.maskBig) === (rule.networkBig & rule.maskBig)) {
            return true;
        }
    }

    return false;
}

/**
 * Origin-style match: exact hosts, portless IPs, and CIDRs.
 * @param {string} host
 * @param {CompiledAllowlist} compiled
 * @returns {boolean}
 */
function hostMatchesCompiled(host, compiled) {
    if (compiled.exactHosts.has(host)) {
        return true;
    }

    if (compiled.portlessIps.size === 0 && compiled.cidrs.length === 0) {
        return false;
    }

    return ipOrCidrMatchesCompiled(canonicalHostnameFromHost(host), compiled);
}

/**
 * Destination-style match: IP/CIDR entries only (domains never match destinations).
 * @param {string} host
 * @param {CompiledAllowlist} compiled
 * @returns {boolean}
 */
function destinationMatchesCompiled(host, compiled) {
    if (compiled.portlessIps.size === 0 && compiled.cidrs.length === 0) {
        return false;
    }

    return ipOrCidrMatchesCompiled(canonicalHostnameFromHost(host), compiled);
}

/**
 * Exact host match against the allowlist (subdomains are not implicitly allowed).
 * Also honors portless IP entries and CIDR ranges for the given host.
 * @param {string} originHost `URL.host` of the requesting page
 * @param {string[]|CompiledAllowlist} allowedDomains
 */
export function isHostAllowlisted(originHost, allowedDomains) {
    const compiled = isCompiledAllowlist(allowedDomains)
        ? allowedDomains
        : compileAllowlist(allowedDomains);
    return hostMatchesCompiled(originHost, compiled);
}

/**
 * Whether a request should bypass blocking based on the allowlist.
 * Domain entries only match the page origin. IP and CIDR entries also match
 * request destinations so trusted addresses can be reached (e.g. from file://).
 * @param {string} originHost `URL.host` of the requesting page
 * @param {string|null|undefined} requestHost `URL.host` of the request target
 * @param {string[]|CompiledAllowlist} allowlist
 */
export function requestMatchesAllowlist(originHost, requestHost, allowlist) {
    const compiled = isCompiledAllowlist(allowlist) ? allowlist : compileAllowlist(allowlist);
    if (hostMatchesCompiled(originHost, compiled)) {
        return true;
    }
    if (!requestHost) {
        return false;
    }
    return destinationMatchesCompiled(requestHost, compiled);
}
