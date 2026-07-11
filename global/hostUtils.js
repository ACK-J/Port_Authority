const IPV4_PATTERN = /^(?:\d{1,3}\.){3}\d{1,3}$/;

/**
 * Returns whether a URL hostname represents an IP address (IPv4 or IPv6).
 * @param {string} hostname A URL.hostname value (IPv6 may include brackets)
 */
export function isIPAddress(hostname) {
    const bare = hostname.startsWith("[") ? hostname.slice(1, -1) : hostname;
    if (IPV4_PATTERN.test(bare)) {
        return true;
    }
    return bare.includes(":");
}

/**
 * Returns whether an allowlist entry uses CIDR notation.
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

    const bareNetwork = network.startsWith("[") ? network.slice(1, -1) : network;
    if (IPV4_PATTERN.test(bareNetwork)) {
        return prefix >= 0 && prefix <= 32 && ipv4ToInt(bareNetwork) !== null;
    }

    return prefix >= 0 && prefix <= 128 && ipv6ToBigInt(bareNetwork) !== null;
}

/**
 * Get a well-formed host to match against from a user-supplied URL.
 * @param {string} url A URL-like value
 * @returns {string} Well formatted host portion of url
 * @throws When parsing an invalid URL
 */
export function extractURLHost(url) {
    url = url.trim();

    if (!url.match(/^\w*:\/\//)) {
        const pathStart = url.indexOf("/");
        const hostPort = pathStart === -1 ? url : url.slice(0, pathStart);
        const path = pathStart === -1 ? "" : url.slice(pathStart);

        if (hostPort.includes(":") && !hostPort.startsWith("[")) {
            const isIPv4WithOptionalPort = /^(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?$/.test(hostPort);
            url = isIPv4WithOptionalPort ?
                `http://${hostPort}${path}` :
                `http://[${hostPort}]${path}`;
        } else {
            url = `http://${url}`;
        }
    }

    return new URL(url).host;
}

/**
 * Normalize and validate a user-supplied allowlist entry.
 * @param {string} input
 * @returns {string}
 * @throws When the entry is invalid
 */
export function normalizeAllowlistEntry(input) {
    input = input.trim();
    if (!input) {
        throw new Error("empty allowlist entry");
    }

    if (input.includes("/")) {
        if (!isCIDRAllowlistEntry(input)) {
            throw new Error("invalid CIDR notation");
        }
        return input;
    }

    return extractURLHost(input);
}

/**
 * Returns whether an origin host matches an allowlist entry.
 * Domains require an exact host match. IP addresses without an explicit port
 * also match the same address on any port (e.g. 127.0.0.1 matches 127.0.0.1:8080).
 * CIDR entries match any origin IP within the range.
 * @param {string} originHost A URL.host value from the request origin
 * @param {string} allowlistEntry A stored allowlist entry
 */
export function hostMatchesAllowlistEntry(originHost, allowlistEntry) {
    if (originHost === allowlistEntry) {
        return true;
    }

    if (isCIDRAllowlistEntry(allowlistEntry)) {
        let originHostname;
        try {
            originHostname = new URL(`http://${originHost}/`).hostname;
        } catch {
            return false;
        }
        return ipInCIDR(originHostname, allowlistEntry);
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

function ipv4ToInt(ip) {
    const parts = ip.split(".").map((part) => Number(part));
    if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
        return null;
    }
    return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

function expandIPv6(ip) {
    const bare = ip.replace(/^\[|\]$/g, "");
    if (!bare.includes("::")) {
        const groups = bare.split(":");
        if (groups.length !== 8) {
            return null;
        }
        return groups;
    }

    const [head, tail] = bare.split("::");
    const headGroups = head ? head.split(":").filter(Boolean) : [];
    const tailGroups = tail ? tail.split(":").filter(Boolean) : [];
    const missing = 8 - headGroups.length - tailGroups.length;
    if (missing < 0) {
        return null;
    }

    return [...headGroups, ...Array(missing).fill("0"), ...tailGroups];
}

function ipv6ToBigInt(ip) {
    const groups = expandIPv6(ip);
    if (!groups) {
        return null;
    }

    let value = 0n;
    for (const group of groups) {
        if (!/^[0-9a-f]{1,4}$/i.test(group)) {
            return null;
        }
        const part = Number.parseInt(group, 16);
        if (part < 0 || part > 0xffff) {
            return null;
        }
        value = (value << 16n) + BigInt(part);
    }

    return value;
}

function ipv4InCIDR(ip, cidr) {
    const slashIndex = cidr.lastIndexOf("/");
    const network = cidr.slice(0, slashIndex);
    const prefix = Number(cidr.slice(slashIndex + 1));
    const ipInt = ipv4ToInt(ip);
    const networkInt = ipv4ToInt(network);
    if (ipInt === null || networkInt === null || prefix < 0 || prefix > 32) {
        return false;
    }

    const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
    return (ipInt & mask) === (networkInt & mask);
}

function ipv6InCIDR(ip, cidr) {
    const slashIndex = cidr.lastIndexOf("/");
    const network = cidr.slice(0, slashIndex);
    const prefix = Number(cidr.slice(slashIndex + 1));
    const ipBig = ipv6ToBigInt(ip);
    const networkBig = ipv6ToBigInt(network);
    if (ipBig === null || networkBig === null || prefix < 0 || prefix > 128) {
        return false;
    }

    const mask = prefix === 0 ?
        0n :
        ((1n << 128n) - 1n) << BigInt(128 - prefix);
    return (ipBig & mask) === (networkBig & mask);
}

function ipInCIDR(ip, cidr) {
    const bareIp = ip.replace(/^\[|\]$/g, "");
    const slashIndex = cidr.lastIndexOf("/");
    const network = cidr.slice(0, slashIndex).replace(/^\[|\]$/g, "");

    if (IPV4_PATTERN.test(bareIp) && IPV4_PATTERN.test(network)) {
        return ipv4InCIDR(bareIp, cidr);
    }

    if (bareIp.includes(":") && network.includes(":")) {
        return ipv6InCIDR(bareIp, cidr);
    }

    return false;
}
