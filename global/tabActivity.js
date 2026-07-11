/**
 * Session-scoped in-memory store for per-tab blocking activity.
 *
 * Issue #52: writing `badges` / `blocked_ports` / `blocked_hosts` through the
 * exclusive storage lock on every blocked request queued thousands of
 * JSON.stringify copies and lock waiters, ballooning WebExtensions RAM into
 * multi-GB territory on LexisNexis-heavy pages (and busy SPAs like Figma).
 *
 * Live state lives here; callers coalesce persistence separately.
 */

/** @typedef {{ counter: number, alerted: number, lastURL: string }} BadgeInfo */

/** @type {{ [tabId: string]: BadgeInfo }} */
let badges = {};

/** @type {{ [tabId: string]: { [host: string]: string[] } }} */
let blockedPorts = {};

/** @type {{ [tabId: string]: string[] }} */
let blockedHosts = {};

/**
 * Snapshot of in-memory activity (deep-enough copies for safe persistence).
 */
export function getTabActivitySnapshot() {
    return {
        badges: clone(badges),
        blocked_ports: clone(blockedPorts),
        blocked_hosts: clone(blockedHosts),
    };
}

export function getBadgeForTab(tabId) {
    return badges[tabId] ?? badges[String(tabId)];
}

/**
 * Drop all activity for a tab (tab closed).
 * @param {number|string} tabId
 */
export function clearTabActivity(tabId) {
    // Plain-object keys are always strings, so numeric and string ids alias.
    delete badges[tabId];
    delete blockedPorts[tabId];
    delete blockedHosts[tabId];
}

/**
 * Clear blocked host/port lists for a tab and reset its badge after navigation.
 * @param {number|string} tabId
 * @param {string} lastURL
 */
export function resetTabActivityForNavigation(tabId, lastURL) {
    delete blockedPorts[tabId];
    delete blockedHosts[tabId];
    badges[tabId] = {
        counter: 0,
        alerted: 0,
        lastURL,
    };
}

/**
 * Record a blocked port-scan target.
 * @param {number} tabId
 * @param {string} host
 * @param {string} port
 * @returns {boolean} true when a new port was recorded
 */
export function recordBlockedPort(tabId, host, port, maxPortsPerHost = 100) {
    const tabHosts = blockedPorts[tabId] || (blockedPorts[tabId] = {});
    const ports = tabHosts[host];
    if (Array.isArray(ports)) {
        if (ports.includes(port)) return false;
        if (ports.length >= maxPortsPerHost) return false;
        tabHosts[host] = ports.concat([port]);
    } else {
        tabHosts[host] = [port];
    }
    return true;
}

/**
 * Record a blocked ThreatMetrix/tracking host.
 * @param {number} tabId
 * @param {string} host
 * @returns {boolean} true when a new host was recorded
 */
export function recordBlockedTrackingHost(tabId, host, maxHostsPerTab = 200) {
    const list = blockedHosts[tabId] || (blockedHosts[tabId] = []);
    if (list.includes(host)) return false;
    if (list.length >= maxHostsPerTab) return false;
    blockedHosts[tabId] = list.concat([host]);
    return true;
}

/**
 * Increment the per-tab block counter.
 * @param {number} tabId
 * @param {string} url
 * @returns {{ counter: number, alerted: number, lastURL: string, shouldNotify: boolean }}
 */
export function incrementBadgeCounter(tabId, url) {
    if (!badges[tabId]) {
        badges[tabId] = {
            counter: 0,
            alerted: 0,
            lastURL: url,
        };
    }

    badges[tabId].counter += 1;
    const shouldNotify = badges[tabId].alerted === 0;
    if (shouldNotify) {
        badges[tabId].alerted += 1;
    }

    return {
        counter: badges[tabId].counter,
        alerted: badges[tabId].alerted,
        lastURL: badges[tabId].lastURL,
        shouldNotify,
    };
}

/**
 * Wipe in-memory maps (startup reset / tests).
 */
export function resetTabActivityMemory() {
    badges = {};
    blockedPorts = {};
    blockedHosts = {};
}

/**
 * Hydrate memory from already-parsed storage values (tests / rare recovery).
 * @param {{ badges?: object, blocked_ports?: object, blocked_hosts?: object }} data
 */
export function loadTabActivityMemory(data = {}) {
    badges = data.badges && typeof data.badges === "object" ? data.badges : {};
    blockedPorts =
        data.blocked_ports && typeof data.blocked_ports === "object"
            ? data.blocked_ports
            : {};
    blockedHosts =
        data.blocked_hosts && typeof data.blocked_hosts === "object"
            ? data.blocked_hosts
            : {};
}

function clone(value) {
    try {
        return structuredClone(value);
    } catch {
        return JSON.parse(JSON.stringify(value));
    }
}
