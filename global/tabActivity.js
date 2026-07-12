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

/** @type {{ [tabId: string]: { [host: string]: Set<string> } }} */
let blockedPorts = {};

/** @type {{ [tabId: string]: Set<string> }} */
let blockedHosts = {};

/** Tabs whose activity changed since the last successful persist/clean. */
/** @type {Set<string>} */
let dirtyTabs = new Set();

/** True when any activity mutation has not yet been persisted. */
let activityDirty = false;

function markDirty(tabId) {
    activityDirty = true;
    if (tabId !== undefined && tabId !== null) {
        dirtyTabs.add(String(tabId));
    }
}

/**
 * @returns {boolean} Whether activity was dirty before this call.
 */
export function consumeActivityDirty() {
    const wasDirty = activityDirty;
    activityDirty = false;
    dirtyTabs.clear();
    return wasDirty;
}

/**
 * @returns {boolean}
 */
export function isActivityDirty() {
    return activityDirty;
}

/**
 * Snapshot of in-memory activity as plain JSON-ready objects (arrays, not Sets).
 * Built without structuredClone — only converts dirty-owned structures as needed.
 */
export function getTabActivitySnapshot() {
    /** @type {{ [tabId: string]: BadgeInfo }} */
    const badgeSnap = {};
    for (const tabId of Object.keys(badges)) {
        const badge = badges[tabId];
        badgeSnap[tabId] = {
            counter: badge.counter,
            alerted: badge.alerted,
            lastURL: badge.lastURL,
        };
    }

    /** @type {{ [tabId: string]: { [host: string]: string[] } }} */
    const portsSnap = {};
    for (const tabId of Object.keys(blockedPorts)) {
        const hosts = blockedPorts[tabId];
        /** @type {{ [host: string]: string[] }} */
        const hostMap = {};
        for (const host of Object.keys(hosts)) {
            hostMap[host] = Array.from(hosts[host]);
        }
        portsSnap[tabId] = hostMap;
    }

    /** @type {{ [tabId: string]: string[] }} */
    const hostsSnap = {};
    for (const tabId of Object.keys(blockedHosts)) {
        hostsSnap[tabId] = Array.from(blockedHosts[tabId]);
    }

    return {
        badges: badgeSnap,
        blocked_ports: portsSnap,
        blocked_hosts: hostsSnap,
    };
}

export function getBadgeForTab(tabId) {
    return badges[tabId];
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
    markDirty(tabId);
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
    markDirty(tabId);
}

/** Defensive caps so a pathological page cannot grow per-tab maps without bound. */
export const MAX_PORTS_PER_HOST = 100;
export const MAX_BLOCKED_HOSTS_PER_TAB = 200;

/**
 * Record a blocked port-scan target.
 * @param {number} tabId
 * @param {string} host
 * @param {string} port
 * @returns {boolean} true when a new port was recorded
 */
export function recordBlockedPort(tabId, host, port, maxPortsPerHost = MAX_PORTS_PER_HOST) {
    const tabHosts = blockedPorts[tabId] || (blockedPorts[tabId] = {});
    let ports = tabHosts[host];
    if (ports) {
        if (ports.has(port)) return false;
        if (ports.size >= maxPortsPerHost) return false;
        ports.add(port);
    } else {
        tabHosts[host] = new Set([port]);
    }
    markDirty(tabId);
    return true;
}

/**
 * Record a blocked ThreatMetrix/tracking host.
 * @param {number} tabId
 * @param {string} host
 * @returns {boolean} true when a new host was recorded
 */
export function recordBlockedTrackingHost(tabId, host, maxHostsPerTab = MAX_BLOCKED_HOSTS_PER_TAB) {
    let list = blockedHosts[tabId];
    if (list) {
        if (list.has(host)) return false;
        if (list.size >= maxHostsPerTab) return false;
        list.add(host);
    } else {
        blockedHosts[tabId] = new Set([host]);
    }
    markDirty(tabId);
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
    markDirty(tabId);

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
    dirtyTabs = new Set();
    activityDirty = false;
}
