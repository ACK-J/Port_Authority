import { updateBadges, notifyThreatMetrix, notifyPortScanning } from "./browserActions.js";
import { getPortForProtocol } from "./constants.js";
import { normalizeHostname } from "./privateAddress.js";
import { compileAllowlist } from "./allowlist.js";
import {
    clearTabActivity,
    consumeActivityDirty,
    getTabActivitySnapshot,
    incrementBadgeCounter,
    isActivityDirty,
    recordBlockedPort,
    recordBlockedTrackingHost,
    resetTabActivityForNavigation,
    resetTabActivityMemory,
} from "./tabActivity.js";

const STORAGE_LOCK_KEY = "port_authority_storage_lock";

/** Coalesce hot-path activity writes so blocked-request storms cannot queue lock work. */
const TAB_ACTIVITY_PERSIST_MS = 75;

/** @type {ReturnType<typeof setTimeout> | null} */
let tabActivityPersistTimer = null;
/** @type {Promise<void> | null} */
let tabActivityPersistInFlight = null;
/** Bumped to invalidate in-flight persists that started before a session reset. */
let tabActivityPersistEpoch = 0;

/** @type {string[] | undefined} */
let allowedDomainListCache;
/** @type {import("./allowlist.js").CompiledAllowlist | undefined} */
let allowedDomainCompiledCache;
/** @type {boolean | undefined} */
let notificationsAllowedCache;

/**
 * Decode a storage value. Supports legacy JSON-stringified payloads and native values.
 * @param {any} storage_value
 * @param {any} default_value
 */
function decodeStorageValue(storage_value, default_value) {
    if (storage_value === undefined) {
        return default_value;
    }
    // Legacy installs stored JSON.stringify(value) as the storage cell.
    if (typeof storage_value === "string") {
        try {
            return JSON.parse(storage_value);
        } catch {
            // Non-JSON strings are treated as the value itself.
            return storage_value;
        }
    }
    return storage_value;
}

/**
 * Lock-free storage read. Callers must hold STORAGE_LOCK_KEY (shared or exclusive).
 * Native objects are stored directly; legacy string cells are still decoded.
 */
async function UNLOCKED_getItemFromLocal(key, default_value) {
    let storage_value;
    try {
        storage_value = await browser.storage.local.get(key);

        if (Object.keys(storage_value).length === 0) {
            return default_value;
        }

        return decodeStorageValue(storage_value[key], default_value);
    } catch (error) {
        console.error("Error getting storage value [" + key + "]: ", {
            error,
            default_value,
            storage_value,
        });
        return default_value;
    }
}

/**
 * Shared-lock read. Safe against mid-modify races.
 */
export async function getItemFromLocal(key, default_value) {
    return navigator.locks.request(
        STORAGE_LOCK_KEY,
        { mode: "shared" },
        async () => UNLOCKED_getItemFromLocal(key, default_value)
    );
}

/**
 * Exclusive-lock write of one key.
 * @template T
 * @param {string} key
 * @param {T} value
 * @returns {Promise<T>}
 */
export async function setItemInLocal(key, value) {
    return setItemsInLocal({ [key]: value }).then(() => value);
}

/**
 * Exclusive-lock write of multiple keys in one storage.set call.
 * Prefer this over sequential setItemInLocal when updating related keys.
 * Values are stored natively (no double JSON.stringify).
 * @param {{ [key: string]: any }} entries
 * @returns {Promise<{ [key: string]: any }>}
 */
export async function setItemsInLocal(entries) {
    return navigator.locks.request(STORAGE_LOCK_KEY, async () => {
        await browser.storage.local.set(entries);
        return entries;
    });
}

/**
 * Exclusive-lock read-modify-write.
 * @template T
 * @param {string} key
 * @param {T} default_value
 * @param {(original_value: T) => (T | Promise<T>)} mutate
 * @returns {Promise<T>}
 */
export async function modifyItemInLocal(key, default_value, mutate) {
    return navigator.locks.request(STORAGE_LOCK_KEY, async () => {
        const initial_value = await UNLOCKED_getItemFromLocal(key, default_value);
        const new_value = await mutate(initial_value);
        await browser.storage.local.set({ [key]: new_value });
        return new_value;
    });
}

/**
 * Clear storage and optionally seed defaults.
 * @param {{ [key: string]: any }} [default_structure]
 */
export async function clearItemsInLocal(default_structure = {}) {
    return navigator.locks.request(STORAGE_LOCK_KEY, async () => {
        await browser.storage.local.clear();
        if (Object.keys(default_structure).length > 0) {
            await browser.storage.local.set(default_structure);
        }
        return default_structure;
    });
}

function setAllowlistCaches(entries) {
    if (entries === undefined) {
        allowedDomainListCache = undefined;
        allowedDomainCompiledCache = undefined;
        return;
    }
    const list = Array.isArray(entries) ? entries : [];
    allowedDomainListCache = list;
    allowedDomainCompiledCache = compileAllowlist(list);
}

/**
 * Sync peek at the compiled allowlist when the hot-path cache is warm.
 * @returns {import("./allowlist.js").CompiledAllowlist | undefined}
 */
export function peekCompiledAllowlist() {
    return allowedDomainCompiledCache;
}

/**
 * In-memory allowlist for the blocking hot path (avoids lock + parse per request).
 * @returns {Promise<string[]>}
 */
export async function getAllowedDomainListCached() {
    if (allowedDomainListCache !== undefined) {
        return allowedDomainListCache;
    }
    const loaded = await getItemFromLocal("allowed_domain_list", []);
    setAllowlistCaches(Array.isArray(loaded) ? loaded : []);
    return allowedDomainListCache;
}

/**
 * Compiled allowlist for the blocking hot path.
 * @returns {Promise<import("./allowlist.js").CompiledAllowlist>}
 */
export async function getCompiledAllowlistCached() {
    if (allowedDomainCompiledCache !== undefined) {
        return allowedDomainCompiledCache;
    }
    await getAllowedDomainListCached();
    return allowedDomainCompiledCache;
}

/**
 * @param {string[] | undefined} [nextValue]
 */
export function syncAllowedDomainListCache(nextValue) {
    setAllowlistCaches(nextValue);
}

async function getNotificationsAllowedCached() {
    if (notificationsAllowedCache !== undefined) {
        return notificationsAllowedCache;
    }
    notificationsAllowedCache = await getItemFromLocal("notificationsAllowed", true);
    return Boolean(notificationsAllowedCache);
}

/**
 * @param {boolean | undefined} [nextValue]
 */
export function syncNotificationsAllowedCache(nextValue) {
    notificationsAllowedCache = nextValue === undefined
        ? undefined
        : Boolean(nextValue);
}

/**
 * Parse a storage.onChanged newValue (native object or legacy JSON string).
 * @param {any} raw
 * @returns {any | undefined}
 */
function parseChangedValue(raw) {
    if (raw === undefined) return undefined;
    return decodeStorageValue(raw, undefined);
}

/**
 * Apply storage.onChanged updates to in-memory settings caches.
 * @param {{ [key: string]: { newValue?: any } }} changes
 */
export function applyStorageChangesToCaches(changes) {
    if (Object.prototype.hasOwnProperty.call(changes, "allowed_domain_list")) {
        syncAllowedDomainListCache(parseChangedValue(changes.allowed_domain_list?.newValue));
    }
    if (Object.prototype.hasOwnProperty.call(changes, "notificationsAllowed")) {
        const parsed = parseChangedValue(changes.notificationsAllowed?.newValue);
        syncNotificationsAllowedCache(parsed === undefined ? undefined : Boolean(parsed));
    }
}

function clearTabActivityPersistTimer() {
    if (tabActivityPersistTimer !== null) {
        clearTimeout(tabActivityPersistTimer);
        tabActivityPersistTimer = null;
    }
}

function scheduleTabActivityPersist() {
    if (tabActivityPersistTimer !== null) return;
    tabActivityPersistTimer = setTimeout(() => {
        tabActivityPersistTimer = null;
        const epoch = tabActivityPersistEpoch;
        tabActivityPersistInFlight = persistTabActivityNow(epoch).finally(() => {
            tabActivityPersistInFlight = null;
        });
    }, TAB_ACTIVITY_PERSIST_MS);
}

/**
 * Flush in-memory tab activity to extension storage (single coalesced write path).
 * @returns {Promise<void>}
 */
export async function flushTabActivity() {
    clearTabActivityPersistTimer();
    if (tabActivityPersistInFlight) {
        await tabActivityPersistInFlight;
    }
    // A mutation during the await may have armed a new debounce timer — drop it
    // and write the latest snapshot once.
    clearTabActivityPersistTimer();
    await persistTabActivityNow(tabActivityPersistEpoch);
}

async function persistTabActivityNow(epoch = tabActivityPersistEpoch) {
    if (epoch !== tabActivityPersistEpoch) return;
    if (!isActivityDirty()) return;

    // Build a plain snapshot synchronously, then clear dirty before the await so
    // mutations during the write re-arm persistence.
    const snapshot = getTabActivitySnapshot();
    consumeActivityDirty();
    if (epoch !== tabActivityPersistEpoch) return;

    await setItemsInLocal({
        badges: snapshot.badges,
        blocked_ports: snapshot.blocked_ports,
        blocked_hosts: snapshot.blocked_hosts,
    });
}

/**
 * Clear per-tab activity when a tab closes or navigates.
 * @param {number|string} tabId
 */
export function clearTabActivityData(tabId) {
    clearTabActivity(tabId);
    scheduleTabActivityPersist();
}

/**
 * Reset session activity in memory and storage.
 * Prevents stale/corrupt per-tab blobs from prior sessions from accumulating (#52).
 */
export async function resetSessionTabActivity() {
    clearTabActivityPersistTimer();
    tabActivityPersistEpoch += 1;
    const epoch = tabActivityPersistEpoch;

    if (tabActivityPersistInFlight) {
        try {
            await tabActivityPersistInFlight;
        } catch {
            // ignore — we're about to overwrite anyway
        }
    }

    clearTabActivityPersistTimer();
    resetTabActivityMemory();

    if (epoch !== tabActivityPersistEpoch) return;

    await setItemsInLocal({
        badges: {},
        blocked_ports: {},
        blocked_hosts: {},
    });
}

/**
 * Flush activity and return the blocked ports/hosts for one tab (popup path).
 * @param {number|string} tabId
 * @returns {Promise<{ blocked_ports: object, blocked_hosts: string[] }>}
 */
export async function getTabActivityForTab(tabId) {
    await flushTabActivity();
    const snapshot = getTabActivitySnapshot();
    return {
        blocked_ports: snapshot.blocked_ports[tabId] ?? {},
        blocked_hosts: snapshot.blocked_hosts[tabId] ?? [],
    };
}

/**
 * Record a blocked port-scan target for a tab.
 * @param {URL} url
 * @param {string|number} tabIdString
 */
export function addBlockedPortToHost(url, tabIdString) {
    const tabId = parseInt(tabIdString, 10);
    if (Number.isNaN(tabId) || tabId < 0) return false;

    // Prefer hostname over host so ports are not mangled; normalize strips IPv6 brackets
    // (Node's URL keeps them; Firefox does not).
    const host = normalizeHostname(url.hostname);
    const mappedPort = getPortForProtocol(url.protocol);
    const port = url.port || (mappedPort != null ? String(mappedPort) : "");
    if (!port) return false;

    const changed = recordBlockedPort(tabId, host, port);
    if (changed) scheduleTabActivityPersist();
    return changed;
}

/**
 * Record a blocked tracking host for a tab.
 * @param {URL} url
 * @param {string|number} tabIdString
 */
export function addBlockedTrackingHost(url, tabIdString) {
    const tabId = parseInt(tabIdString, 10);
    if (Number.isNaN(tabId) || tabId < 0) return false;

    const changed = recordBlockedTrackingHost(tabId, normalizeHostname(url.hostname));
    if (changed) scheduleTabActivityPersist();
    return changed;
}

/**
 * Increase the badge and optionally fire a one-shot notification.
 * Memory update is synchronous; disk persistence is coalesced (issue #52).
 * @param {{ tabId?: number, url?: string, originUrl?: string } | null} request
 * @param {boolean} isThreatMetrix
 * @param {string} [originHostHint] Pre-parsed origin host to avoid a second URL parse
 */
export async function increaseBadge(request, isThreatMetrix, originHostHint) {
    const tabId = request?.tabId;
    const url = request?.url;

    if (!request || tabId === -1 || tabId === undefined || tabId === null) {
        console.error("Invalid `request` passed to increaseBadge:", { request, isThreatMetrix });
        return;
    }

    const { counter, shouldNotify } = incrementBadgeCounter(
        tabId,
        request.originUrl || url
    );
    updateBadges(counter, tabId);
    scheduleTabActivityPersist();

    if (!shouldNotify) return;

    const notifications_enabled = await getNotificationsAllowedCached();
    if (!notifications_enabled) return;

    try {
        const host = originHostHint ?? new URL(request.originUrl).host;
        if (isThreatMetrix) {
            await notifyThreatMetrix(host);
        } else {
            await notifyPortScanning(host);
        }
    } catch (error) {
        console.error("Failed to notify for blocked request:", { request, error });
    }
}

/**
 * Reset badge counters and blocked lists after a tab navigates to a new URL.
 * @param {number|string} tabId
 * @param {string} lastURL
 */
export function resetTabDataForNavigation(tabId, lastURL) {
    resetTabActivityForNavigation(tabId, lastURL);
    scheduleTabActivityPersist();
}
