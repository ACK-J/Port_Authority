/**
 * Cross-origin local navigation (Selective Allow) helpers.
 * Pure decision logic — no badge/notification side effects.
 */
import { isLocalRequestUrl } from "./privateAddress.js";

/** Storage key for persisted { origin, destination } pairs. */
export const CROSS_ORIGIN_ALLOWLIST_KEY = "cross_origin_allowlist";

/** Only allow files that live directly under selectiveAllow/. */
const SELECTIVE_ALLOW_PAGE = /^[A-Za-z0-9._-]+\.html$/;

/**
 * Stable allowlist / pending key for the page that initiated the navigation.
 * file:// URLs use the full path so one HTML file cannot authorize all files.
 * @param {URL} originUrl
 * @returns {string}
 */
export function originAllowKey(originUrl) {
    if (!(originUrl instanceof URL)) {
        return "unknown";
    }
    if (originUrl.protocol === "file:") {
        // pathname is percent-encoded and unique per file on a given OS.
        return `file://${originUrl.pathname}`;
    }
    if (originUrl.host) {
        return originUrl.host;
    }
    return originUrl.protocol.replace(":", "") || "unknown";
}

/**
 * @param {string} origin Allow-key of the initiating page
 * @param {string} destination URL.host of the local target
 * @returns {string}
 */
export function makeAllowKey(origin, destination) {
    return `${origin}|${destination}`;
}

/**
 * Restrict popup page names to a basename under selectiveAllow/.
 * @param {string} [page]
 * @returns {string|null}
 */
export function sanitizeSelectiveAllowPage(page = "selectiveAllow.html") {
    if (typeof page !== "string" || !SELECTIVE_ALLOW_PAGE.test(page)) {
        return null;
    }
    return page;
}

/**
 * True when the entry list already has this origin → destination pair.
 * @param {{ origin: string, destination: string }[]} list
 * @param {string} origin
 * @param {string} destination
 */
export function listHasCrossOriginEntry(list, origin, destination) {
    return (list ?? []).some(
        (entry) => entry?.origin === origin && entry?.destination === destination
    );
}

/**
 * Normalize an optional tab id from a popup message.
 * @param {unknown} tabId
 * @returns {{ ok: true, tabId: number|undefined } | { ok: false, reason: string }}
 */
function normalizeTabId(tabId) {
    if (tabId === undefined || tabId === null) {
        return { ok: true, tabId: undefined };
    }
    if (typeof tabId === "number" && Number.isInteger(tabId) && tabId >= 0) {
        return { ok: true, tabId };
    }
    if (typeof tabId === "string" && /^\d+$/.test(tabId)) {
        return { ok: true, tabId: Number(tabId) };
    }
    return { ok: false, reason: "invalid-tabId" };
}

/**
 * Validate a pending server-side prompt record before allowing navigation.
 * Uses the stored origin/destination/originalUrl — not client-supplied values.
 *
 * @param {{
 *   origin: string,
 *   destination: string,
 *   originalUrl: string,
 *   navigationTabId?: number,
 * }} pending
 * @param {unknown} [messageTabId] Optional tab id from the popup (ignored if pending has one)
 * @returns {{
 *   ok: true,
 *   origin: string,
 *   destination: string,
 *   originalUrl: string,
 *   tabId: number|undefined,
 *   parsedUrl: URL,
 * } | { ok: false, reason: string }}
 */
export function validatePendingAllow(pending, messageTabId) {
    if (!pending || typeof pending !== "object") {
        return { ok: false, reason: "missing-pending" };
    }

    const { origin, destination, originalUrl, navigationTabId } = pending;
    if (
        typeof origin !== "string" ||
        origin.length === 0 ||
        typeof destination !== "string" ||
        destination.length === 0 ||
        typeof originalUrl !== "string" ||
        originalUrl.length === 0
    ) {
        return { ok: false, reason: "invalid-pending" };
    }

    let parsedUrl;
    try {
        parsedUrl = new URL(originalUrl);
    } catch {
        return { ok: false, reason: "unparseable-url" };
    }

    if (parsedUrl.host !== destination) {
        return { ok: false, reason: "destination-mismatch" };
    }

    if (!isLocalRequestUrl(parsedUrl)) {
        return { ok: false, reason: "not-local" };
    }

    if (Number.isInteger(navigationTabId) && navigationTabId >= 0) {
        return {
            ok: true,
            origin,
            destination,
            originalUrl,
            tabId: navigationTabId,
            parsedUrl,
        };
    }

    const tab = normalizeTabId(messageTabId);
    if (!tab.ok) {
        return tab;
    }

    return {
        ok: true,
        origin,
        destination,
        originalUrl,
        tabId: tab.tabId,
        parsedUrl,
    };
}

/**
 * @typedef {object} PendingPrompt
 * @property {string} promptId
 * @property {string} origin
 * @property {string} destination
 * @property {string} originalUrl
 * @property {number|undefined} navigationTabId
 * @property {number} [uiWindowId]
 * @property {number} [uiTabId]
 */

/**
 * In-memory session allow + in-flight prompt tracking for one background page.
 * Cleared automatically when the browser / extension process restarts.
 */
export function createSelectiveAllowState() {
    /** @type {Set<string>} */
    const sessionAllowSet = new Set();
    /** @type {Map<string, PendingPrompt>} allowKey → record */
    const pendingByKey = new Map();
    /** @type {Map<string, string>} promptId → allowKey */
    const pendingById = new Map();
    /** @type {Map<number, string>} ui windowId → allowKey */
    const pendingByWindowId = new Map();
    /** @type {Map<number, string>} ui tabId → allowKey */
    const pendingByUiTabId = new Map();

    function clearIndexes(record) {
        if (!record) return;
        const key = makeAllowKey(record.origin, record.destination);
        pendingByKey.delete(key);
        pendingById.delete(record.promptId);
        if (Number.isInteger(record.uiWindowId)) {
            pendingByWindowId.delete(record.uiWindowId);
        }
        if (Number.isInteger(record.uiTabId)) {
            pendingByUiTabId.delete(record.uiTabId);
        }
    }

    return {
        isSessionAllowed(origin, destination) {
            return sessionAllowSet.has(makeAllowKey(origin, destination));
        },
        allowInSession(origin, destination) {
            sessionAllowSet.add(makeAllowKey(origin, destination));
        },
        hasPendingPrompt(origin, destination) {
            return pendingByKey.has(makeAllowKey(origin, destination));
        },

        /**
         * Register a new in-flight prompt. Replaces any existing pending for the pair.
         * @param {{
         *   origin: string,
         *   destination: string,
         *   originalUrl: string,
         *   navigationTabId?: number,
         * }} details
         * @returns {PendingPrompt}
         */
        createPendingPrompt(details) {
            const key = makeAllowKey(details.origin, details.destination);
            const existing = pendingByKey.get(key);
            if (existing) {
                clearIndexes(existing);
            }

            const promptId =
                globalThis.crypto?.randomUUID?.() ??
                `prompt-${Date.now()}-${Math.random().toString(16).slice(2)}`;

            /** @type {PendingPrompt} */
            const record = {
                promptId,
                origin: details.origin,
                destination: details.destination,
                originalUrl: details.originalUrl,
                navigationTabId: details.navigationTabId,
            };
            pendingByKey.set(key, record);
            pendingById.set(promptId, key);
            return record;
        },

        /**
         * @param {string} promptId
         * @returns {PendingPrompt|undefined}
         */
        getPendingByPromptId(promptId) {
            if (typeof promptId !== "string" || !promptId) return undefined;
            const key = pendingById.get(promptId);
            return key ? pendingByKey.get(key) : undefined;
        },

        /**
         * Attach the opened decision UI so chrome-close can clear pending.
         * @param {string} promptId
         * @param {{ mode: "window"|"tab", id?: number }} opened
         */
        bindPromptUi(promptId, opened) {
            const record = this.getPendingByPromptId(promptId);
            if (!record || !opened || !Number.isInteger(opened.id)) {
                return;
            }
            if (opened.mode === "window") {
                if (Number.isInteger(record.uiWindowId)) {
                    pendingByWindowId.delete(record.uiWindowId);
                }
                record.uiWindowId = opened.id;
                pendingByWindowId.set(opened.id, makeAllowKey(record.origin, record.destination));
            } else if (opened.mode === "tab") {
                if (Number.isInteger(record.uiTabId)) {
                    pendingByUiTabId.delete(record.uiTabId);
                }
                record.uiTabId = opened.id;
                pendingByUiTabId.set(opened.id, makeAllowKey(record.origin, record.destination));
            }
        },

        clearPendingPrompt(origin, destination) {
            const key = makeAllowKey(origin, destination);
            clearIndexes(pendingByKey.get(key));
        },

        clearPendingByPromptId(promptId) {
            clearIndexes(this.getPendingByPromptId(promptId));
        },

        clearPendingByWindowId(windowId) {
            const key = pendingByWindowId.get(windowId);
            if (!key) return;
            clearIndexes(pendingByKey.get(key));
        },

        clearPendingByUiTabId(tabId) {
            const key = pendingByUiTabId.get(tabId);
            if (!key) return;
            clearIndexes(pendingByKey.get(key));
        },

        /** @returns {number} */
        get sessionSize() {
            return sessionAllowSet.size;
        },
        /** @returns {number} */
        get pendingSize() {
            return pendingByKey.size;
        },
    };
}
