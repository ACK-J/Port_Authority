/**
 * Cross-origin local navigation (Selective Allow) helpers.
 * Pure decision logic — no badge/notification side effects.
 */
import { isLocalRequestUrl } from "./privateAddress.js";

/** Storage key for persisted { origin, destination } pairs. */
export const CROSS_ORIGIN_ALLOWLIST_KEY = "cross_origin_allowlist";

/** Reject pathological data:/blob keys from being persisted or prompted. */
const MAX_ORIGIN_KEY_LENGTH = 512;

/**
 * Stable allowlist / pending key for the page that initiated the navigation.
 * - http(s) / host-based: `URL.host`
 * - file://: path so one HTML file cannot authorize all files
 * - other hostless (blob:, about:, …): full href without hash
 * Returns null when the initiator cannot be keyed safely (caller should silent-block).
 * @param {URL} originUrl
 * @returns {string|null}
 */
export function originAllowKey(originUrl) {
    if (!(originUrl instanceof URL)) {
        return null;
    }
    if (originUrl.protocol === "file:") {
        return `file://${originUrl.pathname}`;
    }
    if (originUrl.host) {
        return originUrl.host;
    }
    // data: URLs are content-addressed and can be huge — do not selective-allow.
    if (originUrl.protocol === "data:") {
        return null;
    }
    const key = originUrl.href.split("#")[0];
    if (!key || key.length > MAX_ORIGIN_KEY_LENGTH) {
        return null;
    }
    return key;
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
 * Validate a pending server-side prompt record before allowing navigation.
 * @param {PendingPrompt|undefined|null} pending
 * @returns {{
 *   ok: true,
 *   origin: string,
 *   destination: string,
 *   originalUrl: string,
 *   tabId: number|undefined,
 *   parsedUrl: URL,
 * } | { ok: false, reason: string }}
 */
export function validatePendingAllow(pending) {
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

    const tabId =
        Number.isInteger(navigationTabId) && navigationTabId >= 0
            ? navigationTabId
            : undefined;

    return {
        ok: true,
        origin,
        destination,
        originalUrl,
        tabId,
        parsedUrl,
    };
}

function newPromptId() {
    return (
        globalThis.crypto?.randomUUID?.() ??
        `prompt-${Date.now()}-${Math.random().toString(16).slice(2)}`
    );
}

/**
 * In-memory session allow + in-flight prompt tracking for one background page.
 * One map keyed by promptId; close handlers scan (prompt count stays tiny).
 */
export function createSelectiveAllowState() {
    /** @type {Set<string>} Allow Once only — never mirrors Always Allow. */
    const sessionAllowSet = new Set();
    /** @type {Map<string, PendingPrompt>} */
    const pendingById = new Map();

    function findPending(predicate) {
        for (const record of pendingById.values()) {
            if (predicate(record)) return record;
        }
        return undefined;
    }

    return {
        isSessionAllowed(origin, destination) {
            return sessionAllowSet.has(makeAllowKey(origin, destination));
        },

        /** Allow Once — session memory only. */
        allowInSession(origin, destination) {
            sessionAllowSet.add(makeAllowKey(origin, destination));
        },

        /** Drop a session allow (e.g. settings removed a persisted pair). */
        revokeSessionAllow(origin, destination) {
            sessionAllowSet.delete(makeAllowKey(origin, destination));
        },

        hasPendingPrompt(origin, destination) {
            return Boolean(
                findPending(
                    (r) => r.origin === origin && r.destination === destination
                )
            );
        },

        /**
         * Atomically create-or-update the pending prompt for a pair.
         * Callers should only open UI when `created` is true.
         * @param {{
         *   origin: string,
         *   destination: string,
         *   originalUrl: string,
         *   navigationTabId?: number,
         * }} details
         * @returns {{ pending: PendingPrompt, created: boolean }}
         */
        ensurePendingPrompt(details) {
            const existing = findPending(
                (r) => r.origin === details.origin && r.destination === details.destination
            );
            if (existing) {
                existing.originalUrl = details.originalUrl;
                existing.navigationTabId = details.navigationTabId;
                return { pending: existing, created: false };
            }

            /** @type {PendingPrompt} */
            const record = {
                promptId: newPromptId(),
                origin: details.origin,
                destination: details.destination,
                originalUrl: details.originalUrl,
                navigationTabId: details.navigationTabId,
            };
            pendingById.set(record.promptId, record);
            return { pending: record, created: true };
        },

        /**
         * @param {string} promptId
         * @returns {PendingPrompt|undefined}
         */
        getPendingByPromptId(promptId) {
            if (typeof promptId !== "string" || !promptId) return undefined;
            return pendingById.get(promptId);
        },

        /**
         * @param {string} promptId
         * @param {{ mode: "window"|"tab", id: number }} opened
         * @returns {boolean} false when the UI id cannot be bound
         */
        bindPromptUi(promptId, opened) {
            const record = pendingById.get(promptId);
            if (!record || !opened || !Number.isInteger(opened.id) || opened.id < 0) {
                return false;
            }
            if (opened.mode === "window") {
                record.uiWindowId = opened.id;
                delete record.uiTabId;
            } else if (opened.mode === "tab") {
                record.uiTabId = opened.id;
                delete record.uiWindowId;
            } else {
                return false;
            }
            return true;
        },

        clearPendingByPromptId(promptId) {
            pendingById.delete(promptId);
        },

        clearPendingByWindowId(windowId) {
            const record = findPending((r) => r.uiWindowId === windowId);
            if (record) pendingById.delete(record.promptId);
        },

        clearPendingByUiTabId(tabId) {
            const record = findPending((r) => r.uiTabId === tabId);
            if (record) pendingById.delete(record.promptId);
        },

        /** @returns {number} */
        get sessionSize() {
            return sessionAllowSet.size;
        },
        /** @returns {number} */
        get pendingSize() {
            return pendingById.size;
        },
    };
}
