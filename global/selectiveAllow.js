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
 * @param {string} origin URL.host of the initiating page
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
 * Validate an Allow Once / Always Allow decision from the popup.
 * Rejects non-local targets and mismatched host / originalUrl pairs.
 *
 * @param {{
 *   origin?: unknown,
 *   destination?: unknown,
 *   originalUrl?: unknown,
 *   tabId?: unknown,
 * }} message
 * @returns {{
 *   ok: true,
 *   origin: string,
 *   destination: string,
 *   originalUrl: string,
 *   tabId: number|undefined,
 *   parsedUrl: URL,
 * } | { ok: false, reason: string }}
 */
export function validateAllowDecision(message) {
    if (!message || typeof message !== "object") {
        return { ok: false, reason: "invalid-message" };
    }

    const { origin, destination, originalUrl, tabId } = message;
    if (
        typeof origin !== "string" ||
        origin.length === 0 ||
        typeof destination !== "string" ||
        destination.length === 0 ||
        typeof originalUrl !== "string" ||
        originalUrl.length === 0
    ) {
        return { ok: false, reason: "invalid-fields" };
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

    let normalizedTabId;
    if (tabId === undefined || tabId === null) {
        normalizedTabId = undefined;
    } else if (typeof tabId === "number" && Number.isInteger(tabId) && tabId >= 0) {
        normalizedTabId = tabId;
    } else if (typeof tabId === "string" && /^\d+$/.test(tabId)) {
        normalizedTabId = Number(tabId);
    } else {
        return { ok: false, reason: "invalid-tabId" };
    }

    return {
        ok: true,
        origin,
        destination,
        originalUrl,
        tabId: normalizedTabId,
        parsedUrl,
    };
}

/**
 * In-memory session allow + in-flight prompt dedupe for one background page.
 * Cleared automatically when the browser / extension process restarts.
 */
export function createSelectiveAllowState() {
    /** @type {Set<string>} */
    const sessionAllowSet = new Set();
    /** @type {Set<string>} */
    const pendingPrompts = new Set();

    return {
        isSessionAllowed(origin, destination) {
            return sessionAllowSet.has(makeAllowKey(origin, destination));
        },
        allowInSession(origin, destination) {
            sessionAllowSet.add(makeAllowKey(origin, destination));
        },
        hasPendingPrompt(origin, destination) {
            return pendingPrompts.has(makeAllowKey(origin, destination));
        },
        markPendingPrompt(origin, destination) {
            pendingPrompts.add(makeAllowKey(origin, destination));
        },
        clearPendingPrompt(origin, destination) {
            pendingPrompts.delete(makeAllowKey(origin, destination));
        },
        /** @returns {number} */
        get sessionSize() {
            return sessionAllowSet.size;
        },
        /** @returns {number} */
        get pendingSize() {
            return pendingPrompts.size;
        },
    };
}
