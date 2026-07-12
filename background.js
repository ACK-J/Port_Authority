import {
    getItemFromLocal,
    setItemInLocal,
    modifyItemInLocal,
    addBlockedPortToHost,
    addBlockedTrackingHost,
    increaseBadge,
    getAllowedDomainListCached,
    applyStorageChangesToCaches,
    resetSessionTabActivity,
    clearTabActivityData,
    resetTabDataForNavigation,
    getTabActivityForTab,
} from "./global/BrowserStorageManager.js";
import { getBadgeForTab } from "./global/tabActivity.js";
import { evaluateRequest, createDnsResultCache } from "./global/requestFilter.js";
import {
    openSelectiveAllowPopup,
    notifySelectiveAllow,
} from "./global/browserActions.js";
import { isLocalRequestUrl } from "./global/privateAddress.js";
import {
    CROSS_ORIGIN_ALLOWLIST_KEY,
    createSelectiveAllowState,
    listHasCrossOriginEntry,
    originAllowKey,
    validatePendingAllow,
} from "./global/selectiveAllow.js";

/** Session-scoped DNS result cache — not persisted to disk. */
const dnsResultCache = createDnsResultCache();

/** Session allow (Allow Once) + pending-prompt tracking. */
const selectiveAllow = createSelectiveAllowState();

async function startup() {
    // Defaults apply until settings are explicitly written.
    console.log("Startup called");

    // Drop stale/corrupt per-tab activity left from prior sessions (issue #52).
    await resetSessionTabActivity();

    // Warm the allowlist cache so the first requests avoid a storage round-trip.
    await getAllowedDomainListCached();

    const state = await getItemFromLocal("blocking_enabled", true);
    if (state === true) {
        await start();
    } else {
        await stop();
    }
}

function blockPortScan(requestDetails, url) {
    increaseBadge(requestDetails, false);
    addBlockedPortToHost(url, requestDetails.tabId);
    return { cancel: true };
}

/** @param {number|undefined} tabId */
function normalizedNavigationTabId(tabId) {
    return Number.isInteger(tabId) && tabId >= 0 ? tabId : undefined;
}

/**
 * Open the decision UI outside the blocking webRequest stack.
 * Pending is cleared unless a UI id is successfully bound for close tracking.
 */
function scheduleSelectiveAllowPrompt(pending) {
    setTimeout(() => {
        (async () => {
            let opened;
            try {
                opened = await openSelectiveAllowPopup(
                    pending.origin,
                    pending.destination,
                    pending.originalUrl,
                    pending.promptId
                );
            } catch (error) {
                console.error("Failed to open selective allow prompt:", error);
                selectiveAllow.clearPendingByPromptId(pending.promptId);
                return;
            }

            if (!opened || !selectiveAllow.bindPromptUi(pending.promptId, opened)) {
                console.error("Selective allow UI opened without a trackable id");
                selectiveAllow.clearPendingByPromptId(pending.promptId);
                return;
            }

            try {
                await notifySelectiveAllow(pending.origin, pending.destination);
            } catch (error) {
                console.warn("Selective allow notification failed:", error);
            }
        })();
    }, 0);
}

/**
 * Top-level navigations to literal local addresses get a Selective Allow prompt
 * instead of a silent block. Subresource port scans still use blockPortScan().
 */
async function handleSelectiveAllowNavigation(requestDetails, url) {
    let originUrl;
    try {
        originUrl = new URL(requestDetails.originUrl);
    } catch {
        return blockPortScan(requestDetails, url);
    }

    const origin = originAllowKey(originUrl);
    const destination = url.host;
    if (!origin || !destination) {
        // Unkeyable opaque initiator (e.g. data:) — keep the silent block path.
        return blockPortScan(requestDetails, url);
    }

    // Allow Once (session) — Always Allow is storage-only and checked below.
    if (selectiveAllow.isSessionAllowed(origin, destination)) {
        return { cancel: false };
    }

    const crossOriginList = await getItemFromLocal(CROSS_ORIGIN_ALLOWLIST_KEY, []);
    if (listHasCrossOriginEntry(crossOriginList, origin, destination)) {
        return { cancel: false };
    }

    // Atomic create-or-update after the storage await so concurrent navigations
    // for the same pair share one promptId / one decision UI.
    const { pending, created } = selectiveAllow.ensurePendingPrompt({
        origin,
        destination,
        originalUrl: requestDetails.url,
        navigationTabId: normalizedNavigationTabId(requestDetails.tabId),
    });
    if (created) {
        scheduleSelectiveAllowPrompt(pending);
    }

    return { cancel: true };
}

async function cancel(requestDetails) {
    const decision = await evaluateRequest(requestDetails, {
        getAllowedDomains: () => getAllowedDomainListCached(),
        resolveDns: (hostname) => browser.dns.resolve(hostname, ["canonical_name"]),
        dnsCache: dnsResultCache,
    });

    if (!decision.cancel) {
        if (decision.reason === "unparseable-origin") {
            console.error("Aborted filtering on domain due to unparseable originUrl: ", requestDetails.originUrl);
        } else if (decision.reason === "unparseable-url") {
            console.error("Error filtering on domain due to unparseable request URL: ", requestDetails.url);
        } else if (decision.reason === "dns-failure") {
            console.warn("DNS resolution failed for request:", requestDetails.url);
        }
        return { cancel: false };
    }

    if (decision.reason === "portscan") {
        if (
            requestDetails.type === "main_frame" &&
            decision.url &&
            isLocalRequestUrl(decision.url)
        ) {
            return handleSelectiveAllowNavigation(requestDetails, decision.url);
        }
        return blockPortScan(requestDetails, decision.url);
    }

    if (decision.reason === "threatmetrix") {
        increaseBadge(requestDetails, true);
        addBlockedTrackingHost(decision.url, requestDetails.tabId);
        return { cancel: true };
    }

    return { cancel: false };
}

async function start() {
    try {
        if (browser.webRequest.onBeforeRequest.hasListener(cancel)) {
            console.log("Blocking listener already attached");
            await setItemInLocal("blocking_enabled", true);
            return;
        }

        browser.webRequest.onBeforeRequest.addListener(
            cancel,
            { urls: ["<all_urls>"] },
            ["blocking"]
        );

        console.log("Attached `onBeforeRequest` listener successfully: blocking enabled");
        await setItemInLocal("blocking_enabled", true);
    } catch (e) {
        console.error("START() ", e);
    }
}

async function stop() {
    try {
        if (browser.webRequest.onBeforeRequest.hasListener(cancel)) {
            browser.webRequest.onBeforeRequest.removeListener(cancel);
            console.log("Removed `onBeforeRequest` listener successfully: blocking disabled");
        }
        await setItemInLocal("blocking_enabled", false);
    } catch (e) {
        console.error("STOP() ", e);
    }
}

function handleUpdated(tabId, changeInfo, tabInfo) {
    if (!changeInfo.url) return;

    const badge = getBadgeForTab(tabId);
    if (!badge) return;

    if (badge.lastURL !== changeInfo.url) {
        resetTabDataForNavigation(tabId, tabInfo.url);
    }
}

function handleRemoved(tabId) {
    selectiveAllow.clearPendingByUiTabId(tabId);
    clearTabActivityData(tabId);
}

function handleWindowRemoved(windowId) {
    selectiveAllow.clearPendingByWindowId(windowId);
}

/**
 * @param {number|undefined} tabId
 * @param {string} url
 */
async function navigateAllowedUrl(tabId, url) {
    if (Number.isInteger(tabId) && tabId >= 0) {
        try {
            await browser.tabs.update(tabId, { url, active: true });
            return;
        } catch (error) {
            console.warn("Selective allow could not update tab; opening a new one:", {
                tabId,
                error,
            });
        }
    }
    await browser.tabs.create({ url });
}

/** Parse JSON-stringified storage.onChanged values. */
function parseStorageChangeValue(raw) {
    if (raw === undefined) return undefined;
    try {
        return JSON.parse(raw);
    } catch {
        return undefined;
    }
}

/**
 * Settings removals must drop any leftover session allows for the same pair
 * (defense in depth if a pair was also Allow Once'd earlier in the session).
 */
function syncSessionAllowsWithCrossOriginChange(change) {
    if (!change) return;
    const oldList = parseStorageChangeValue(change.oldValue);
    const newList = parseStorageChangeValue(change.newValue);
    if (!Array.isArray(oldList)) return;
    const next = Array.isArray(newList) ? newList : [];
    for (const entry of oldList) {
        if (
            entry?.origin &&
            entry?.destination &&
            !listHasCrossOriginEntry(next, entry.origin, entry.destination)
        ) {
            selectiveAllow.revokeSessionAllow(entry.origin, entry.destination);
        }
    }
}

const extensionOrigin = new URL(browser.runtime.getURL("")).origin;
async function onMessage(message, sender) {
    if (sender.origin !== extensionOrigin) {
        console.warn("Message from unexpected origin:", sender.url);
        return;
    }

    switch (message.type) {
        case "toggleEnabled":
            message.value ? await start() : await stop();
            break;
        case "getTabActivity":
            return getTabActivityForTab(message.tabId);
        case "selectiveAllowDismiss": {
            if (typeof message.promptId === "string") {
                selectiveAllow.clearPendingByPromptId(message.promptId);
            }
            break;
        }
        case "allowOnce":
        case "alwaysAllow": {
            const pending = selectiveAllow.getPendingByPromptId(message.promptId);
            if (!pending) {
                console.warn("Rejected selective allow decision: unknown or expired prompt", message);
                return;
            }

            const validated = validatePendingAllow(pending);
            if (!validated.ok) {
                console.warn("Rejected selective allow decision:", validated.reason, message);
                selectiveAllow.clearPendingByPromptId(pending.promptId);
                return;
            }

            const { origin, destination, originalUrl, tabId } = validated;
            selectiveAllow.clearPendingByPromptId(pending.promptId);

            if (message.type === "allowOnce") {
                selectiveAllow.allowInSession(origin, destination);
            } else {
                // Always Allow is storage-only so settings removal takes effect immediately.
                await modifyItemInLocal(CROSS_ORIGIN_ALLOWLIST_KEY, [], (list) => {
                    if (listHasCrossOriginEntry(list, origin, destination)) {
                        return list;
                    }
                    return list.concat([{ origin, destination }]);
                });
            }

            await navigateAllowedUrl(tabId, originalUrl);
            break;
        }
        default:
            console.warn("Port Authority: unknown message: ", message);
            break;
    }
}
browser.runtime.onMessage.addListener(onMessage);

browser.storage.onChanged.addListener((changes, areaName) => {
    if (areaName !== "local") return;
    applyStorageChangesToCaches(changes);
    if (Object.prototype.hasOwnProperty.call(changes, CROSS_ORIGIN_ALLOWLIST_KEY)) {
        syncSessionAllowsWithCrossOriginChange(changes[CROSS_ORIGIN_ALLOWLIST_KEY]);
    }
});

startup();
browser.tabs.onUpdated.addListener(handleUpdated);
browser.tabs.onRemoved.addListener(handleRemoved);
browser.windows.onRemoved.addListener(handleWindowRemoved);
