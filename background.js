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

/** Session allow + pending-prompt tracking for cross-origin local navigations. */
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

/**
 * Open the decision UI outside the blocking webRequest stack and bind its
 * window/tab id so chrome-close clears pending. Notification failures must
 * not clear pending after a successful open.
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
                    pending.navigationTabId,
                    pending.promptId
                );
            } catch (error) {
                console.error("Failed to open selective allow prompt:", error);
                selectiveAllow.clearPendingByPromptId(pending.promptId);
                return;
            }

            if (!opened) {
                selectiveAllow.clearPendingByPromptId(pending.promptId);
                return;
            }

            selectiveAllow.bindPromptUi(pending.promptId, opened);

            try {
                await notifySelectiveAllow(pending.origin, pending.destination);
            } catch (error) {
                // Prompt UI is already open — do not clear pending on notify failure.
                console.warn("Selective allow notification failed:", error);
            }
        })();
    }, 0);
}

/**
 * Top-level navigations to literal local addresses get a Selective Allow prompt
 * instead of a silent block. Subresource port scans still use blockPortScan().
 * Prompting is skipped while a popup for the same origin→destination is open.
 */
async function handleSelectiveAllowNavigation(requestDetails, url) {
    let originUrl;
    try {
        originUrl = new URL(requestDetails.originUrl);
    } catch {
        // Without a parseable origin we cannot key a permission — fall back.
        return blockPortScan(requestDetails, url);
    }

    const origin = originAllowKey(originUrl);
    const destination = url.host;
    if (!destination) {
        return blockPortScan(requestDetails, url);
    }

    if (selectiveAllow.isSessionAllowed(origin, destination)) {
        return { cancel: false };
    }

    const crossOriginList = await getItemFromLocal(CROSS_ORIGIN_ALLOWLIST_KEY, []);
    if (listHasCrossOriginEntry(crossOriginList, origin, destination)) {
        return { cancel: false };
    }

    // Dedupe: do not open another popup for the same pair while one is pending.
    // Still cancel the navigation so the local target is not reached.
    if (!selectiveAllow.hasPendingPrompt(origin, destination)) {
        const pending = selectiveAllow.createPendingPrompt({
            origin,
            destination,
            originalUrl: requestDetails.url,
            navigationTabId: requestDetails.tabId,
        });
        scheduleSelectiveAllowPrompt(pending);
    }

    // Cancel without badge noise — the user gets an explicit prompt instead.
    return { cancel: true };
}

async function cancel(requestDetails) {
    const decision = await evaluateRequest(requestDetails, {
        getAllowedDomains: () => getAllowedDomainListCached(),
        resolveDns: (hostname) => browser.dns.resolve(hostname, ["canonical_name"]),
        dnsCache: dnsResultCache,
    });

    if (!decision.cancel) {
        // Avoid per-request console I/O on the hot allow path — logging every
        // first-party asset on SPAs (Figma, etc.) retains huge console buffers.
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
        // Only literal local main_frame navigations are prompted. DNS-rebinding
        // portscans (and all subresources) stay on the silent block path.
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

/**
 * Reset per-tab activity when the tab navigates to a new URL.
 * Borrowed and modified from https://gitlab.com/KevinRoebert/ClearUrls/-/blob/master/core_js/badgedHandler.js
 */
function handleUpdated(tabId, changeInfo, tabInfo) {
    if (!changeInfo.url) return;

    const badge = getBadgeForTab(tabId);
    if (!badge) return;

    if (badge.lastURL !== changeInfo.url) {
        resetTabDataForNavigation(tabId, tabInfo.url);
    }
}

/**
 * Closed tabs must drop their activity maps — otherwise badges/blocked_* grow
 * without bound across a long browsing session (issue #52 / #47).
 * Also clear Selective Allow pending when the decision UI tab is closed.
 */
function handleRemoved(tabId) {
    selectiveAllow.clearPendingByUiTabId(tabId);
    clearTabActivityData(tabId);
}

function handleWindowRemoved(windowId) {
    selectiveAllow.clearPendingByWindowId(windowId);
}

/**
 * Navigate the cancelled tab when possible; otherwise open a new tab.
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

const extensionOrigin = new URL(browser.runtime.getURL("")).origin;
async function onMessage(message, sender) {
    // Defense in depth: runtime.onMessage is extension-internal, but reject unexpected origins.
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

            const validated = validatePendingAllow(pending, message.tabId);
            if (!validated.ok) {
                console.warn("Rejected selective allow decision:", validated.reason, message);
                // Invalid pending should not keep the pair locked from re-prompting.
                selectiveAllow.clearPendingByPromptId(pending.promptId);
                return;
            }

            const { origin, destination, originalUrl, tabId } = validated;
            selectiveAllow.allowInSession(origin, destination);
            selectiveAllow.clearPendingByPromptId(pending.promptId);

            if (message.type === "alwaysAllow") {
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
});

startup();
browser.tabs.onUpdated.addListener(handleUpdated);
browser.tabs.onRemoved.addListener(handleRemoved);
browser.windows.onRemoved.addListener(handleWindowRemoved);
