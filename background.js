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
import { openSelectiveAllowPopup } from "./global/browserActions.js";
import { isLocalRequestUrl } from "./global/privateAddress.js";
import {
    CROSS_ORIGIN_ALLOWLIST_KEY,
    createSelectiveAllowState,
    listHasCrossOriginEntry,
    validateAllowDecision,
} from "./global/selectiveAllow.js";

/** Session-scoped DNS result cache — not persisted to disk. */
const dnsResultCache = createDnsResultCache();

/** Session allow + pending-prompt dedupe for cross-origin local navigations. */
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
 * Top-level navigations to literal local addresses get a Selective Allow prompt
 * instead of a silent block. Subresource port scans still use blockPortScan().
 * Prompting is skipped while a popup for the same origin→destination is open.
 */
async function handleSelectiveAllowNavigation(requestDetails, url) {
    let originHost;
    try {
        originHost = new URL(requestDetails.originUrl).host;
    } catch {
        // Without a parseable origin we cannot key a permission — fall back.
        return blockPortScan(requestDetails, url);
    }

    const destination = url.host;
    if (selectiveAllow.isSessionAllowed(originHost, destination)) {
        return { cancel: false };
    }

    const crossOriginList = await getItemFromLocal(CROSS_ORIGIN_ALLOWLIST_KEY, []);
    if (listHasCrossOriginEntry(crossOriginList, originHost, destination)) {
        return { cancel: false };
    }

    // Dedupe: do not open another popup for the same pair while one is pending.
    // Still cancel the navigation so the local target is not reached.
    if (!selectiveAllow.hasPendingPrompt(originHost, destination)) {
        selectiveAllow.markPendingPrompt(originHost, destination);
        openSelectiveAllowPopup(
            originHost,
            destination,
            requestDetails.url,
            requestDetails.tabId
        ).catch((error) => {
            console.error("Failed to open selective allow popup:", error);
            selectiveAllow.clearPendingPrompt(originHost, destination);
        });
    }

    // Cancel without badge noise — the user already sees an explicit prompt.
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
 */
function handleRemoved(tabId) {
    clearTabActivityData(tabId);
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
            if (typeof message.origin === "string" && typeof message.destination === "string") {
                selectiveAllow.clearPendingPrompt(message.origin, message.destination);
            }
            break;
        }
        case "allowOnce":
        case "alwaysAllow": {
            const validated = validateAllowDecision(message);
            if (!validated.ok) {
                console.warn("Rejected selective allow decision:", validated.reason, message);
                return;
            }

            const { origin, destination, originalUrl, tabId } = validated;
            selectiveAllow.allowInSession(origin, destination);
            selectiveAllow.clearPendingPrompt(origin, destination);

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
