import {
    getItemFromLocal,
    setItemInLocal,
    addBlockedPortToHost,
    addBlockedTrackingHost,
    increaseBadge,
    getAllowedDomainListCached,
    applyStorageChangesToCaches,
    resetSessionTabActivity,
    clearTabActivityData,
    resetTabDataForNavigation,
    peekBadgeForTab,
    flushTabActivity,
} from "./global/BrowserStorageManager.js";
import { getTabActivitySnapshot } from "./global/tabActivity.js";
import { evaluateRequest, createDnsResultCache } from "./global/requestFilter.js";

/** Session-scoped DNS result cache — not persisted to disk. */
const dnsResultCache = createDnsResultCache();

async function startup() {
    // No need to check and initialize notification, state, and allow list values as they will
    // fall back to the default values until explicitly set
    console.log("Startup called");

    // Drop stale/corrupt per-tab activity left from prior sessions (issue #52).
    // Popup data is session-scoped in practice; tabs reload and repopulate anyway.
    await resetSessionTabActivity();

    // Warm the allowlist cache so the first requests avoid a storage round-trip.
    await getAllowedDomainListCached();

    // Get the blocking state from cold storage
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
        return blockPortScan(requestDetails, decision.url);
    }

    if (decision.reason === "threatmetrix") {
        increaseBadge(requestDetails, true);
        addBlockedTrackingHost(decision.url, requestDetails.tabId);
        return { cancel: true };
    }

    return { cancel: false };
} // end cancel()

async function start() {
    // Enables blocking
    try {
        if (browser.webRequest.onBeforeRequest.hasListener(cancel)) {
            console.log("Blocking listener already attached");
            await setItemInLocal("blocking_enabled", true);
            return;
        }

        browser.webRequest.onBeforeRequest.addListener(
            cancel,
            { urls: ["<all_urls>"] }, // Match all HTTP, HTTPS, FTP, FTPS, WS, WSS URLs.
            ["blocking"] // if cancel() returns true block the request.
        );

        console.log("Attached `onBeforeRequest` listener successfully: blocking enabled");
        await setItemInLocal("blocking_enabled", true);
    } catch (e) {
        console.error("START() ", e);
    }
}

async function stop() {
    // Disables blocking
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
 * Called when each tab is updated, and if the URL has changed.
 * Borrowed and modified from https://gitlab.com/KevinRoebert/ClearUrls/-/blob/master/core_js/badgedHandler.js
 */
function handleUpdated(tabId, changeInfo, tabInfo) {
    if (!changeInfo.url) return;

    const badge = peekBadgeForTab(tabId);
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

const extensionOrigin = new URL(browser.runtime.getURL("")).origin;
async function onMessage(message, sender) {
    // Add origin check for security (preemptively accepting messages from any extension page/script in advance of potential `settings.js` rewrite)
    /* TODO Potentially remove, pretty sure this isn't needed:
       https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/runtime/onMessage#:~:text=from%20another%20part%20of%20your%20extension
       https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/runtime/onMessageExternal
    */
    if (sender.origin !== extensionOrigin) {
        console.warn("Message from unexpected origin:", sender.url);
        return;
    }

    switch (message.type) {
        case "toggleEnabled":
            message.value ? await start() : await stop();
            break;
        case "getTabActivity": {
            // Popup reads live memory (then storage is only a durability backup).
            await flushTabActivity();
            const snapshot = getTabActivitySnapshot();
            const tabId = message.tabId;
            return {
                blocked_ports: snapshot.blocked_ports[tabId] ?? snapshot.blocked_ports[String(tabId)] ?? {},
                blocked_hosts: snapshot.blocked_hosts[tabId] ?? snapshot.blocked_hosts[String(tabId)] ?? [],
            };
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
