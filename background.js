import { getItemFromLocal, setItemInLocal, modifyItemInLocal,
    addBlockedPortToHost, addBlockedTrackingHost, increaseBadge } from "./global/BrowserStorageManager.js";
import { evaluateRequest, createDnsResultCache } from "./global/requestFilter.js";

/** Session-scoped DNS result cache — not persisted to disk. */
const dnsResultCache = createDnsResultCache();

async function startup(){
    // No need to check and initialize notification, state, and allow list values as they will 
    // fall back to the default values until explicitly set
    console.log("Startup called");

	// Get the blocking state from cold storage
    const state = await getItemFromLocal("blocking_enabled", true); 
	if (state === true) {
	    start();
	} else {
	    stop();
	}
}

function blockPortScan(requestDetails, url) {
    increaseBadge(requestDetails, false);
    addBlockedPortToHost(url, requestDetails.tabId);
    return { cancel: true };
}

async function cancel(requestDetails) {
    const decision = await evaluateRequest(requestDetails, {
        getAllowedDomains: () => getItemFromLocal("allowed_domain_list", []),
        resolveDns: (hostname) => browser.dns.resolve(hostname, ["canonical_name"]),
        dnsCache: dnsResultCache,
    });

    if (!decision.cancel) {
        if (decision.reason === "first-party") {
            console.debug("Same-origin/first-party request allowed:", {
                origin: requestDetails.originUrl,
                request: requestDetails.url,
            });
        } else if (decision.reason === "unparseable-origin") {
            console.error("Aborted filtering on domain due to unparseable originUrl: ", requestDetails.originUrl);
        } else if (decision.reason === "allowlisted") {
            console.debug("Aborted filtering on domain due to whitelist: ", requestDetails.originUrl);
        } else if (decision.reason === "unparseable-url") {
            console.error("Error filtering on domain due to unparseable request URL: ", requestDetails.url);
        } else if (decision.reason === "dns-failure") {
            console.warn("DNS resolution failed for request:", requestDetails.url);
        }
        return { cancel: false };
    }

    if (decision.reason === "portscan") {
        console.debug("Blocking domain for portscanning: ", decision.url);
        return blockPortScan(requestDetails, decision.url);
    }

    if (decision.reason === "threatmetrix") {
        console.debug("Blocking domain for LexisNexis/ThreatMetrix match:", { url: decision.url });
        increaseBadge(requestDetails, true);
        addBlockedTrackingHost(decision.url, requestDetails.tabId);
        return { cancel: true };
    }

    return { cancel: false };
} // end cancel()

async function start() {  // Enables blocking
    try {
        //Add event listener
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

async function stop() {  // Disables blocking
    try {
        //Remove event listener
        browser.webRequest.onBeforeRequest.removeListener(cancel);

        console.log("Removed `onBeforeRequest` listener successfully: blocking disabled");
        await setItemInLocal("blocking_enabled", false);
    } catch (e) {
        console.error("STOP() ", e);
    }
}

async function isListening() { // returns if blocking is on
    const storage_state = await getItemFromLocal("blocking_enabled", true);
    const listener_attached_state = browser.webRequest.onBeforeRequest.hasListener(cancel);

    // If storage says that blocking is enabled when it actually isn't, soft throw an error to the console
    if (storage_state !== listener_attached_state) {
        console.error("Mismatch in blocking state according to storage value and listener attached status:", {
            storage_state,
            listener_attached_state
        });
    }

    // Rely on the actual listener being attached as the ground source of truth over what storage says
    return listener_attached_state;
}

/**
 * Call by each tab is updated.
 * And if url has changed.
 * Borrowed and modified from https://gitlab.com/KevinRoebert/ClearUrls/-/blob/master/core_js/badgedHandler.js
 */
async function handleUpdated(tabId, changeInfo, tabInfo) {
    // TODO investigate a better way to interact with current locking practices
    const badges = await getItemFromLocal("badges", {});
    if (!badges[tabId] || !changeInfo.url) return;

    if (badges[tabId].lastURL !== changeInfo.url) {
        badges[tabId] = {
            counter: 0,
            alerted: 0,
            lastURL: tabInfo.url
        };
        await setItemInLocal("badges", badges);

        // Clear out the blocked ports for the current tab
        await modifyItemInLocal("blocked_ports", {},
            (blocked_ports_object) => {
                delete blocked_ports_object[tabId];
                return blocked_ports_object;
            });

        // Clear out the hosts for the current tab
        await modifyItemInLocal("blocked_hosts", {},
            (blocked_hosts_object) => {
                delete blocked_hosts_object[tabId];
                return blocked_hosts_object;
            });
    }
}

const extensionOrigin = new URL(browser.runtime.getURL("")).origin;
async function onMessage(message, sender) {
    // Add origin check for security (preemptively accepting messages from any extension page/script in advance of potential `settings.js` rewrite)
    /* TODO Potentially remove, pretty sure this isn't needed:
       https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/runtime/onMessage#:~:text=from%20another%20part%20of%20your%20extension
       https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/runtime/onMessageExternal
    */
    if (sender.origin !== extensionOrigin) {
        console.warn('Message from unexpected origin:', sender.url);
        return;
    }

    switch (message.type) {
        case 'toggleEnabled':
            message.value ? await start() : await stop();
            break;
        default:
            console.warn('Port Authority: unknown message: ', message);
            break;
    }
}
browser.runtime.onMessage.addListener(onMessage);

startup();
// Call by each tab is updated.
browser.tabs.onUpdated.addListener(handleUpdated);
