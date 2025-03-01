import { getItemFromLocal, setItemInLocal, modifyItemInLocal,
    addBlockedPortToHost, addBlockedTrackingHost, increaseBadge } from "./BrowserStorageManager.js";

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

async function cancel(requestDetails) {
    // First check the whitelist
    let check_allowed_url;
    try {
        check_allowed_url = new URL(requestDetails.originUrl);
    } catch {
        console.error("Aborted filtering on domain due to unparseable domain: ", requestDetails.originUrl);
        return { cancel: false }; // invalid origin
    }

    const allowed_domains_list = await getItemFromLocal("allowed_domain_list", []);
    // Perform an exact match against the whitelisted domains (dont assume subdomains are allowed)
    const domainIsWhiteListed = allowed_domains_list.some(
        (domain) => check_allowed_url.host === domain
    );
    if (domainIsWhiteListed){
        console.debug("Aborted filtering on domain due to whitelist: ", check_allowed_url);
        return { cancel: false };
    }

    // This regex is explained here https://regex101.com/r/LSL180/1 below I needed to change \b -> \\b
    let local_filter = new RegExp("\\b(^(http|https|wss|ws|ftp|ftps):\/\/127[.](?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[.](?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[.](?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|^(http|https|wss|ws|ftp|ftps):\/\/0.0.0.0|^(http|https|wss|ws|ftp|ftps):\/\/(10)([.](25[0-5]|2[0-4][0-9]|1[0-9]{1,2}|[0-9]{1,2})){3}|^(http|https|wss|ws|ftp|ftps):\/\/localhost|^(http|https|wss|ws|ftp|ftps):\/\/172[.](0?16|0?17|0?18|0?19|0?20|0?21|0?22|0?23|0?24|0?25|0?26|0?27|0?28|0?29|0?30|0?31)[.](?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[.](?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|^(http|https|wss|ws|ftp|ftps):\/\/192[.]168[.](?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[.](?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|^(http|https|wss|ws|ftp|ftps):\/\/169[.]254[.](?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[.](?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))(?:\/([789]|1?[0-9]{2}))?\\b", "i");
    // Create a regex to find all sub-domains for online-metrix.net  Explained here https://regex101.com/r/f8LSTx/2
    let thm = new RegExp("online-metrix[.]net$", "i");

    // This reduces having to check this conditional multiple times
    let is_requested_local = local_filter.test(requestDetails.url);
    // Make sure we are not searching the CNAME of local addresses
    if (!is_requested_local) {
        let url = new URL(requestDetails.url);
        // Send a request to get the CNAME of the webrequest
        let resolving = await browser.dns.resolve(url.host, ["canonical_name"]);
        // If the CNAME redirects to a online-metrix.net domain -> Block
        if (thm.test(resolving.canonicalName)) {
            console.debug("Blocking domain for being a threatmetrix match: ", {url: url, cname: resolving.canonicalName});
            increaseBadge(requestDetails, true); // increment badge and alert
            addBlockedTrackingHost(url, requestDetails.tabId);
            return { cancel: true };
        }
    }

    // Check if the network request is going to a local address
    if (is_requested_local) {
        // If URL in the address bar is a local address dont block the request
        if (!local_filter.test(requestDetails.originUrl)) {
            let url = new URL(requestDetails.url);
            console.debug("Blocking domain for portscanning: ", url);
            increaseBadge(requestDetails, false); // increment badge and alert
            addBlockedPortToHost(url, requestDetails.tabId);
            return { cancel: true };
        }
    }
    // Dont block sites that don't alert the detection
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

async function onMessage(message, sender) {
  // Add origin check for security
  const extensionOrigin = new URL(browser.runtime.getURL("")).origin;
  if (sender.url !== `${extensionOrigin}/popup/popup.html`) {
    console.warn('Message from unexpected origin:', sender.url);
    return;
  }

  switch(message.type) {
    case 'popupInit':
      return {
        isListening: await isListening(),
        notificationsAllowed: await getItemFromLocal("notificationsAllowed", true),
      };
    case 'toggleEnabled':
      message.value ? await start() : await stop();
      break;
    case 'setItemInLocal':
      await setItemInLocal(message.key, message.value);
      break;
    case 'setNotificationsAllowed':
      await setItemInLocal("notificationsAllowed", message.value);
      break;
    case 'getItemInLocal':
      return await getItemFromLocal(message.key, message.defaultValue);
    default:
      console.warn('Port Authority: unknown message: ', message);
      break;
  }
}
browser.runtime.onMessage.addListener(onMessage);

startup();
// Call by each tab is updated.
browser.tabs.onUpdated.addListener(handleUpdated);
