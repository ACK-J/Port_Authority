async function startup(){
    // No need to check and initialize notification, state, and allow list values as they will 
    // fall back to the default values until explicitly set

	// Get the blocking state
	const state = await getItemFromLocal("state", true); 
	if (state === true) {
	    start();
	} else {
	    stop();
	}
}

async function notifyPortScanning(domain_name) {
    if (domain_name){
        browser.notifications.create("port-scanning-notification", {
            "type": "basic",
            "iconUrl": browser.runtime.getURL("icons/logo-96.png"),
            "title": "Port Scan Blocked",
            "message": "Port Authority blocked " + domain_name + " from port scanning your private network."
        });
    } else {
        browser.notifications.create("port-scanning-notification", {
            "type": "basic",
            "iconUrl": browser.runtime.getURL("icons/logo-96.png"),
            "title": "Port Scan Blocked",
            "message": "Port Authority blocked this site from port scanning your private network."
        });
    }
}

async function notifyThreatMetrix(domain_name) {
    if (domain_name) {
        browser.notifications.create("threatmetrix-notification", {
            "type": "basic",
            "iconUrl": browser.runtime.getURL("icons/logo-96.png"),
            "title": "Tracking Script Blocked",
            "message": "Port Authority blocked a hidden LexisNexis endpoint on " + domain_name + " from running an invasive data collection script."
        });
    } else {
        browser.notifications.create("threatmetrix-notification", {
            "type": "basic",
            "iconUrl": browser.runtime.getURL("icons/logo-96.png"),
            "title": "Tracking Script Blocked",
            "message": "Port Authority blocked a hidden LexisNexis endpoint from running an invasive data collection script."
        });
    }
}

/**
 * Adds the host and port of the provided url to a list of hosts and ports that were blocked from port scanning.
 * 
 * @param {string} tabId Id the of the browser tab the port check was executed in
 * @param {URL} url URL object built from the url of the tab associated with the tabID
 */
const addBlockedPortToHost = async (url, tabIdString) => {
    const tabId = parseInt(tabIdString);
    const host = url.host.split(":")[0];
    const port = "" + (url.port || getPortForProtocol(url.protocol));

    // Grab the blocked ports object from extensions storage
    const blocked_ports = await getItemFromLocal("blocked_ports", {});

    // Grab the array of ports blocked for the host url
    const tab_hosts = blocked_ports[tabId] || {};
    let hosts_ports = tab_hosts[host];
    if (Array.isArray(hosts_ports)) {
        // Add the port to the array of blocked ports for this host IFF the port doesn't exist
        if (hosts_ports.indexOf(port) === -1) {
            hosts_ports = tab_hosts[host].concat([port]);
            tab_hosts[host] = hosts_ports;
            blocked_ports[tabId] = tab_hosts;
            await setItemInLocal("blocked_ports", blocked_ports);
        }

    } else {
        tab_hosts[host] = [port];
        blocked_ports[tabId] = tab_hosts;
        await setItemInLocal("blocked_ports", blocked_ports);
    }
}

/**
 * Adds the host and port of the provided url to a list of hosts and ports that were blocked from port scanning.
 * 
 * @param {string} tabId Id the of the browser tab the port check was executed in
 * @param {URL} url URL object built from the url of the tab associated with the tabID
 */
async function addBlockedTrackingHost(url, tabIdString) {
    const tabId = parseInt(tabIdString);
    const host = url.host;

    const blocked_hosts_tabs = await getItemFromLocal("blocked_hosts", {});

    let blocked_hosts = blocked_hosts_tabs[tabId] || [];

    if (blocked_hosts.indexOf(host) === -1) {
        blocked_hosts = blocked_hosts.concat([host]);
    }

    blocked_hosts_tabs[tabId] = blocked_hosts;
    
    await setItemInLocal("blocked_hosts", blocked_hosts_tabs);
}

async function cancel(requestDetails) {
    // First check the whitelist
    let check_allowed_url;
    try {
        check_allowed_url = new URL(requestDetails.originUrl);
    } catch {
        return { cancel: false }; // invalid origin
    }

    const allowed_domains_list = await getItemFromLocal("allowed_domain_list", []);
    // Perform an exact match against the whitelisted domains (dont assume subdomains are allowed)
    const domainIsWhiteListed = allowed_domains_list.some(
        (domain) => check_allowed_url.host === domain
    );
    if (domainIsWhiteListed){
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
            await increaseBadge(requestDetails, true); // increment badge and alert
            await addBlockedTrackingHost(url, requestDetails.tabId);
            return { cancel: true };
        }
    }

    // Check if the network request is going to a local address
    if (is_requested_local) {
        // If URL in the address bar is a local address dont block the request
        if (!local_filter.test(requestDetails.originUrl)) {
            let url = new URL(requestDetails.url);
            await increaseBadge(requestDetails, false); // increment badge and alert
            await addBlockedPortToHost(url, requestDetails.tabId);
            return { cancel: true };
        }
    }
    // Dont block sites that don't alert the detection
    return { cancel: false };
} // end cancel()


async function start() {  // Enables blocking
    try {
        await setItemInLocal("state", true); // Define the blocking state value
        //Add event listener
        browser.webRequest.onBeforeRequest.addListener(
            cancel,
            { urls: ["<all_urls>"] }, // Match all HTTP, HTTPS, FTP, FTPS, WS, WSS URLs.
            ["blocking"] // if cancel() returns true block the request.
        );
    } catch (e) {
        console.log("START() ", e);
    }

}

async function stop() {  // Disables blocking
    try {
        await setItemInLocal("state", false); // Define the blocking state value
        //Remove event listener
        browser.webRequest.onBeforeRequest.removeListener(cancel);
    } catch (e) {
        console.log("STOP() ", e);
    }

}

function isListening() { // returns if blocking is on
    return browser.webRequest.onBeforeRequest.hasListener(cancel);
}

/**
 * Increases the badged by one.
 * Borrowed and modified from https://gitlab.com/KevinRoebert/ClearUrls/-/blob/master/core_js/badgedHandler.js
 */
async function increaseBadge(request, isThreatMetrix) {
    // Error check
    if (request === null) return;

    const tabId = request.tabId;
    const url = request.url;
    const badges = await getItemFromLocal("badges", {});

    if (tabId === -1) return;

    if (badges[tabId] == null) {
        badges[tabId] = {
            counter: 1,
            alerted: 0,
            lastURL: url
        };
    } else {
        badges[tabId].counter += 1;
    }
    // Update badge text
    browser.browserAction.setBadgeText({ 
        text: (badges[tabId]).counter.toString(), 
        tabId: tabId 
    }).catch();

    // Update notification alerted status
    if (badges[tabId].alerted === 0 && await getItemFromLocal("notificationsAllowed", true)) {
        badges[tabId].alerted += 1;
        if (isThreatMetrix){
            notifyThreatMetrix(new URL(request.originUrl).host);
        } else {
            notifyPortScanning(new URL(request.originUrl).host);
        }
    }

    await setItemInLocal("badges", badges);
}

/**
 * Call by each tab is updated.
 * And if url has changed.
 * Borrowed and modified from https://gitlab.com/KevinRoebert/ClearUrls/-/blob/master/core_js/badgedHandler.js
 */
async function handleUpdated(tabId, changeInfo, tabInfo) {
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
	const blocked_ports_object = await getItemFromLocal("blocked_ports", {});
	delete blocked_ports_object[tabId];
	await setItemInLocal("blocked_ports", blocked_ports_object);
        
	// Clear out the hosts for the current tab
	const blocked_hosts_object = await getItemFromLocal("blocked_hosts", {});
	delete blocked_hosts_object[tabId];
	await setItemInLocal("blocked_hosts", blocked_hosts_object);
    }
}

async function onMessage(message, sender) {
  // Add origin check for security
  const extensionOrigin = new URL(browser.runtime.getURL("")).origin;
  console.log('onmessage', message, sender, extensionOrigin)
  if (sender.url !== `${extensionOrigin}/popup/popup.html`) {
    console.warn('Message from unexpected origin:', sender.url);
    return;
  }

  const notificationsAllowed = await getItemFromLocal("notificationsAllowed", true);
  switch(message.type) {
    case 'popupInit':
      const state = await getItemFromLocal("state", true);
      return {
        isListening: state,
        notificationsAllowed,
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