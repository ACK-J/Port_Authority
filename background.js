let badges = {};
var notificationsAllowed = true;

function notifyPortScanning() {
    browser.notifications.create("port-scanning-notification", {
        "type": "basic",
        "iconUrl": browser.runtime.getURL("icons/logo-96.png"),
        "title": "This site attempted to port scan you!",
        "message": "Port Authority has blocked this site from bypassing security measures and port scanning your private network."
    });
}

function notifyThreatMetrix() {
    browser.notifications.create("threatmetrix-notification", {
        "type": "basic",
        "iconUrl": browser.runtime.getURL("icons/logo-96.png"),
        "title": "This site attempted to track you!",
        "message": "Port Authority dynamically blocked a hidden LexisNexis endpoint from running an invasive data collection script."
    });
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
    const port = url.port || getPortForProtocol(url.protocol);

    // Grab the blocked ports object from extensions storage
    const blocked_ports_object = await getItemFromLocal("blocked_ports", {});
    // Extension storage returns {blocked_ports: data} because..... I actually don't know why
    const blocked_ports_string = blocked_ports_object.blocked_ports;

    let blocked_ports;
    try {
        blocked_ports = JSON.parse(blocked_ports_string)
    } catch {
        blocked_ports = {}
    }

    // Grab the array of ports blocked for the host url
    const tab_hosts = blocked_ports[tabId] || {};
    const hosts_ports = tab_hosts[host];
    if (Array.isArray(hosts_ports)) {
        // Add the port to the array of blocked ports for this host IFF the port doesn't exist
        if (hosts_ports.indexOf(port) === -1) {
            const hosts_ports = tab_hosts[host].concat([port])
            tab_hosts[host] = hosts_ports
        }

    } else {
        tab_hosts[host] = [port];
    }

    blocked_ports[tabId] = tab_hosts;

    await setItemInLocal("blocked_ports", blocked_ports);
    return;
}

/**
 * Adds the host and port of the provided url to a list of hosts and ports that were blocked from port scanning.
 * 
 * @param {string} tabId Id the of the browser tab the port check was executed in
 * @param {URL} url URL object built from the url of the tab associated with the tabID
 */
const addBlockedTrackingHost = async (url, tabIdString) => {
    const tabId = parseInt(tabIdString);
    const host = url.host;

    const blocked_hosts_object = await getItemFromLocal("blocked_hosts", []);
    const blocked_hosts_string = blocked_hosts_object.blocked_hosts;

    let blocked_hosts_tabs;
    try {
        blocked_hosts_tabs = JSON.parse(blocked_hosts_string)
    } catch {
        blocked_hosts_tabs = {}
    }

    let blocked_hosts = blocked_hosts_tabs[tabId] || [];

    if (blocked_hosts.indexOf(host) === -1) {
        blocked_hosts = blocked_hosts.concat([host]);
    }

    blocked_hosts_tabs[tabId] = blocked_hosts;
    

    await setItemInLocal("blocked_hosts", blocked_hosts_tabs);
    return;
}

async function cancel(requestDetails) {
    // This regex is explained here https://regex101.com/r/DOPCdB/16/ below I needed to change \b -> \\b
    let local_filter = new RegExp("\\b(^(http|https|wss|ws|ftp|ftps):\/\/127[.](?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[.](?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[.](?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|^(http|https|wss|ws|ftp|ftps):\/\/(10)([.](25[0-5]|2[0-4][0-9]|1[0-9]{1,2}|[0-9]{1,2})){3}|^(http|https|wss|ws|ftp|ftps):\/\/localhost|^(http|https|wss|ws|ftp|ftps):\/\/172[.](0?16|0?17|0?18|0?19|0?20|0?21|0?22|0?23|0?24|0?25|0?26|0?27|0?28|0?29|0?30|0?31)[.](?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[.](?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|^(http|https|wss|ws|ftp|ftps):\/\/192[.]168[.](?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[.](?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|^(http|https|wss|ws|ftp|ftps):\/\/169[.]254[.](?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[.](?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|^(http|https|wss|ws|ftp|ftps):\/\/\[?::1|^(http|https|wss|ws|ftp|ftps):\/\/\[?[fF][cCdD][0-9a-fA-F]{2}(?:[:][0-9a-fA-F]{0,4}){0,7}|^(http|https|wss|ws|ftp|ftps):\/\/\[?[fF][eE][89aAbB][0-9a-fA-F](?:[:][0-9a-fA-F]{0,4}){0,7})(?:\/([789]|1?[0-9]{2}))?\\b\]?", "i");
    // Create a regex to find all sub-domains for online-metrix.net  Explained here https://regex101.com/r/f8LSTx/2
    let thm = new RegExp("online-metrix[.]net$", "i");

    // This reduces having to check this conditional multiple times
    let is_requested_local = requestDetails.url.search(local_filter);

    // Make sure we are not searching the CNAME of local addresses
    if (is_requested_local !== 0) {
        // Parse the URL
        let url = new URL(requestDetails.url);
        // Send a request to get the CNAME of the webrequest
        let resolving = await browser.dns.resolve(url.host, ["canonical_name"]);
        // If the CNAME redirects to a online-metrix.net domain -> Block
        if (resolving.canonicalName.search(thm) !== -1) {
            let tabId = requestDetails.tabId;
            increaseBadged(requestDetails);
            await addBlockedTrackingHost(url, tabId);
            if (badges[tabId].alerted == 0 && notificationsAllowed) {
                notifyThreatMetrix();
                badges[tabId].alerted += 1;
            }
            return { cancel: true };
        }
    }

    // Check if the network request is going to a local address
    // search should return a 0 for the 0th index of the string
    // if a match is further down the URL, it is probably a FP
    if (is_requested_local === 0) {
        // Check if the current website visited is a local address
        if (requestDetails.originUrl.search(local_filter) !== 0) {

            // Increase the badge counter
            let tabId = requestDetails.tabId;
            increaseBadged(requestDetails);

            let url = new URL(requestDetails.url);
            await addBlockedPortToHost(url, tabId);
            if (badges[tabId].alerted == 0 && notificationsAllowed) {
                notifyPortScanning();
                badges[tabId].alerted += 1;

            }
            // Cancel the request
            return { cancel: true };
        }
    }
    // Dont block sites that don't alert the detection
    return { cancel: false };
} // end cancel()


function start() {  // Enables blocking
    try {
        localStorage.setItem("state", true);
        //Add event listener
        browser.webRequest.onBeforeRequest.addListener(
            cancel,
            { urls: ["<all_urls>"] }, // Match all HTTP, HTTPS, FTP, FTPS, WS, WSS URLs.
            ["blocking"] // if cancel() returns true block the request.
        );
    } catch (e) {
        console.log("START() ", e)
    }

}

function stop() {  // Disables blocking
    try {
        localStorage.setItem("state", false);
        //Remove event listener
        browser.webRequest.onBeforeRequest.removeListener(cancel);
    } catch (e) {
        console.log("STOP() ", e)
    }

}

function toggleNotificationsAllowed() {  // toggles notifications
    notificationsAllowed = !notificationsAllowed;
}

function isNotifying() {  // returns if notifications are on
    return notificationsAllowed;
}

function isListening() { // returns if blocking is on
    return browser.webRequest.onBeforeRequest.hasListener(cancel);
}

/**
 * Increases the badged by one.
 * Borrowed and modified from https://gitlab.com/KevinRoebert/ClearUrls/-/blob/master/core_js/badgedHandler.js
 */
function increaseBadged(request) {
    // Error check
    if (request === null) return;

    const tabId = request.tabId;
    const url = request.url;

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
    browser.browserAction.setBadgeText({ text: (badges[tabId]).counter.toString(), tabId: tabId });

}

/**
 * Call by each tab is updated.
 * And if url has changed.
 * Borrowed and modified from https://gitlab.com/KevinRoebert/ClearUrls/-/blob/master/core_js/badgedHandler.js
 */
async function handleUpdated(tabId, changeInfo, tabInfo) {
    if (!badges[tabId] || !changeInfo.url) return;

    if (badges[tabId].lastURL !== changeInfo.url) {
        badges[tabId] = {
            counter: 0,
            alerted: 0,
            lastURL: tabInfo.url
        };
        
	// Clear out the blocked ports for the current tab
        const blocked_ports_object = await getItemFromLocal("blocked_ports", {});
	blocked_ports_object[tabId] = {}
	await setItemInLocal("blocked_ports", blocked_ports_object)
        
        // Clear out the hosts for the current tab
        const blocked_hosts_object = await getItemFromLocal("blocked_hosts", []);
	blocked_hosts_object[tabId] = []
	await setItemInLocal("blocked_hosts", blocked_hosts_object)
    }
}

start();
// Call by each tab is updated.
browser.tabs.onUpdated.addListener(handleUpdated);
browser.runtime.onStartup.addListener(async () => { await browser.storage.local.clear() })
