localStorage.removeItem('check');
localStorage.setItem('check', true);

let badges = {};

function onError(error) {
  console.error(`Error: ${error}`);
}

function notify(){
  browser.notifications.create("port-scanning-notification", {
    "type": "basic",
    "iconUrl": browser.runtime.getURL("icons/logo-96.png"),
    "title": "This site attempted to port scan you!",
    "message": "Port Authority has blocked this site from port scanning your private network."
  });
}

function cancel(requestDetails) {
	// Please note that the regex in https://regex101.com/r/DOPCdB/4/ is different from below, since below I needed to add an extra \ to \\b
	const local_filter = "\\b((http|https|wss|ws):\/\/127\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(http|https|wss|ws):\/\/0?10\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(http|https|wss|ws):\/\/localhost|(http|https|wss|ws):\/\/172\.(0?16|0?17|0?18|0?19|0?20|0?21|0?22|0?23|0?24|0?25|0?26|0?27|0?28|0?29|0?30|0?31)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(http|https|wss|ws):\/\/192\.168\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(http|https|wss|ws):\/\/169\.254\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(http|https|wss|ws):\/\/::1|(http|https|wss|ws):\/\/[fF][cCdD][0-9a-fA-F]{2}(?:[:][0-9a-fA-F]{0,4}){0,7}|(http|https|wss|ws):\/\/[fF][eE][89aAbB][0-9a-fA-F](?:[:][0-9a-fA-F]{0,4}){0,7})(?:\/([789]|1?[0-9]{2}))?\\b";
    // Error check
    if (requestDetails.originUrl === null || requestDetails.url === null){
        return {cancel: false};
    }
    // Check if the network request is going to a local address
    if (requestDetails.url.match(local_filter) !== null){
	    // Check if the current website visited is a local address
	    if (requestDetails.originUrl.match(local_filter) === null){
                let tabId = requestDetails.tabId;
                increaseBadged(requestDetails);
                if (badges[tabId].alerted == 0){
                    notify();
                    badges[tabId].alerted += 1;
                }
	        return {cancel: true};
	    }
    }
    // Dont block sites that don't alert the detection
    return {cancel: false};
}

export function start() {
    //Add event listener
    browser.webRequest.onBeforeRequest.addListener(
        cancel,
        {urls: ["*://*/*"]}, // Match all HTTP, HTTPS and WebSocket URLs.
        ["blocking"] // if cancel() returns true block the request.
    );
}
export function stop() {
  //Remove event listener
  browser.webRequest.onBeforeRequest.removeListener(cancel);
}

/**
 * Increases the badged by one.
 * Borrowed and modified from https://gitlab.com/KevinRoebert/ClearUrls/-/blob/master/core_js/badgedHandler.js
 */
function increaseBadged(request) {
    // Error check
    if(request === null) return;

    const tabId = request.tabId;
    const url = request.url;

    if(tabId === -1) return;

    if (badges[tabId] == null) {
        badges[tabId] = {
            counter: 1,
            alerted: 0,
            lastURL: url
        };
    } else {
        badges[tabId].counter += 1;
    }
    browser.browserAction.setBadgeText({text: (badges[tabId]).counter.toString(), tabId: tabId});

}

/**
 * Call by each tab is updated.
 * And if url has changed.
 * Borrowed and modified from https://gitlab.com/KevinRoebert/ClearUrls/-/blob/master/core_js/badgedHandler.js
 */
function handleUpdated(tabId, changeInfo, tabInfo) {
    if(!badges[tabId] || !changeInfo.url) return;

    if (badges[tabId].lastURL !== changeInfo.url) {
        badges[tabId] = {
            counter: 0,
            alerted: 0,
            lastURL: tabInfo.url
        };
    }
}



start();
// Call by each tab is updated.
browser.tabs.onUpdated.addListener(handleUpdated);



