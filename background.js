let port_scans_blocked = 0;
localStorage.removeItem('check');
localStorage.setItem('check', true);
let notified = false;


var portScanningNotif = "port-scanning-notification"

function notify(){
  browser.notifications.create(portScanningNotif, {
    "type": "basic",
    "iconUrl": browser.runtime.getURL("icons/logo-16.png"),
    "title": "This site attempted to port scan you!",
    "message": "Port Authority has blocked this site from port scanning your private network."
  });
}

function cancel(requestDetails) {
	// Please note that the regex in https://regex101.com/r/DOPCdB/4/ is different from below, since below I needed to add an extra \ to \\b and \\w
	const local_filter = "\\b(\\w[htpsw]{1,5}:\/\/127\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|\\w[htpsw]{1,5}:\/\/0?10\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|\\w[htpsw]{1,5}:\/\/localhost|\\w[htpsw]{1,5}:\/\/172\.(16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|\\w[htpsw]{1,5}:\/\/192\.168\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|\\w[htpsw]{1,5}:\/\/169\.254\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|\\w[htpsw]{1,5}:\/\/::1|\\w[htpsw]{1,5}:\/\/[fF][cCdD][0-9a-fA-F]{2}(?:[:][0-9a-fA-F]{0,4}){0,7}|\\w[htpsw]{1,5}:\/\/[fF][eE][89aAbB][0-9a-fA-F](?:[:][0-9a-fA-F]{0,4}){0,7})(?:\/([789]|1?[0-9]{2}))?\\b";
    // Error check
    if (requestDetails.originUrl === null || requestDetails.url === null){
        return {cancel: false};
    }
    // Check if the network request is going to a local address
    if (requestDetails.url.match(local_filter) !== null){
	    // Check if the current website visited is a local address
	    if (requestDetails.originUrl.match(local_filter) === null){
                increment();
                if (!notified){
                    notify();
                    notified = true;
                }
	        return {cancel: true};
	    }
    }
    // Dont block sites that don't alert the detection
    return {cancel: false};
}

function increment() {
  browser.browserAction.setBadgeText({text: (++port_scans_blocked).toString()});
}

export function start() {
    //Add event listener
    browser.webRequest.onBeforeRequest.addListener(
        cancel,
        {urls: ["*://*/*"]}, // Match all HTTP, HTTPS and WebSocket URLs.
        ["blocking"] // if cancel() returns true block the request.
    );
    notified = false;
}
export function stop() {
  //Remove event listener
  browser.webRequest.onBeforeRequest.removeListener(cancel);
}

start();



