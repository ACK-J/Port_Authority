
function cancel(requestDetails) {
	var local_filter = "\\b(127\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|0?10\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|^ws:\/\/localhost|^http:\/\/localhost|^https:\/\/localhost|^wss:\/\/localhost|172\.0?1[6-9]\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|
172\.0?2[0-9]\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|172\.0?3[0-2]\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|192\.168\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|169\.254\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|::1|[fF][cCdD][0-9a-fA-F]{2}(?:[:][0-9a-fA-F]{0,4}){0,7}|[fF][eE][89aAbB][0-9a-fA-F](?:[:][0-9a-fA-F]{0,4}){0,7})(?:\/([789]|1?[0-9]{2}))?\\b"
    // Error check
    if (requestDetails.originUrl === null){
        return {cancel: false};
    }
    // Check if the network request is going to a local address
    if (requestDetails.url.match(local_filter) !== null){
	    // Check if the current website visited is a local address
	    if (requestDetails.originUrl.match(local_filter) === null){
	        return {cancel: true};
	    }
    }
    // Dont block sites that don't alert the detection
    return {cancel: false};
}

browser.webRequest.onBeforeRequest.addListener(
    cancel,
    {urls: ["*://*/*"]}, // Match all HTTP, HTTPS and WebSocket URLs.
    ["blocking"] // if cancel() returns true block the request.
);
