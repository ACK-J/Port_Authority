
function cancel(requestDetails) {
	var local_filter = "\\b(127\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|0?10\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|172\.0?1[6-9]\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|172\.0?2[0-9]\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|172\.0?3[0-2]\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|192\.168\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|169\.254\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|::1|[fF][cCdD][0-9a-fA-F]{2}(?:[:][0-9a-fA-F]{0,4}){0,7}|[fF][eE][89aAbB][0-9a-fA-F](?:[:][0-9a-fA-F]{0,4}){0,7})(?:\/([789]|1?[0-9]{2}))?\\b"
    var one_twenty_seven = "\b127\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|0?10\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|172\.0?1[6-9]\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    var one_seventy_two = "\b172\.0?2[0-9]\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|172\.0?3[0-2]\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    var one_ninety_two = "192\.168\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
    var link_local = "169\.254\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    var ipv6_loopback = "\b::1\b"
    var private_ipv6 = "\b[fF][cCdD][0-9a-fA-F]{2}(?:[:][0-9a-fA-F]{0,4}){0,7}\b"
    var link_local_ipv6 = "\b([fF][eE][89aAbB][0-9a-fA-F](?:[:][0-9a-fA-F]{0,4}){0,7})(?:\/([789]|1?[0-9]{2}))?\b"
    var url;
    // Grab the current active tab
    cur_tab = browser.tabs.query({active: true});
    // Get the URL from the current tab
    console.log(requestDetails.url);
    console.log(requestDetails.url.match(local_filter) !== null );
    // Assign the current website to var url
    cur_tab.then(function(v) {
      console.log(v[0].url);
      url = v[0].url;
    });
    // Error check
    if (url === null){
        return {cancel: false};
    }
    // Check if the network request is going to a local address
    if (requestDetails.url.match(local_filter) !== null){ //|| requestDetails.url.match(one_seventy_two) !== null || requestDetails.url.match(one_ninety_two) !== null || requestDetails.url.match(link_local) !== null || requestDetails.url.match(ipv6_loopback) !== null || requestDetails.url.match(private_ipv6) !== null || requestDetails.url.match(link_local_ipv6) !== null){
	    console.log("1");
	    // Check if the current website is a local address
	    if (requestDetails.originUrl.match(local_filter) === null){// && requestDetails.originUrl.match(one_seventy_two) === null && requestDetails.originUrl.match(one_ninety_two) === null && requestDetails.originUrl.match(link_local) === null && requestDetails.originUrl.match(ipv6_loopback) === null && requestDetails.originUrl.match(private_ipv6) === null && requestDetails.originUrl.match(link_local_ipv6) === null){
	        console.log("2");
	        return {cancel: true};
	    }
    }

    return {cancel: false};
}

browser.webRequest.onBeforeRequest.addListener(
    cancel,
    {urls: ["*://*/*"]}, // Match all HTTP, HTTPS and WebSocket URLs.
    ["blocking"] // if cancel() returns true block the request.
);
