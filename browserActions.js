
// TODO better separate concerns between storage related things and browser actions
// Currently importing this from BrowserStorageManager, reaaally need to stop doing that

export async function notifyPortScanning(domain_name) {
    if (domain_name) {
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
}// TODO better separate concerns between storage related things and browser actions
// Currently importing this from BrowserStorageManager, reaaally need to stop doing that

export async function notifyThreatMetrix(domain_name) {
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
