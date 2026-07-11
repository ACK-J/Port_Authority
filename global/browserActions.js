async function notify(id, title, message) {
    return browser.notifications.create(id, {
        type: "basic",
        iconUrl: browser.runtime.getURL("icons/logo-96.png"),
        title,
        message,
    });
}

export async function notifyPortScanning(domain_name) {
    const message = domain_name
        ? `Port Authority blocked ${domain_name} from port scanning your private network.`
        : "Port Authority blocked this site from port scanning your private network.";

    return notify("port-scanning-notification", "Port Scan Blocked", message);
}

export async function notifyThreatMetrix(domain_name) {
    const message = domain_name
        ? `Port Authority blocked a hidden LexisNexis endpoint on ${domain_name} from running an invasive data collection script.`
        : "Port Authority blocked a hidden LexisNexis endpoint from running an invasive data collection script.";

    return notify("threatmetrix-notification", "Tracking Script Blocked", message);
}

/**
 * Updates the extension button's badge text on the relevant tab.
 * @param {string|number} text
 * @param {number|string} tabId
 */
export function updateBadges(text, tabId) {
    try {
        browser.browserAction.setBadgeText({
            text: text.toString(),
            tabId: parseInt(tabId, 10),
        });
    } catch (error) {
        console.error("Couldn't update badge:", { tabId, text, error });
    }
}

/**
 * @returns {Promise<number|undefined>} Focused tab id, or undefined when none
 */
export async function getActiveTabId() {
    const tabs = await browser.tabs.query({
        currentWindow: true,
        active: true,
    });
    return tabs[0]?.id;
}
