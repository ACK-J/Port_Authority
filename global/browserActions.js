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
 * Heads-up that a Selective Allow decision window/tab was opened.
 * @param {string} origin
 * @param {string} destination
 */
export async function notifySelectiveAllow(origin, destination) {
    const from = origin || "this page";
    return notify(
        "selective-allow-notification",
        "Local Navigation Blocked",
        `Port Authority blocked ${from} from opening ${destination}. Choose Block, Allow Once, or Always Allow in the prompt.`
    );
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

/**
 * Build the Selective Allow decision page URL.
 * @param {string} origin
 * @param {string} destination
 * @param {string} originalUrl
 * @param {number} [tabId]
 * @param {string} [promptId]
 * @returns {string}
 */
export function buildSelectiveAllowUrl(
    origin,
    destination,
    originalUrl,
    tabId,
    promptId
) {
    const params = new URLSearchParams({ origin, destination, originalUrl });
    if (Number.isInteger(tabId) && tabId >= 0) {
        params.set("tabId", String(tabId));
    }
    if (typeof promptId === "string" && promptId.length > 0) {
        params.set("promptId", promptId);
    }
    return browser.runtime.getURL(`selectiveAllow/selectiveAllow.html?${params}`);
}

/**
 * Opens a Selective Allow decision UI.
 * Prefers a popup window; falls back to a tab if the window cannot open.
 *
 * @param {string} origin
 * @param {string} destination
 * @param {string} originalUrl
 * @param {number} [tabId]
 * @param {string} [promptId]
 * @returns {Promise<{ mode: "window"|"tab", id: number }|undefined>}
 */
export async function openSelectiveAllowPopup(
    origin,
    destination,
    originalUrl,
    tabId,
    promptId
) {
    const url = buildSelectiveAllowUrl(
        origin,
        destination,
        originalUrl,
        tabId,
        promptId
    );

    try {
        const win = await browser.windows.create({
            url,
            type: "popup",
            width: 520,
            height: 320,
            allowScriptsToClose: true,
            focused: true,
        });
        if (Number.isInteger(win?.id) && win.id >= 0) {
            return { mode: "window", id: win.id };
        }
    } catch (windowError) {
        console.warn("Selective allow popup window failed; opening a tab instead:", windowError);
    }

    try {
        const tab = await browser.tabs.create({ url, active: true });
        if (Number.isInteger(tab?.id) && tab.id >= 0) {
            return { mode: "tab", id: tab.id };
        }
    } catch (tabError) {
        console.error("Selective allow fallback tab failed:", tabError);
    }

    return undefined;
}
