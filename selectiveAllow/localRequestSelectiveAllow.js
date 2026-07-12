// Handles Selective Allow decisions for cross-origin local request blocking.

const params = new URLSearchParams(location.search);
const origin = params.get("origin") ?? "unknown";
const destination = params.get("destination") ?? "unknown";
const originalUrl = params.get("originalUrl") ?? "";
const tabIdParam = params.get("tabId");
const tabId = tabIdParam !== null && /^\d+$/.test(tabIdParam) ? Number(tabIdParam) : undefined;

// Extract the protocol from the original URL for display
const protocol = (() => {
    try {
        return new URL(originalUrl).protocol.replace(":", "");
    } catch {
        return "unknown";
    }
})();

document.getElementById("detail-origin").textContent = origin;
document.getElementById("detail-destination").textContent = destination;
document.getElementById("detail-protocol").textContent = protocol;

function sendDecision(type) {
    const message = { type, origin, destination, originalUrl };
    if (tabId !== undefined) {
        message.tabId = tabId;
    }
    return browser.runtime.sendMessage(message);
}

document.getElementById("btn-block").addEventListener("click", () => {
    browser.runtime.sendMessage({ type: "selectiveAllowDismiss", origin, destination });
    window.close();
});

document.getElementById("btn-allow-once").addEventListener("click", () => {
    sendDecision("allowOnce");
    window.close();
});

document.getElementById("btn-always-allow").addEventListener("click", () => {
    sendDecision("alwaysAllow");
    window.close();
});
