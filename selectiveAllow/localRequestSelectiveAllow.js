// Handles Selective Allow decisions for cross-origin local request blocking.

const params = new URLSearchParams(location.search);
const origin = params.get("origin") ?? "unknown";
const destination = params.get("destination") ?? "unknown";
const originalUrl = params.get("originalUrl") ?? "";
const promptId = params.get("promptId") ?? "";
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

async function sendDecision(type) {
    const message = { type, promptId };
    if (tabId !== undefined) {
        message.tabId = tabId;
    }
    try {
        await browser.runtime.sendMessage(message);
    } finally {
        window.close();
    }
}

document.getElementById("btn-block").addEventListener("click", () => {
    sendDecision("selectiveAllowDismiss");
});

document.getElementById("btn-allow-once").addEventListener("click", () => {
    sendDecision("allowOnce");
});

document.getElementById("btn-always-allow").addEventListener("click", () => {
    sendDecision("alwaysAllow");
});
