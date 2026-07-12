// Handles Selective Allow decisions for cross-origin local request blocking.

const params = new URLSearchParams(location.search);
const origin = params.get("origin") ?? "unknown";
const destination = params.get("destination") ?? "unknown";
const originalUrl = params.get("originalUrl") ?? "";
const promptId = params.get("promptId") ?? "";

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
    try {
        await browser.runtime.sendMessage({ type, promptId });
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
