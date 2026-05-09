const params = new URLSearchParams(location.search);
const origin = params.get("origin") ?? "unknown";
const destination = params.get("destination") ?? "unknown";
const originalUrl = params.get("originalUrl") ?? "";

const protocol = (() => {
    try { return new URL(originalUrl).protocol.replace(":", ""); } catch { return "unknown"; }
})();

document.getElementById("detail-origin").textContent = origin;
document.getElementById("detail-destination").textContent = destination;
document.getElementById("detail-protocol").textContent = protocol;

document.getElementById("btn-block").addEventListener("click", () => {
    window.close();
});

document.getElementById("btn-allow-once").addEventListener("click", () => {
    browser.runtime.sendMessage({ type: "allowOnce", origin, destination, originalUrl });
    window.close();
});

document.getElementById("btn-always-allow").addEventListener("click", () => {
    browser.runtime.sendMessage({ type: "alwaysAllow", origin, destination, originalUrl });
    window.close();
});
