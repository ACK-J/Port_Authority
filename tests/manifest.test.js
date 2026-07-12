import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { suite, assert, assertEqual } from "./harness.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

function readJson(relativePath) {
    return JSON.parse(readFileSync(join(root, relativePath), "utf8"));
}

function readText(relativePath) {
    return readFileSync(join(root, relativePath), "utf8");
}

export async function run() {
    suite("manifest.json structure");
    const manifest = readJson("manifest.json");
    assertEqual(manifest.manifest_version, 2, "manifest v2");
    assertEqual(manifest.name, "Port Authority", "extension name");
    assert(typeof manifest.version === "string" && /^\d+\.\d+\.\d+$/.test(manifest.version), "semver version");
    assert(manifest.background?.scripts?.includes("background.js"), "background script registered");
    assertEqual(manifest.background?.type, "module", "background is ES module");
    assertEqual(manifest.browser_action?.default_popup, "popup/popup.html", "popup registered");
    assertEqual(manifest.options_ui?.page, "settings/settings.html", "settings page registered");

    suite("manifest permissions");
    const required = [
        "webRequest",
        "webRequestBlocking",
        "storage",
        "tabs",
        "notifications",
        "dns",
        "<all_urls>",
    ];
    for (const perm of required) {
        assert(manifest.permissions.includes(perm), `permission: ${perm}`);
    }

    suite("background.js wires request filter");
    const background = readText("background.js");
    assert(background.includes('from "./global/requestFilter.js"'), "imports requestFilter");
    assert(background.includes("evaluateRequest"), "calls evaluateRequest");
    assert(background.includes("createDnsResultCache"), "creates session DNS cache");
    assert(background.includes("dnsCache"), "passes dnsCache to evaluateRequest");
    assert(background.includes("toggleEnabled"), "handles toggle messages");
    assert(background.includes("onBeforeRequest"), "registers webRequest listener");
    assert(background.includes("hasListener"), "guards against duplicate blocking listeners");
    assert(background.includes("onRemoved"), "cleans up tab activity on tab close");
    assert(background.includes("resetSessionTabActivity"), "resets stale session activity on startup");
    assert(background.includes("getAllowedDomainListCached"), "uses cached allowlist on hot path");
    assert(background.includes("handleSelectiveAllowNavigation"), "selective allow for main_frame locals");
    assert(background.includes("validatePendingAllow"), "validates allow Once/Always against pending");
    assert(background.includes("allowOnce"), "handles allowOnce messages");
    assert(background.includes("alwaysAllow"), "handles alwaysAllow messages");
    assert(background.includes("clearPendingByWindowId"), "clears pending when prompt window closes");
    assert(background.includes("windows.onRemoved"), "listens for prompt window close");
    assert(background.includes("originAllowKey"), "uses stable origin keys including file paths");
    assert(background.includes("ensurePendingPrompt"), "atomic pending create-or-update");
    assert(background.includes("revokeSessionAllow"), "can revoke session allows");
    assert(background.includes("syncSessionAllowsWithCrossOriginChange"), "settings removal syncs session");

    suite("requestFilter.js ThreatMetrix remediation surface");
    const requestFilter = readText("global/requestFilter.js");
    assert(requestFilter.includes("THREATMETRIX_SUFFIXES"), "exports auditable suffix list");
    assert(requestFilter.includes("matchesThreatMetrixHost"), "exports host matcher");
    assert(requestFilter.includes("createDnsResultCache"), "exports DNS LRU helper");
    assert(requestFilter.includes("getInflight"), "DNS cache coalesces in-flight resolves");
    assert(requestFilter.includes("threatmetrix.com"), "lists threatmetrix.com");
    assert(requestFilter.includes("lexisnexisrisk.com"), "lists lexisnexisrisk.com");
    assert(requestFilter.includes("lnrsoftware.com"), "lists lnrsoftware.com");
    assert(requestFilter.includes('from "./allowlist.js"'), "uses shared allowlist helper");
    assert(requestFilter.includes("requestMatchesAllowlist"), "delegates allowlist checks");
    assert(requestFilter.includes('from "./privateAddress.js"'), "imports privateAddress helpers");

    suite("privateAddress.js owns hostname normalization");
    const privateAddress = readText("global/privateAddress.js");
    assert(privateAddress.includes("export function normalizeHostname"), "exports normalizeHostname");

    suite("settings.js uses shared allowlist helper");
    const settings = readText("settings/settings.js");
    assert(settings.includes('from "../global/allowlist.js"'), "imports allowlist module");
    assert(settings.includes("normalizeAllowlistEntry"), "uses normalizeAllowlistEntry");
    assert(settings.includes("cross_origin_allowlist"), "manages selective allow permissions");
    assert(settings.includes("load_cross_origin_list"), "renders cross-origin allowlist");

    suite("core modules exist");
    for (const path of [
        "global/privateAddress.js",
        "global/requestFilter.js",
        "global/allowlist.js",
        "global/selectiveAllow.js",
        "global/BrowserStorageManager.js",
        "global/tabActivity.js",
        "global/browserActions.js",
        "global/constants.js",
        "global/domUtils.js",
        "selectiveAllow/selectiveAllow.html",
        "selectiveAllow/localRequestSelectiveAllow.js",
        "popup/PopupUI.js",
        "popup/switch.js",
        "TestPortScans.html",
    ]) {
        assert(readText(path).length > 0, `${path} is non-empty`);
    }
}
