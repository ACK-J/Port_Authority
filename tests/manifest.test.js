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

    suite("core modules exist");
    for (const path of [
        "global/privateAddress.js",
        "global/requestFilter.js",
        "global/allowlist.js",
        "global/BrowserStorageManager.js",
        "global/tabActivity.js",
        "global/browserActions.js",
        "global/constants.js",
        "global/domUtils.js",
        "popup/PopupUI.js",
        "popup/switch.js",
        "TestPortScans.html",
    ]) {
        assert(readText(path).length > 0, `${path} is non-empty`);
    }
}
