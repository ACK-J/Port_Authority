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
    assert(background.includes("toggleEnabled"), "handles toggle messages");
    assert(background.includes("onBeforeRequest"), "registers webRequest listener");
    assert(background.includes("allowed_domain_list"), "reads allowlist from storage");

    suite("settings.js uses shared allowlist helper");
    const settings = readText("settings/settings.js");
    assert(settings.includes('from "../global/allowlist.js"'), "imports allowlist module");
    assert(settings.includes("extractURLHost"), "uses extractURLHost");

    suite("core modules exist");
    for (const path of [
        "global/privateAddress.js",
        "global/requestFilter.js",
        "global/allowlist.js",
        "global/BrowserStorageManager.js",
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
