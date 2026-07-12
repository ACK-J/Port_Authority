import {
    suite,
    assert,
    assertEqual,
} from "./harness.js";

export async function run() {
    const created = [];
    const badgeUpdates = [];
    const tabQueries = [];
    const windowsCreated = [];
    const tabsCreated = [];

    globalThis.browser = {
        notifications: {
            create: async (id, options) => {
                created.push({ id, ...options });
                return id;
            },
        },
        runtime: {
            getURL: (path) => `moz-extension://addon-id/${path}`,
        },
        browserAction: {
            setBadgeText: (details) => badgeUpdates.push(details),
        },
        tabs: {
            query: async (q) => {
                tabQueries.push(q);
                return [{ id: 42, url: "https://active.example/" }];
            },
            create: async (details) => {
                tabsCreated.push(details);
                return { id: 99, ...details };
            },
        },
        windows: {
            create: async (details) => {
                windowsCreated.push(details);
                return { id: 1, ...details };
            },
        },
    };

    const actions = await import("../global/browserActions.js");

    suite("notifyPortScanning");
    {
        created.length = 0;
        await actions.notifyPortScanning("evil.example");
        assertEqual(created.length, 1, "one notification created");
        assertEqual(created[0].id, "port-scanning-notification", "port scan id");
        assertEqual(created[0].title, "Port Scan Blocked", "title");
        assert(created[0].message.includes("evil.example"), "domain in message");
        assert(created[0].iconUrl.endsWith("icons/logo-96.png"), "icon path");
    }
    {
        created.length = 0;
        await actions.notifyPortScanning();
        assert(created[0].message.includes("blocked this site"), "fallback message without domain");
    }

    suite("notifyThreatMetrix");
    {
        created.length = 0;
        await actions.notifyThreatMetrix("shop.example");
        assertEqual(created[0].id, "threatmetrix-notification", "tmx id");
        assertEqual(created[0].title, "Tracking Script Blocked", "tmx title");
        assert(created[0].message.includes("shop.example"), "domain in tmx message");
        assert(created[0].message.includes("LexisNexis"), "mentions LexisNexis");
    }
    {
        created.length = 0;
        await actions.notifyThreatMetrix();
        assert(created[0].message.includes("hidden LexisNexis endpoint"), "fallback tmx message");
    }

    suite("notifySelectiveAllow");
    {
        created.length = 0;
        await actions.notifySelectiveAllow("github.com", "localhost:8080");
        assertEqual(created[0].id, "selective-allow-notification", "selective allow id");
        assert(created[0].message.includes("github.com"), "origin in message");
        assert(created[0].message.includes("localhost:8080"), "destination in message");
    }

    suite("updateBadges");
    {
        badgeUpdates.length = 0;
        actions.updateBadges(3, 99);
        assertEqual(badgeUpdates.length, 1, "badge updated once");
        assertEqual(badgeUpdates[0].text, "3", "badge text stringified");
        assertEqual(badgeUpdates[0].tabId, 99, "tab id parsed");
    }
    {
        badgeUpdates.length = 0;
        actions.updateBadges(0, "12");
        assertEqual(badgeUpdates[0].tabId, 12, "string tabId parsed to int");
        assertEqual(badgeUpdates[0].text, "0", "zero badge allowed");
    }

    suite("getActiveTabId");
    {
        tabQueries.length = 0;
        const id = await actions.getActiveTabId();
        assertEqual(id, 42, "returns active tab id");
        assertEqual(tabQueries[0].active, true, "queries active tab");
        assertEqual(tabQueries[0].currentWindow, true, "queries current window");
    }
    {
        globalThis.browser.tabs.query = async () => [];
        const id = await actions.getActiveTabId();
        assertEqual(id, undefined, "no active tab returns undefined");
    }

    suite("openSelectiveAllowPopup");
    {
        windowsCreated.length = 0;
        tabsCreated.length = 0;
        const result = await actions.openSelectiveAllowPopup(
            "github.com",
            "localhost:8080",
            "http://localhost:8080/app",
            "prompt-abc"
        );
        assertEqual(windowsCreated.length, 1, "popup window created");
        assertEqual(result?.mode, "window", "reports window mode");
        assertEqual(result?.id, 1, "returns window id");
        const url = new URL(windowsCreated[0].url);
        assert(url.pathname.endsWith("selectiveAllow/selectiveAllow.html"), "popup path");
        assertEqual(url.searchParams.get("promptId"), "prompt-abc", "promptId query");
        assertEqual(url.searchParams.get("tabId"), null, "tabId not in query");
        assertEqual(url.searchParams.get("origin"), "github.com", "origin display query");
    }
    {
        windowsCreated.length = 0;
        tabsCreated.length = 0;
        globalThis.browser.windows.create = async () => {
            throw new Error("window blocked");
        };
        const result = await actions.openSelectiveAllowPopup(
            "github.com",
            "localhost:8080",
            "http://localhost:8080/",
            "prompt-y"
        );
        assertEqual(result?.mode, "tab", "falls back to tab mode");
        assertEqual(result?.id, 99, "returns tab id");
        assertEqual(tabsCreated.length, 1, "fallback tab created");
        assert(tabsCreated[0].url.includes("promptId=prompt-y"), "fallback includes promptId");
    }
    {
        windowsCreated.length = 0;
        tabsCreated.length = 0;
        globalThis.browser.windows.create = async () => ({ id: undefined });
        globalThis.browser.tabs.create = async (details) => {
            tabsCreated.push(details);
            return { id: 77, ...details };
        };
        const result = await actions.openSelectiveAllowPopup(
            "github.com",
            "localhost:8080",
            "http://localhost:8080/",
            "prompt-z"
        );
        assertEqual(result?.mode, "tab", "falls back when window id missing");
        assertEqual(result?.id, 77, "uses fallback tab id");
    }
}
