/**
 * BrowserStorageManager tests with mocked extension storage + locks.
 *
 * Imports are dynamic after mocks are installed so the module sees them.
 */
import {
    suite,
    assert,
    assertEqual,
    createMockStorage,
    installLockMock,
} from "./harness.js";

function silenceConsole() {
    const original = {
        debug: console.debug,
        warn: console.warn,
        error: console.error,
    };
    console.debug = () => {};
    console.warn = () => {};
    console.error = () => {};
    return () => Object.assign(console, original);
}

export async function run() {
    const restoreConsole = silenceConsole();
    try {
        await runQuiet();
    } finally {
        restoreConsole();
    }
}

async function runQuiet() {
    installLockMock();
    const storage = createMockStorage();
    globalThis.browser = {
        storage: { local: storage },
    };

    const notifications = [];
    const badges = [];

    const storageApi = await import("../global/BrowserStorageManager.js");

    globalThis.browser.notifications = {
        create: async (id, opts) => {
            notifications.push({ id, ...opts });
            return id;
        },
    };
    globalThis.browser.runtime = {
        getURL: (path) => `moz-extension://test/${path}`,
    };
    globalThis.browser.browserAction = {
        setBadgeText: (details) => {
            badges.push(details);
        },
    };

    suite("getItemFromLocal defaults and reads");
    {
        const value = await storageApi.getItemFromLocal("missing_key", ["default"]);
        assertEqual(value, ["default"], "missing key returns default");
    }
    {
        await storageApi.setItemInLocal("blocking_enabled", true);
        const value = await storageApi.getItemFromLocal("blocking_enabled", false);
        assertEqual(value, true, "reads back boolean true");
    }
    {
        await storageApi.setItemInLocal("allowed_domain_list", ["a.com", "b.com"]);
        const value = await storageApi.getItemFromLocal("allowed_domain_list", []);
        assertEqual(value, ["a.com", "b.com"], "reads back array");
    }
    {
        await storageApi.setItemInLocal("notificationsAllowed", false);
        const value = await storageApi.getItemFromLocal("notificationsAllowed", true);
        assertEqual(value, false, "false is a valid stored value");
    }

    suite("setItemInLocal overwrite");
    {
        await storageApi.setItemInLocal("counter", 1);
        await storageApi.setItemInLocal("counter", 2);
        const value = await storageApi.getItemFromLocal("counter", 0);
        assertEqual(value, 2, "overwrite replaces prior value");
    }

    suite("modifyItemInLocal atomic updates");
    {
        await storageApi.setItemInLocal("list", ["x"]);
        const updated = await storageApi.modifyItemInLocal("list", [], (list) => list.concat("y"));
        assertEqual(updated, ["x", "y"], "modify returns new value");
        assertEqual(await storageApi.getItemFromLocal("list", []), ["x", "y"], "modify persisted");
    }
    {
        const updated = await storageApi.modifyItemInLocal("brand_new", 0, (v) => v + 5);
        assertEqual(updated, 5, "modify uses default when missing");
    }
    {
        await storageApi.setItemInLocal("race", 0);
        await Promise.all([
            storageApi.modifyItemInLocal("race", 0, async (v) => {
                await new Promise((r) => setTimeout(r, 5));
                return v + 1;
            }),
            storageApi.modifyItemInLocal("race", 0, async (v) => {
                await new Promise((r) => setTimeout(r, 5));
                return v + 1;
            }),
            storageApi.modifyItemInLocal("race", 0, async (v) => {
                await new Promise((r) => setTimeout(r, 5));
                return v + 1;
            }),
        ]);
        const value = await storageApi.getItemFromLocal("race", -1);
        assertEqual(value, 3, "locked modifies serialize increments");
    }

    suite("clearItemsInLocal");
    {
        await storageApi.setItemInLocal("tmp", 123);
        const defaults = await storageApi.clearItemsInLocal({
            allowed_domain_list: [],
            blocking_enabled: true,
            notificationsAllowed: true,
        });
        assertEqual(defaults.blocking_enabled, true, "clear returns defaults");
        assertEqual(await storageApi.getItemFromLocal("tmp", null), null, "old keys gone");
        assertEqual(await storageApi.getItemFromLocal("blocking_enabled", false), true, "defaults written");
    }

    suite("addBlockedPortToHost");
    {
        await storageApi.resetSessionTabActivity();

        storageApi.addBlockedPortToHost(new URL("http://127.0.0.1:22/"), "7");
        storageApi.addBlockedPortToHost(new URL("http://127.0.0.1:80/"), "7");
        storageApi.addBlockedPortToHost(new URL("http://127.0.0.1:22/"), "7");
        storageApi.addBlockedPortToHost(new URL("http://10.0.0.1:445/"), "7");
        storageApi.addBlockedPortToHost(new URL("https://192.168.0.1/"), "8");
        await storageApi.flushTabActivity();

        const ports = await storageApi.getItemFromLocal("blocked_ports", {});
        assertEqual(ports[7]["127.0.0.1"], ["22", "80"], "ports collected without dupes");
        assertEqual(ports[7]["10.0.0.1"], ["445"], "second host on same tab");
        assertEqual(ports[8]["192.168.0.1"], ["443"], "default https port recorded");
    }
    {
        storageApi.addBlockedPortToHost(new URL("http://172.16.0.1/"), "9");
        await storageApi.flushTabActivity();
        const ports = await storageApi.getItemFromLocal("blocked_ports", {});
        assertEqual(ports[9]["172.16.0.1"], ["80"], "default http port");
    }

    suite("addBlockedTrackingHost");
    {
        await storageApi.resetSessionTabActivity();
        storageApi.addBlockedTrackingHost(new URL("https://cdn.brand.com/tmx.js"), "3");
        storageApi.addBlockedTrackingHost(new URL("https://cdn.brand.com/tmx.js"), "3");
        storageApi.addBlockedTrackingHost(new URL("https://other.brand.com/x"), "3");
        storageApi.addBlockedTrackingHost(new URL("https://cdn.brand.com/tmx.js"), "4");
        await storageApi.flushTabActivity();

        const hosts = await storageApi.getItemFromLocal("blocked_hosts", {});
        assertEqual(hosts[3], ["cdn.brand.com", "other.brand.com"], "unique hosts per tab");
        assertEqual(hosts[4], ["cdn.brand.com"], "separate tab list");
    }

    suite("increaseBadge");
    {
        await storageApi.clearItemsInLocal({ notificationsAllowed: true });
        await storageApi.resetSessionTabActivity();
        storageApi.syncNotificationsAllowedCache(true);
        badges.length = 0;
        notifications.length = 0;

        await storageApi.increaseBadge(
            { tabId: 11, url: "http://127.0.0.1:22/", originUrl: "https://scanner.example/" },
            false
        );
        await storageApi.increaseBadge(
            { tabId: 11, url: "http://127.0.0.1:80/", originUrl: "https://scanner.example/" },
            false
        );
        await storageApi.flushTabActivity();

        const badgeState = await storageApi.getItemFromLocal("badges", {});
        assertEqual(badgeState[11].counter, 2, "badge counter increments");
        assertEqual(badgeState[11].alerted, 1, "only one notification alerted");
        assert(badges.length >= 2, "badge text updated");
        assert(notifications.some((n) => n.id === "port-scanning-notification"), "port scan notification");
    }
    {
        await storageApi.clearItemsInLocal({ notificationsAllowed: true });
        await storageApi.resetSessionTabActivity();
        storageApi.syncNotificationsAllowedCache(true);
        notifications.length = 0;
        await storageApi.increaseBadge(
            { tabId: 12, url: "https://tmx.example/", originUrl: "https://shop.example/" },
            true
        );
        assert(notifications.some((n) => n.id === "threatmetrix-notification"), "threatmetrix notification");
    }
    {
        await storageApi.clearItemsInLocal({ notificationsAllowed: false });
        await storageApi.resetSessionTabActivity();
        storageApi.syncNotificationsAllowedCache(false);
        notifications.length = 0;
        await storageApi.increaseBadge(
            { tabId: 13, url: "http://127.0.0.1/", originUrl: "https://x.example/" },
            false
        );
        assertEqual(notifications.length, 0, "notifications suppressed when disabled");
    }
    {
        await storageApi.increaseBadge(null, false);
        await storageApi.increaseBadge({ tabId: -1, url: "http://x/" }, false);
        assert(true, "invalid increaseBadge calls do not throw");
    }

    suite("tab activity coalescing and cleanup (issue #52)");
    {
        await storageApi.resetSessionTabActivity();

        let setCalls = 0;
        const innerSet = storage.set.bind(storage);
        storage.set = async (obj) => {
            setCalls += 1;
            return innerSet(obj);
        };

        const setsBeforeBurst = setCalls;
        for (let i = 0; i < 500; i++) {
            storageApi.addBlockedTrackingHost(
                new URL(`https://h-${i % 5}.online-metrix.net/x`),
                "42"
            );
        }
        assertEqual(setCalls, setsBeforeBurst, "no storage writes during sync blocked-host burst");

        await storageApi.flushTabActivity();
        assert(setCalls > setsBeforeBurst, "flush persists coalesced activity");

        const hosts = await storageApi.getItemFromLocal("blocked_hosts", {});
        assertEqual(hosts[42].length, 5, "unique hosts retained after burst");

        storageApi.syncNotificationsAllowedCache(false);
        const setsBeforeBadges = setCalls;
        for (let i = 0; i < 100; i++) {
            await storageApi.increaseBadge(
                {
                    tabId: 42,
                    url: `https://h-${i % 5}.online-metrix.net/x`,
                    originUrl: "https://bank.example/",
                },
                true
            );
        }
        await storageApi.flushTabActivity();
        const badgeState = await storageApi.getItemFromLocal("badges", {});
        assertEqual(badgeState[42].counter, 100, "all increments applied in memory");
        assert(
            setCalls - setsBeforeBadges <= 10,
            "badge storm does not create one storage write per increment"
        );

        storageApi.clearTabActivityData(42);
        await storageApi.flushTabActivity();
        const clearedHosts = await storageApi.getItemFromLocal("blocked_hosts", {});
        const clearedBadges = await storageApi.getItemFromLocal("badges", {});
        assertEqual(clearedHosts[42], undefined, "tab close clears blocked hosts");
        assertEqual(clearedBadges[42], undefined, "tab close clears badges");

        storage.set = innerSet;
    }

    suite("allowlist cache");
    {
        await storageApi.setItemInLocal("allowed_domain_list", ["a.example"]);
        storageApi.syncAllowedDomainListCache(undefined);
        const first = await storageApi.getAllowedDomainListCached();
        assertEqual(first, ["a.example"], "cache loads from storage");

        await storage.set({ allowed_domain_list: JSON.stringify(["stale-ignored.example"]) });
        const second = await storageApi.getAllowedDomainListCached();
        assertEqual(second, ["a.example"], "hot path keeps cached allowlist");

        storageApi.applyStorageChangesToCaches({
            allowed_domain_list: { newValue: JSON.stringify(["fresh.example"]) },
        });
        const third = await storageApi.getAllowedDomainListCached();
        assertEqual(third, ["fresh.example"], "storage.onChanged refreshes cache");
    }

    assert(typeof storageApi.getItemFromLocal === "function", "API exported");
}
