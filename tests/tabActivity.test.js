import {
    suite,
    assert,
    assertEqual,
} from "./harness.js";
import {
    clearTabActivity,
    getTabActivitySnapshot,
    incrementBadgeCounter,
    recordBlockedPort,
    recordBlockedTrackingHost,
    resetTabActivityForNavigation,
    resetTabActivityMemory,
} from "../global/tabActivity.js";

export async function run() {
    suite("tabActivity in-memory maps");
    {
        resetTabActivityMemory();
        assertEqual(recordBlockedPort(1, "127.0.0.1", "22"), true, "first port recorded");
        assertEqual(recordBlockedPort(1, "127.0.0.1", "22"), false, "duplicate port ignored");
        assertEqual(recordBlockedPort(1, "127.0.0.1", "80"), true, "second port recorded");
        assertEqual(recordBlockedTrackingHost(1, "tmx.example"), true, "tracking host recorded");
        assertEqual(recordBlockedTrackingHost(1, "tmx.example"), false, "duplicate tracking host ignored");

        const snap = getTabActivitySnapshot();
        assertEqual(snap.blocked_ports[1]["127.0.0.1"], ["22", "80"], "ports snapshot");
        assertEqual(snap.blocked_hosts[1], ["tmx.example"], "hosts snapshot");
    }

    suite("tabActivity badge increments");
    {
        resetTabActivityMemory();
        const first = incrementBadgeCounter(9, "https://a.example/");
        assertEqual(first.counter, 1, "first increment");
        assertEqual(first.shouldNotify, true, "first block notifies");
        const second = incrementBadgeCounter(9, "https://a.example/");
        assertEqual(second.counter, 2, "second increment");
        assertEqual(second.shouldNotify, false, "subsequent blocks do not re-notify");
    }

    suite("tabActivity cleanup");
    {
        resetTabActivityMemory();
        recordBlockedPort(3, "10.0.0.1", "445");
        recordBlockedTrackingHost(3, "fp.example");
        incrementBadgeCounter(3, "https://x/");
        clearTabActivity(3);
        const snap = getTabActivitySnapshot();
        assertEqual(snap.blocked_ports[3], undefined, "ports cleared");
        assertEqual(snap.blocked_hosts[3], undefined, "hosts cleared");
        assertEqual(snap.badges[3], undefined, "badges cleared");
    }

    suite("tabActivity navigation reset");
    {
        resetTabActivityMemory();
        recordBlockedPort(5, "10.0.0.2", "22");
        recordBlockedTrackingHost(5, "ln.example");
        incrementBadgeCounter(5, "https://old.example/");
        resetTabActivityForNavigation(5, "https://new.example/");
        const snap = getTabActivitySnapshot();
        assertEqual(snap.blocked_ports[5], undefined, "ports cleared on navigate");
        assertEqual(snap.blocked_hosts[5], undefined, "hosts cleared on navigate");
        assertEqual(snap.badges[5].counter, 0, "badge counter reset");
        assertEqual(snap.badges[5].lastURL, "https://new.example/", "lastURL updated");
        assert(true, "navigation reset keeps a badge slot");
    }
}
