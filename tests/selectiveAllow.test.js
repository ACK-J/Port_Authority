/**
 * Unit tests for Selective Allow helpers (issue #57).
 */
import {
    makeAllowKey,
    originAllowKey,
    listHasCrossOriginEntry,
    validatePendingAllow,
    createSelectiveAllowState,
} from "../global/selectiveAllow.js";
import { suite, assert, assertEqual } from "./harness.js";

export async function run() {
    suite("makeAllowKey");
    {
        assertEqual(
            makeAllowKey("github.com", "localhost:8080"),
            "github.com|localhost:8080",
            "joins origin and destination"
        );
    }

    suite("originAllowKey");
    {
        assertEqual(
            originAllowKey(new URL("https://github.com/foo")),
            "github.com",
            "https host key"
        );
        assertEqual(
            originAllowKey(new URL("https://github.com:8443/foo")),
            "github.com:8443",
            "host with non-default port"
        );
        assertEqual(
            originAllowKey(new URL("file:///tmp/a.html")),
            "file:///tmp/a.html",
            "file url uses pathname"
        );
        assert(
            originAllowKey(new URL("file:///tmp/a.html")) !==
                originAllowKey(new URL("file:///tmp/b.html")),
            "file keys are not collapsed to protocol only"
        );
    }

    suite("listHasCrossOriginEntry");
    {
        const list = [
            { origin: "docs.example", destination: "127.0.0.1:8000" },
            { origin: "github.com", destination: "localhost:8080" },
        ];
        assert(
            listHasCrossOriginEntry(list, "github.com", "localhost:8080"),
            "finds matching pair"
        );
        assert(
            !listHasCrossOriginEntry(list, "github.com", "localhost:9090"),
            "different destination is not a match"
        );
        assert(
            !listHasCrossOriginEntry([], "github.com", "localhost:8080"),
            "empty list has no match"
        );
        assert(
            !listHasCrossOriginEntry(null, "github.com", "localhost:8080"),
            "null list treated as empty"
        );
    }

    suite("validatePendingAllow");
    {
        const valid = validatePendingAllow({
            origin: "github.com",
            destination: "localhost:8080",
            originalUrl: "http://localhost:8080/console",
            navigationTabId: 7,
        });
        assert(valid.ok, "accepts pending local navigation");
        assertEqual(valid.origin, "github.com", "origin from pending");
        assertEqual(valid.tabId, 7, "navigationTabId used");
    }
    {
        const valid = validatePendingAllow({
            origin: "docs.example",
            destination: "192.168.1.10",
            originalUrl: "https://192.168.1.10/",
            navigationTabId: -1,
        });
        assert(valid.ok, "negative tabId treated as missing");
        assertEqual(valid.tabId, undefined, "invalid tab cleared");
    }
    {
        const result = validatePendingAllow({
            origin: "evil.example",
            destination: "localhost:8080",
            originalUrl: "https://evil.example/phish",
        });
        assert(!result.ok, "rejects remote originalUrl");
        assertEqual(result.reason, "destination-mismatch", "destination-mismatch reason");
    }
    {
        const result = validatePendingAllow({
            origin: "evil.example",
            destination: "example.com",
            originalUrl: "https://example.com/",
        });
        assert(!result.ok, "rejects non-local destination");
        assertEqual(result.reason, "not-local", "not-local reason");
    }
    {
        const result = validatePendingAllow(null);
        assert(!result.ok, "rejects missing pending");
        assertEqual(result.reason, "missing-pending", "missing-pending reason");
    }

    suite("createSelectiveAllowState");
    {
        const state = createSelectiveAllowState();
        const pending = state.createPendingPrompt({
            origin: "a.com",
            destination: "localhost:1",
            originalUrl: "http://localhost:1/",
            navigationTabId: 5,
        });
        assert(state.hasPendingPrompt("a.com", "localhost:1"), "pending marked");
        assertEqual(state.pendingSize, 1, "one pending");
        assert(state.getPendingByPromptId(pending.promptId)?.originalUrl === "http://localhost:1/", "lookup by promptId");

        assert(state.bindPromptUi(pending.promptId, { mode: "window", id: 42 }), "bind window ok");
        assert(!state.bindPromptUi(pending.promptId, { mode: "window", id: undefined }), "reject missing id");
        state.clearPendingByWindowId(42);
        assert(!state.hasPendingPrompt("a.com", "localhost:1"), "window close clears pending");
    }
    {
        const state = createSelectiveAllowState();
        const pending = state.createPendingPrompt({
            origin: "b.com",
            destination: "localhost:2",
            originalUrl: "http://localhost:2/a",
            navigationTabId: 1,
        });
        state.updatePendingNavigation("b.com", "localhost:2", {
            originalUrl: "http://localhost:2/b",
            navigationTabId: 9,
        });
        assertEqual(
            state.getPendingByPromptId(pending.promptId)?.originalUrl,
            "http://localhost:2/b",
            "pending url updated"
        );
        assertEqual(
            state.getPendingByPromptId(pending.promptId)?.navigationTabId,
            9,
            "pending tab updated"
        );
    }
    {
        const state = createSelectiveAllowState();
        const pending = state.createPendingPrompt({
            origin: "c.com",
            destination: "localhost:3",
            originalUrl: "http://localhost:3/",
        });
        assert(state.bindPromptUi(pending.promptId, { mode: "tab", id: 9 }), "bind tab ok");
        state.clearPendingByUiTabId(9);
        assert(!state.hasPendingPrompt("c.com", "localhost:3"), "ui tab close clears pending");
    }
    {
        const state = createSelectiveAllowState();
        state.allowInSession("a.com", "localhost:1");
        assert(state.isSessionAllowed("a.com", "localhost:1"), "session allowed");
        state.revokeSessionAllow("a.com", "localhost:1");
        assert(!state.isSessionAllowed("a.com", "localhost:1"), "session revoked");
    }
    {
        const state = createSelectiveAllowState();
        const first = state.createPendingPrompt({
            origin: "d.com",
            destination: "localhost:4",
            originalUrl: "http://localhost:4/a",
        });
        const second = state.createPendingPrompt({
            origin: "d.com",
            destination: "localhost:4",
            originalUrl: "http://localhost:4/b",
        });
        assertEqual(state.pendingSize, 1, "only one pending per pair");
        assertEqual(state.getPendingByPromptId(first.promptId), undefined, "old promptId invalidated");
        assertEqual(
            state.getPendingByPromptId(second.promptId)?.originalUrl,
            "http://localhost:4/b",
            "new prompt wins"
        );
    }
}
