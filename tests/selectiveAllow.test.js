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
        assertEqual(
            originAllowKey(new URL("blob:https://example.com/uuid-1")),
            "blob:https://example.com/uuid-1",
            "blob uses full href"
        );
        assert(
            originAllowKey(new URL("blob:https://example.com/uuid-1")) !==
                originAllowKey(new URL("blob:https://example.com/uuid-2")),
            "blob keys are not collapsed to protocol only"
        );
        assertEqual(
            originAllowKey(new URL("about:blank")),
            "about:blank",
            "about:blank keyed fully"
        );
        assertEqual(
            originAllowKey(new URL("data:text/html,hi")),
            null,
            "data: URLs are not selective-allowed"
        );
        assertEqual(originAllowKey(null), null, "non-URL rejected");
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
        const result = validatePendingAllow({
            origin: "evil.example",
            destination: "localhost:8080",
            originalUrl: "https://evil.example/phish",
        });
        assert(!result.ok, "rejects remote originalUrl");
        assertEqual(result.reason, "destination-mismatch", "destination-mismatch reason");
    }
    {
        const result = validatePendingAllow(null);
        assert(!result.ok, "rejects missing pending");
        assertEqual(result.reason, "missing-pending", "missing-pending reason");
    }

    suite("createSelectiveAllowState");
    {
        const state = createSelectiveAllowState();
        const first = state.ensurePendingPrompt({
            origin: "a.com",
            destination: "localhost:1",
            originalUrl: "http://localhost:1/a",
            navigationTabId: 5,
        });
        assert(first.created, "first ensure creates");
        assert(state.hasPendingPrompt("a.com", "localhost:1"), "pending marked");
        assertEqual(state.pendingSize, 1, "one pending");

        const second = state.ensurePendingPrompt({
            origin: "a.com",
            destination: "localhost:1",
            originalUrl: "http://localhost:1/b",
            navigationTabId: 9,
        });
        assert(!second.created, "second ensure updates");
        assertEqual(second.pending.promptId, first.pending.promptId, "same promptId kept");
        assertEqual(second.pending.originalUrl, "http://localhost:1/b", "url updated");
        assertEqual(second.pending.navigationTabId, 9, "tab updated");
        assertEqual(state.pendingSize, 1, "still one pending");

        assert(state.bindPromptUi(first.pending.promptId, { mode: "window", id: 42 }), "bind window ok");
        assert(!state.bindPromptUi(first.pending.promptId, { mode: "window", id: undefined }), "reject missing id");
        state.clearPendingByWindowId(42);
        assert(!state.hasPendingPrompt("a.com", "localhost:1"), "window close clears pending");
    }
    {
        const state = createSelectiveAllowState();
        const { pending } = state.ensurePendingPrompt({
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
}
