/**
 * Unit tests for Selective Allow helpers (issue #57).
 */
import {
    makeAllowKey,
    originAllowKey,
    sanitizeSelectiveAllowPage,
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
        assertEqual(
            originAllowKey(new URL("file:///tmp/b.html")),
            "file:///tmp/b.html",
            "different files get different keys"
        );
        assert(
            originAllowKey(new URL("file:///tmp/a.html")) !==
                originAllowKey(new URL("file:///tmp/b.html")),
            "file keys are not collapsed to protocol only"
        );
    }

    suite("sanitizeSelectiveAllowPage");
    {
        assertEqual(
            sanitizeSelectiveAllowPage(),
            "selectiveAllow.html",
            "default page allowed"
        );
        assertEqual(
            sanitizeSelectiveAllowPage("localRequest.html"),
            "localRequest.html",
            "simple basename allowed"
        );
        assertEqual(
            sanitizeSelectiveAllowPage("../settings/settings.html"),
            null,
            "path traversal rejected"
        );
        assertEqual(
            sanitizeSelectiveAllowPage("foo/bar.html"),
            null,
            "nested path rejected"
        );
        assertEqual(
            sanitizeSelectiveAllowPage("not-html.js"),
            null,
            "non-html rejected"
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
        assertEqual(valid.destination, "localhost:8080", "destination from pending");
        assertEqual(valid.tabId, 7, "navigationTabId preferred");
        assertEqual(valid.parsedUrl.host, "localhost:8080", "parsed host");
    }
    {
        const valid = validatePendingAllow(
            {
                origin: "docs.example",
                destination: "192.168.1.10",
                originalUrl: "https://192.168.1.10/",
            },
            "12"
        );
        assert(valid.ok, "falls back to message tabId");
        assertEqual(valid.tabId, 12, "string tabId coerced");
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
        const mismatched = validatePendingAllow({
            origin: "github.com",
            destination: "localhost:9090",
            originalUrl: "http://localhost:8080/",
        });
        assert(!mismatched.ok, "rejects destination/host mismatch");
        assertEqual(mismatched.reason, "destination-mismatch", "host mismatch reason");
    }
    {
        const result = validatePendingAllow({
            origin: "github.com",
            destination: "localhost:8080",
            originalUrl: "not a url",
        });
        assert(!result.ok, "rejects unparseable originalUrl");
        assertEqual(result.reason, "unparseable-url", "unparseable reason");
    }
    {
        const result = validatePendingAllow({
            origin: "",
            destination: "localhost:8080",
            originalUrl: "http://localhost:8080/",
        });
        assert(!result.ok, "rejects empty origin");
        assertEqual(result.reason, "invalid-pending", "invalid-pending reason");
    }
    {
        const result = validatePendingAllow(
            {
                origin: "github.com",
                destination: "localhost:8080",
                originalUrl: "http://localhost:8080/",
            },
            -1
        );
        assert(!result.ok, "rejects negative tabId");
        assertEqual(result.reason, "invalid-tabId", "invalid-tabId reason");
    }
    {
        const result = validatePendingAllow(null);
        assert(!result.ok, "rejects missing pending");
        assertEqual(result.reason, "missing-pending", "missing-pending reason");
    }

    suite("createSelectiveAllowState");
    {
        const state = createSelectiveAllowState();
        assert(!state.isSessionAllowed("a.com", "localhost:1"), "starts empty");
        assert(!state.hasPendingPrompt("a.com", "localhost:1"), "no pending yet");

        const pending = state.createPendingPrompt({
            origin: "a.com",
            destination: "localhost:1",
            originalUrl: "http://localhost:1/",
            navigationTabId: 5,
        });
        assert(state.hasPendingPrompt("a.com", "localhost:1"), "pending marked");
        assertEqual(state.pendingSize, 1, "one pending");
        assert(typeof pending.promptId === "string" && pending.promptId.length > 0, "promptId issued");
        assertEqual(
            state.getPendingByPromptId(pending.promptId)?.originalUrl,
            "http://localhost:1/",
            "lookup by promptId"
        );

        state.bindPromptUi(pending.promptId, { mode: "window", id: 42 });
        state.clearPendingByWindowId(42);
        assert(!state.hasPendingPrompt("a.com", "localhost:1"), "window close clears pending");
        assertEqual(state.getPendingByPromptId(pending.promptId), undefined, "promptId gone after window close");
    }
    {
        const state = createSelectiveAllowState();
        const pending = state.createPendingPrompt({
            origin: "b.com",
            destination: "localhost:2",
            originalUrl: "http://localhost:2/",
        });
        state.bindPromptUi(pending.promptId, { mode: "tab", id: 9 });
        state.clearPendingByUiTabId(9);
        assert(!state.hasPendingPrompt("b.com", "localhost:2"), "ui tab close clears pending");
    }
    {
        const state = createSelectiveAllowState();
        const pending = state.createPendingPrompt({
            origin: "c.com",
            destination: "localhost:3",
            originalUrl: "http://localhost:3/",
        });
        state.clearPendingByPromptId(pending.promptId);
        assert(!state.hasPendingPrompt("c.com", "localhost:3"), "promptId clear works");
    }
    {
        const state = createSelectiveAllowState();
        state.allowInSession("a.com", "localhost:1");
        assert(state.isSessionAllowed("a.com", "localhost:1"), "session allowed");
        assertEqual(state.sessionSize, 1, "one session allow");
        assert(!state.isSessionAllowed("a.com", "localhost:2"), "other destination not allowed");
    }
    {
        // Replacing a pending prompt for the same pair drops the old promptId.
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
