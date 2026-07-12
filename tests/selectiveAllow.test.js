/**
 * Unit tests for Selective Allow helpers (issue #57).
 */
import {
    makeAllowKey,
    sanitizeSelectiveAllowPage,
    listHasCrossOriginEntry,
    validateAllowDecision,
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

    suite("validateAllowDecision");
    {
        const valid = validateAllowDecision({
            origin: "github.com",
            destination: "localhost:8080",
            originalUrl: "http://localhost:8080/console",
            tabId: 7,
        });
        assert(valid.ok, "accepts local navigation with matching host");
        assertEqual(valid.origin, "github.com", "origin preserved");
        assertEqual(valid.destination, "localhost:8080", "destination preserved");
        assertEqual(valid.tabId, 7, "tabId preserved");
        assertEqual(valid.parsedUrl.host, "localhost:8080", "parsed host");
    }
    {
        const valid = validateAllowDecision({
            origin: "docs.example",
            destination: "192.168.1.10",
            originalUrl: "https://192.168.1.10/",
            tabId: "12",
        });
        assert(valid.ok, "accepts string tabId digits");
        assertEqual(valid.tabId, 12, "string tabId coerced");
    }
    {
        const result = validateAllowDecision({
            origin: "evil.example",
            destination: "localhost:8080",
            originalUrl: "https://evil.example/phish",
            tabId: 1,
        });
        assert(!result.ok, "rejects remote originalUrl that does not match destination");
        assertEqual(result.reason, "destination-mismatch", "destination-mismatch reason");
    }
    {
        const result = validateAllowDecision({
            origin: "evil.example",
            destination: "example.com",
            originalUrl: "https://example.com/",
            tabId: 1,
        });
        assert(!result.ok, "rejects non-local destination even when hosts match");
        assertEqual(result.reason, "not-local", "not-local reason");
    }
    {
        const result = validateAllowDecision({
            origin: "github.com",
            destination: "localhost:8080",
            originalUrl: "http://localhost:8080/",
            // destination host would match if URL were local:8080 — craft mismatch via host
        });
        // Force mismatch: destination claims localhost:9090
        const mismatched = validateAllowDecision({
            origin: "github.com",
            destination: "localhost:9090",
            originalUrl: "http://localhost:8080/",
        });
        assert(!mismatched.ok, "rejects when destination host differs from originalUrl");
        assertEqual(mismatched.reason, "destination-mismatch", "host mismatch reason");
        assert(result.ok, "control case without tabId still valid");
        assertEqual(result.tabId, undefined, "missing tabId is ok");
    }
    {
        const result = validateAllowDecision({
            origin: "github.com",
            destination: "localhost:8080",
            originalUrl: "not a url",
        });
        assert(!result.ok, "rejects unparseable originalUrl");
        assertEqual(result.reason, "unparseable-url", "unparseable reason");
    }
    {
        const result = validateAllowDecision({
            origin: "",
            destination: "localhost:8080",
            originalUrl: "http://localhost:8080/",
        });
        assert(!result.ok, "rejects empty origin");
        assertEqual(result.reason, "invalid-fields", "invalid-fields reason");
    }
    {
        const result = validateAllowDecision({
            origin: "github.com",
            destination: "localhost:8080",
            originalUrl: "http://localhost:8080/",
            tabId: -1,
        });
        assert(!result.ok, "rejects negative tabId");
        assertEqual(result.reason, "invalid-tabId", "invalid-tabId reason");
    }

    suite("createSelectiveAllowState");
    {
        const state = createSelectiveAllowState();
        assert(!state.isSessionAllowed("a.com", "localhost:1"), "starts empty");
        assert(!state.hasPendingPrompt("a.com", "localhost:1"), "no pending yet");

        state.markPendingPrompt("a.com", "localhost:1");
        assert(state.hasPendingPrompt("a.com", "localhost:1"), "pending marked");
        assertEqual(state.pendingSize, 1, "one pending");

        state.allowInSession("a.com", "localhost:1");
        state.clearPendingPrompt("a.com", "localhost:1");
        assert(state.isSessionAllowed("a.com", "localhost:1"), "session allowed");
        assert(!state.hasPendingPrompt("a.com", "localhost:1"), "pending cleared");
        assertEqual(state.sessionSize, 1, "one session allow");

        // Different destination is independent
        assert(!state.isSessionAllowed("a.com", "localhost:2"), "other destination not allowed");
    }
}
