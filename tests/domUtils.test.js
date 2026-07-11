import { createElement } from "../global/domUtils.js";
import { suite, assert, assertEqual, installDocumentMock } from "./harness.js";

export async function run() {
    installDocumentMock();

    suite("createElement basics");
    {
        const el = createElement("div");
        assertEqual(el.tagName, "DIV", "creates element with tag");
        assertEqual(el.childNodes.length, 0, "no children by default");
    }
    {
        const el = createElement("span", null, "hello");
        assertEqual(el.childNodes.length, 1, "single text child");
        assertEqual(el.childNodes[0], "hello", "text content preserved");
    }

    suite("createElement attributes");
    {
        const el = createElement("button", {
            class: ["unselectable", "warning-text"],
            "aria-label": "Remove domain",
        });
        assertEqual(el.getAttribute("class"), "unselectable warning-text", "class array joined");
        assertEqual(el.getAttribute("aria-label"), "Remove domain", "aria-label set");
    }
    {
        const el = createElement("div", { className: "three" });
        assertEqual(el.getAttribute("class"), "three", "className aliased to class");
    }
    {
        const el = createElement("input", { type: "checkbox", checked: "true" });
        assertEqual(el.getAttribute("type"), "checkbox", "type attr");
        assertEqual(el.getAttribute("checked"), "true", "checked attr");
    }

    suite("createElement nested children");
    {
        const child = createElement("em", {}, "added");
        const el = createElement("span", {}, ["no", "spaces", child]);
        assertEqual(el.childNodes.length, 3, "three children");
        assertEqual(el.childNodes[0], "no", "first child string");
        assertEqual(el.childNodes[2], child, "nested element child");
    }
    {
        // Mirrors allowlist remove button structure
        const item = createElement("li", {}, [
            "example.com",
            " ",
            createElement("button", { class: "unselectable", "aria-label": "Remove 'example.com' from allowlist" }, "✕"),
        ]);
        assertEqual(item.tagName, "LI", "list item tag");
        assertEqual(item.childNodes.length, 3, "domain, space, button");
        assertEqual(item.childNodes[2].tagName, "BUTTON", "button child");
        assertEqual(item.childNodes[2].getAttribute("aria-label"), "Remove 'example.com' from allowlist", "button label");
    }

    suite("createElement blocked-ports popup structure");
    {
        const expansion = createElement("label", { class: ["ports-expansion-toggle", "unselectable"] }, [
            createElement("input", { type: "checkbox" }),
            "2 ports",
        ]);
        const ports = createElement("ul", { class: "ports-expansion-target" }, [
            createElement("li", { class: "port" }, "22"),
            createElement("li", { class: "port" }, "80"),
        ]);
        const container = createElement("li", { class: "blocked-host-item" }, [
            createElement("span", { class: "host" }, "127.0.0.1"),
            expansion,
            ports,
        ]);
        assertEqual(container.childNodes.length, 3, "host + toggle + ports");
        assertEqual(ports.childNodes.length, 2, "two ports listed");
        assert(expansion.getAttribute("class").includes("unselectable"), "toggle classes applied");
    }
}
