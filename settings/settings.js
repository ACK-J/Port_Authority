import { getItemFromLocal, modifyItemInLocal } from "../global/BrowserStorageManager.js";
import { createElement } from "../global/domUtils.js";

/**
 * A single item in the allowlist display
 * @param {string} domain Technically a `URL.host` aka domain + port
 * @param {AbortSignal} abort_signal Signal to kill the 'remove' button listeners when rerendering the table
 * @returns {Element}
 * ```html
 * <li>
 *     {domain}
 *     <button onclick="{remove & refresh display}"
 *             class="unselectable"
 *             aria-label="Remove {domain} from allowlist">
 *         ✕
 *     </button>
 * </li>
 * ```
 */
function allowed_domain_item(domain, abort_signal) {
    /** The listener for the "Remove domain" button's onclick. Removes the current domain from the list and refreshes the display */
    const remove_domain_listener = () => {
        modifyItemInLocal("allowed_domain_list", [],
            (list) => list.filter(
                (d) => d !== domain
            )).then(
                /* Reuse the updated value to re-render the display */
                (list) => load_allowed_domains(list)
            );
    }

    // Main container, the domain is inserted as plain text with a space
    const item = createElement("li", {}, [domain, " "]);

    // Button to remove the domain from the allowlist
    const remove_button = createElement("button", {class: "unselectable", "aria-label": `Remove '${domain}' from allowlist`}, "✕");
    remove_button.addEventListener("click", remove_domain_listener, {signal: abort_signal}); // By triggering `remove_buttons_event_controller.abort()`, all buttons with this signal passed will have their listeners removed
    item.appendChild(remove_button);

    return item;
}

let remove_buttons_event_controller;
const list_contents = document.getElementById("allowlist_contents");
const allowlist_section = document.getElementById("allowlist_section");
async function load_allowed_domains(allowed_domain_list) {
    // Remove all of the stale listeners
    // TODO figure out if this is needed, unsure since calling `replaceChildren` could do listener cleanup on the deleted children
    if (remove_buttons_event_controller) remove_buttons_event_controller.abort();

    // Make a new AbortController for all of the fresh buttons
    remove_buttons_event_controller = new AbortController();

    // If not provided, fetch the allowed domain list from storage
    allowed_domain_list ??= await getItemFromLocal("allowed_domain_list", []);

    // Clear stale contents, if any
    list_contents.replaceChildren();

    // Early return, hiding wrapper if no data provided
    if(allowed_domain_list?.length === 0) {
        allowlist_section.setAttribute("hidden", "");
        return;
    }

    // Populate the list items
    for(const domain of allowed_domain_list) {
        const new_row = allowed_domain_item(domain, remove_buttons_event_controller.signal);

        list_contents.appendChild(new_row);
    };

    // Unhide the container wrapper at end
    allowlist_section.removeAttribute("hidden");
}

/**
 * Get a well-formed host to match against from an user-supplied URL
 * @param {string} url A URL-like value (eg `https://example.com/file/path/etc`, `discord.com/invite/abcdefg`, `example.com:8080`)
 * @returns {string} Well formatted host portion of url (eg `example.com`, `discord.com`, `example.com:8080`)
 * 
 * @throws Parsing an invalid URL
 */
function extractURLHost(url) {
    // Leading/trailing whitespace removal
    url = url.trim();

    // We don't actually care about the protocol as we only compare url.host
    // But the URL object will fail to create if no protocol is provided
    if (!url.match(/^\w*:\/\//)) {
        url = "http://" + url;
    }
    const newUrl = new URL(url);
    return newUrl.host;
}

// Allowlist add form bindings
const allowlist_add_form = document.getElementById("allowlist_add_form");
function allowlist_add_listener(event) {
    // Prevent the form submit event from reloading the page and hiding `alert`s used for feedback
    event.preventDefault();

    const form_url = allowlist_add_form.elements["add_domain"];
    let url = form_url.value;
    try {
        url = extractURLHost(url);
    } catch(error) {
        console.warn("Error parsing a domain to add to the allowlist:", {url, error});
        alert("Please enter a valid domain.");
        return;
    }
    
    // Clear the URL input box
    form_url.value = "";

    // Update and rerender the list
    modifyItemInLocal("allowed_domain_list", [],
        (list) => {
            // Only update the list if it's a new member
            if (!list.includes(url)) {
                return list.concat(url);
            } else {
                alert("This domain is already in the list.");
                return list;
            }
        }).then(
            /* Reuse the updated value to re-render the display */
            (list) => load_allowed_domains(list)
        );
}
allowlist_add_form.addEventListener("submit", allowlist_add_listener);

load_allowed_domains();
