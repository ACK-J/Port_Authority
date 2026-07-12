import { getItemFromLocal, modifyItemInLocal } from "../global/BrowserStorageManager.js";
import { createElement } from "../global/domUtils.js";
import { normalizeAllowlistEntry } from "../global/allowlist.js";

/**
 * A single item in the allowlist display
 * @param {string} domain Technically a `URL.host` aka domain + port
 * @param {AbortSignal} abort_signal Signal to kill the 'remove' button listeners when rerendering the table
 * @returns {Element}
 * ```html
 * <li>
 *     <span class="domain">{domain}</span>
 *     <button onclick="{remove & refresh display}"
 *             class="unselectable"
 *             aria-label="Remove {domain} from allowlist">
 *         ✕
 *     </button>
 * </li>
 * ```
 */
function allowlist_item(domain, abort_signal) {
    /** The listener for the "Remove domain" button's onclick. Removes the current domain from the list and refreshes the display */
    const remove_domain_listener = () => {
        modifyItemInLocal("allowed_domain_list", [],
            (list) => list.filter(
                (d) => d !== domain
            )).then(
                /* Reuse the updated value to re-render the display */
                (list) => load_allowlist(list)
            );
    }

    const item = createElement("li", {}, [
        createElement("span", {class: "domain"}, domain),
        createElement("button", {class: "unselectable", "aria-label": `Remove '${domain}' from allowlist`}, "✕"),
    ]);

    const remove_button = item.querySelector("button");
    remove_button.addEventListener("click", remove_domain_listener, {signal: abort_signal}); // By triggering `remove_buttons_event_controller.abort()`, all buttons with this signal passed will have their listeners removed

    return item;
}

// Populate `#allowlist_section`
let remove_buttons_event_controller;
const allowlist_wrapper = document.getElementById("allowlist_section");
const allowlist_contents = document.getElementById("allowlist_contents");
async function load_allowlist(allowed_domain_list) {
    // Drop prior remove-button listeners before rebuilding the list.
    if (remove_buttons_event_controller) remove_buttons_event_controller.abort();
    remove_buttons_event_controller = new AbortController();

    // If not provided, fetch the allowed domain list from storage
    allowed_domain_list ??= await getItemFromLocal("allowed_domain_list", []);

    // Clear stale contents, if any
    allowlist_contents.replaceChildren();

    // Early return, hiding wrapper if no data provided
    if(allowed_domain_list?.length === 0) {
        allowlist_wrapper.setAttribute("hidden", "");
        return;
    }

    // Populate the list items
    for(const domain of allowed_domain_list) {
        const new_row = allowlist_item(domain, remove_buttons_event_controller.signal);

        allowlist_contents.appendChild(new_row);
    };

    // Unhide the container wrapper at end
    allowlist_wrapper.removeAttribute("hidden");
}

// Allowlist add form bindings
const allowlist_add_form = document.getElementById("allowlist_add_form");
function allowlist_add_listener(event) {
    // Prevent the form submit event from reloading the page and hiding `alert`s used for feedback
    event.preventDefault();

    const form_url = allowlist_add_form.elements["add_domain"];
    let url = form_url.value;
    try {
        url = normalizeAllowlistEntry(url);
    } catch(error) {
        console.warn("Error parsing an allowlist entry:", {url, error});
        alert("Please enter a valid domain, IP address, or CIDR range.");
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
                alert("This entry is already in the list.");
                return list;
            }
        }).then(
            /* Reuse the updated value to re-render the display */
            (list) => load_allowlist(list)
        );
}
allowlist_add_form.addEventListener("submit", allowlist_add_listener);

load_allowlist();
