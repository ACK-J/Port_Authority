import { getItemFromLocal, modifyItemInLocal } from "../global/BrowserStorageManager.js";

let remove_buttons_event_controller;
async function load_allowed_domains() {
    // Remove all of the stale listeners (might not need this since calling `replaceChildren` should kill all the children's listeners, but better safe than sorry)
    if (remove_buttons_event_controller) remove_buttons_event_controller.abort();

    // Make a new AbortController for all of the fresh buttons
    remove_buttons_event_controller = new AbortController();
    const signal = remove_buttons_event_controller.signal;

    const allowedDomainsList = await getItemFromLocal(
        "allowed_domain_list",
        []
    );

    // Results in a list of `<li>domain.com <button onclick="remove & refresh UI">Remove</button></li>`
    const domainListDomElements = allowedDomainsList.map((domain) => {
        const listItem = document.createElement("li");
        listItem.innerText = domain + " ";

        const button = document.createElement("button");
        button.innerText = "Remove";
        button.addEventListener("click", async () => {
            // Remove the current domain from the list
            await modifyItemInLocal("allowed_domain_list", [],
                (list) => list.filter(
                    (d) => d !== domain
                ));

            // Refresh the domain list displayed
            load_allowed_domains();
        }, { signal }); // By triggering `remove_buttons_event_controller.abort()`, all buttons with this signal passed will have their listeners removed
        listItem.appendChild(button);

        return listItem;
    });

    // Override the old list with the new contents
    const listContainerElement = document.getElementById("allowedDomainsListID");
    listContainerElement.replaceChildren(...domainListDomElements);
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
