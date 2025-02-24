import { getItemFromLocal, modifyItemInLocal } from "../BrowserStorageManager.js";

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

function extractURLHost(text) {
    let url = text + ""; // cast to string (is this needed?)

    // We don't actually care about the protocol as we only compare url.host
    // But the URL object will fail to create if no protocol is provided
    if (url.slice(0, 4) !== "http") {
        url = "https://" + url;
    }
    const newUrl = new URL(url);
    return newUrl.host;
}

async function saveOptions(e) {
    let url;
    try {
        url = extractURLHost(e.target[0].value);
    } catch(error) {
        console.error(error);
        alert("Please enter a valid domain.");
        return;
    }

    await modifyItemInLocal("allowed_domain_list", [],
        (list) => {
            // Only update the list if it's a new member
            if (!list.includes(url)) {
                return list.concat(url);
            } else {
                alert("This domain is already in the list.");
                return list;
            }
        });
}

load_allowed_domains();
document.querySelector("form").addEventListener("submit", saveOptions);
