// content-script.js
"use strict";
const SECTION_HEADER_ELEMENT = "h5";

//TODO Fix this copied function, want to use `BrowserStorageManager` instead
async function getItemFromLocal(key, default_value) {
    let storage_value = null;
    try {
        storage_value = await browser.storage.local.get(key);

        // Objects not in storage don't need to be parsed as JSON
        if (storage_value === null) {
            console.warn("No value found for [" + key + "], using default: ", {
                [key]: default_value
            });
            return default_value;
        }

        // Everything going to plan
        return JSON.parse(storage_value[key]);
    } catch (error) {
        console.error("Error getting storage value [" + key + "]: ", {
            error,
            default_value,
            storage_value
        });

        // Still degrading gracefully by returning the default value
        return default_value;
    }
}

/**
 * Applies an object of variable_name: variable_value as attributes to a provided DOM element.
 *
 * @param {element} element The element to add data attributes to
 * @param {object} attributes An object of all values to add
 */
const setAttributesOnElement = (element, attributes) => {
    // Grab the list of attribute names to add
    const attribute_names = Object.keys(attributes);

    // For each attribute, add the name and value to the elements attributes
    for (let i = 0; i < attribute_names.length; i++) {
        const attribute = attribute_names[i];
        element.setAttribute(attribute, attributes[attribute]);
    }
};

function buildSectionWrapper() {
    const section_wrapper = document.createElement("div");
    section_wrapper.classList.add("col-12", "d-flex", "flex-column");
    return section_wrapper;
}

/**
 * Generates markup for a bootstrap collapse element.
 * The collapse has a title with a btn-link on the opposite side
 * <div>
 *  <div class="d-flex justify-content-between">
 *      <h6>collapse_title</h5>
 *      <button>toggle_text</button>
 *  </div>
 * </div>
 *
 * @param {string} data_target ID of the collapse element used for the toggles data target.
 * @param {string} collapse_title Title of the collapse element
 * @param {string} toggle_text Text for the toggle button
 * @returns {element} A collapse Wrapper with a button to toggle the collapse
 */
function buildCollapseWrapperAndToggle(
    data_target,
    collapse_title,
    toggle_text
) {
    // Wrapper to hold the title, toggle, and collapse element
    const collapse_wrapper = document.createElement("div");
    const title_toggle_wrapper = document.createElement("div");

    // Wrapper to hold the title and toggle button
    title_toggle_wrapper.classList.add(
        "d-flex",
        "justify-content-between",
        "align-items-center"
    );

    // Title of the collapse
    const title_element = document.createElement("h6");
    title_element.innerText = collapse_title;
    title_element.classList.add("bold-text");
    title_toggle_wrapper.appendChild(title_element);

    // Collpase toggle button
    const collapse_toggle_button = document.createElement("button");

    collapse_toggle_button.innerText = toggle_text;
    const collapse_attributes = {
        type: "button",
        class: "btn btn-link",
        "data-bs-target": `#${data_target}`,
        "data-bs-toggle": "collapse",
        "aria-expanded": false,
        "aria-controls": data_target,
    };
    setAttributesOnElement(collapse_toggle_button, collapse_attributes);
    title_toggle_wrapper.appendChild(collapse_toggle_button);

    collapse_wrapper.appendChild(title_toggle_wrapper);

    return collapse_wrapper;
}

/**
 * Displays a list of blocked ports in the popup UI.
 * Data is re-rendered each time the popup is opened.
 */
async function updateBlockedPortsDisplay() {
    let querying = await browser.tabs.query({
        currentWindow: true,
        active: true,
    });
    const tab = querying[0];
    const tabId = tab.id;

    const blocked_data_display = document.getElementById(
        "blocked_data_display"
    );
    // Create a wrapper element to hold the header and list of blocked hosts
    const all_ports_wrapper = buildSectionWrapper();

    // Build the header/title element for this section
    const all_ports_header = document.createElement(SECTION_HEADER_ELEMENT);
    all_ports_header.innerText = "Blocked Port Scans:";
    all_ports_header.classList.add("bold-text");

    // Add the header to the blocked hosts wrapper element
    all_ports_wrapper.appendChild(all_ports_header);

    // Grab the blocked ports from the extensions local storage.
    const blocked_ports_tabs = await getItemFromLocal("blocked_ports", {});

    if (Object.entries(blocked_ports_tabs).length === 0) {
        // Nothing to render
        return;
    }

    const blocked_ports = blocked_ports_tabs[tabId] || {};

    const hosts = Object.keys(blocked_ports);

    // build a tree for each host that was blocked
    for (let i_host = 0; i_host < hosts.length; i_host++) {
        // Build the wrapper for displaying the host name and ports blocked
        const host = hosts[i_host];
        const host_id = `host${i_host}`;
        const host_wrapper = buildCollapseWrapperAndToggle(
            host_id,
            host,
            "View Ports"
        );

        // build the list of blocked ports then append it to the wrapper
        const hosts_ul = document.createElement("div");
        hosts_ul.id = host_id;
        hosts_ul.classList.add("list-unstyled", "collapse");

        const ports = blocked_ports[hosts[i_host]];

        // Add each port to the HTML
        for (let i_port = 0; i_port < ports.length; i_port++) {
            const port = ports[i_port];
            const port_element = document.createElement("div");
            port_element.innerText = port;
            port_element.classList.add("ps-2");
            hosts_ul.appendChild(port_element);
        }

        host_wrapper.appendChild(hosts_ul);
        all_ports_wrapper.appendChild(host_wrapper);
    }

    blocked_data_display.appendChild(all_ports_wrapper);

    // Append the header to the GUI
    const blocked_data_display_ports = document.getElementById(
        "blocked_data_display"
    );
    blocked_data_display_ports.appendChild(all_ports_wrapper);
}

async function updateBlockedHostsDisplay() {
    let querying = await browser.tabs.query({
        currentWindow: true,
        active: true,
    });
    const tab = querying[0];
    const tabId = tab.id;

    // grab the list of blocked hosts from extension storage

    // Create a wrapper element to hold the header and list of blocked hosts
    const hosts_wrapper = buildSectionWrapper();

    // Build the header/title element for this section
    const host_header = document.createElement(SECTION_HEADER_ELEMENT);
    host_header.innerText = "Blocked Tracking Scripts:";
    host_header.classList.add("bold-text");

    // Add the header to the blocked hosts wrapper element
    hosts_wrapper.appendChild(host_header);

    // create the UL element to hold all the blocked hosts
    const hosts_ul = document.createElement("ul");
    hosts_ul.classList.add("list-unstyled");

    try {
        const blocked_hosts_tabs = await getItemFromLocal(
            "blocked_hosts",
            {}
        );
        const blocked_hosts = blocked_hosts_tabs[tabId] || [];

        // Build a list of host names as li elements
        for (let host = 0; host < blocked_hosts.length; host++) {
            //Grab the host name
            const host_name = blocked_hosts[host];

            // Create the list element for the blocked host and set the text to the hosts name
            const host_li = document.createElement("li");
            host_li.classList.add("ps-2", "brand-text-color", "bold-text");
            host_li.innerText = host_name;

            // Add the list element to the hosts UL
            hosts_ul.appendChild(host_li);
        }
    } catch (error) {
        // Something went wrong, empty the ul to be safe
        hosts_ul.innerText = "";
    }
    // Add the list of blocked hosts to the wrapper containing the section header
    hosts_wrapper.appendChild(hosts_ul);

    // Append the list of blocked hosts to the Popups blocked_data_display section
    const blocked_data_display = document.getElementById(
        "blocked_data_display"
    );
    blocked_data_display.appendChild(hosts_wrapper);
}

// Helper function for calling all DOM-Modifying functions
function buildDataMarkup() {
    // Shows any and all hosts that attempted to connect to a tracking service
    updateBlockedHostsDisplay();
    // Shows any and all ports that were blocked from scanning. Ports are sorted based on host that attempted the port scan
    updateBlockedPortsDisplay();
}

buildDataMarkup();
