import { getItemFromLocal } from "../global/BrowserStorageManager.js";
import { getActiveTabId } from "../global/browserActions.js";

/**
 * Data fetching only, separated from rendering logic
 * @param {"blocked_ports" | "blocked_hosts"} data_type Which storage key to extract the blocking activity data from
 */
async function fetch_tabs_blocking_data(data_type) {
    // TODO rework this when flipping data structure as discussed in issue #47: https://github.com/ACK-J/Port_Authority/issues/47
    const all_tabs_data = await getItemFromLocal(data_type, {});
    if (Object.keys(all_tabs_data).length === 0) return;

    const tab_id = await getActiveTabId();
    return all_tabs_data[tab_id];
}

const SECTION_HEADER_ELEMENT = "h2";

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
    const blocked_ports = fetch_tabs_blocking_data("blocked_ports");

    // Early return if no data
    if (!blocked_ports) return;

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
        const blocked_hosts = fetch_tabs_blocking_data("blocked_hosts") || [];

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
