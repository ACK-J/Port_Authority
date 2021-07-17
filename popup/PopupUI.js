// content-script.js
"use strict";
const SECTION_HEADER_ELEMENT = "h5";

function buildSectionWrapper() {
    const section_wrapper = document.createElement("div");
    section_wrapper.classList.add("col-12", "d-flex", "flex-column");
    return section_wrapper;
}

/**
 * Displays a list of blocked ports in the popup UI.
 * Data is re-rendered each time the popup is opened.
 */
async function updateBlockedPortsDisplay() {
    // Grab the blocked ports from the extensions local storage.
    const blocked_ports_object = await browser.storage.local.get({ "blocked_ports": {} });
    const blocked_ports_string = blocked_ports_object.blocked_ports;

    const blocked_data_display = document.getElementById("blocked_data_display");
    // Create a wrapper element to hold the header and list of blocked hosts
    const all_ports_wrapper = document.createElement("div");

    // Build the header/title element for this section
    const all_ports_header = document.createElement(SECTION_HEADER_ELEMENT);
    all_ports_header.innerHTML = "Blocked ports";

    // Add the header to the blocked hosts wrapper element
    all_ports_wrapper.appendChild(all_ports_header);


    if (blocked_ports_string) {
        try {
            const blocked_ports = JSON.parse(blocked_ports_string);

            const hosts = Object.keys(blocked_ports);
            const all_hosts_display = buildSectionWrapper();

            // build a tree for each host that was blocked
            for (let i_host = 0; i_host < hosts.length; i_host++) {
                // Build the wrapper for displaying the host name and ports blocked
                const host = hosts[i_host];
                const hosts_wrapper = document.createElement("div");
                const host_display = document.createElement("h6");
                host_display.innerHTML = host;
                hosts_wrapper.appendChild(host_display);

                // build the list of blocked ports then append it to the wrapper
                const hosts_ul = document.createElement("ul");
                hosts_ul.classList.add("list-unstyled");

                const ports = blocked_ports[hosts[i_host]];

                for (let i_port = 0; i_port < ports.length; i_port++) {
                    const port = ports[i_port];
                    const port_element = document.createElement("li");
                    port_element.innerHTML = port;
                    port_element.classList.add("pl-1")
                    hosts_ul.appendChild(port_element);
                }

                hosts_wrapper.appendChild(hosts_ul);
                all_hosts_display.appendChild(hosts_wrapper);
            }

            blocked_data_display.innerHTML = "";
            blocked_data_display.appendChild(all_hosts_display);
        } catch {

        }
    }
}

async function updateBlockedHostsDisplay() {

    // grab the list of blocked hosts from extension storage
    const blocked_hosts_object = await browser.storage.local.get({ "blocked_hosts": {} });
    const blocked_hosts_string = blocked_hosts_object.blocked_hosts;

    // Create a wrapper element to hold the header and list of blocked hosts
    const hosts_wrapper = buildSectionWrapper();

    // Build the header/title element for this section
    const host_header = document.createElement(SECTION_HEADER_ELEMENT);
    host_header.innerHTML = "Blocked hosts";

    // Add the header to the blocked hosts wrapper element
    hosts_wrapper.appendChild(host_header);

    // create the UL element to hold all the blocked hosts
    const hosts_ul = document.createElement("ul");
    hosts_ul.classList.add("list-unstyled");

    try {
        // Data is stored as a valid JSON string, parse the data into an array (blocked hosts should be an array of domains)
        const blocked_hosts = JSON.parse(blocked_hosts_string);

        // Build a list of host names as li elements
        for (let host = 0; host < blocked_hosts.length; host++) {
            //Grab the host name
            const host_name = blocked_hosts[host];

            // Create the list element for the blocked host and set the text to the hosts name
            const host_li = document.createElement("li");
            host_li.innerHTML = host_name;

            // Add the list element to the hosts UL
            hosts_ul.appendChild(host_li);
        }

    } 
    // Something went wrong, empty the ul to be safe
    catch(error) {
        console.log(error);
        hosts_ul.innerHTML = "";
    }
    // Add the list of blocked hosts to the wrapper containing the section header
    hosts_wrapper.appendChild(hosts_ul);

    // Append the list of blocked ports to the Popups blocked_data_display section
    const blocked_data_display = document.getElementById("blocked_data_display");
    blocked_data_display.appendChild(hosts_wrapper);
}

// Helper function for calling all DOM-Modifying functions
function showBlockedData() {
    // Shows any and all ports that were blocked from scanning. Ports are sorted based on host that attempted the port scan
    updateBlockedPortsDisplay();
    // Shows any and all hosts that attempted to connect to a tracking service
    updateBlockedHostsDisplay();
}

showBlockedData();
