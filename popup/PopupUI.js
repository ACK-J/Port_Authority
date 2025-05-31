import { getItemFromLocal } from "../global/BrowserStorageManager.js";
import { getActiveTabId } from "../global/browserActions.js";
import { createElement } from "../global/domUtils.js";

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

/**
 * An item in the popup display for "Blocked Port Scans"
 * @param {string} host The LAN hostname/IP that was accessed
 * @param {string[]} ports Which port(s) were scanned
 * @returns {Element} An element that represents a portscanned domain and the ports that were scanned, structured as follows
 * 
 * ```html
 * <li class="blocked-host-item">
 *     <span class="host">{host}</span>
 *     <label class="ports-expansion-toggle unselectable">
 *         <input type="checkbox">
 *         View Ports
 *     </label>
 *     <ul class="ports-expansion-target">
 *         <li class="port">{ports[0]}</li>
 *         {<li class="port">{ports[1]}</li>...}
 *     </ul>
 * </li>
 * ```
 */
function blocked_ports_item(host, ports) {
    const container = createElement("li", {class: "blocked-host-item"});

    // The host/domain itself
    const host_span = createElement("span", {class: "host"}, host);
    container.appendChild(host_span);

    // No ports case: return early and warn
    if (ports.length === 0) {
        console.warn("No port supplied when rendering blocked portscans for '" + host + "'");

        return container;
    }

    // Put low-number privileged ports first in the list
    ports.sort((a, b)=>(+a - +b));

    /**"View Ports" toggle
     * 
     * Collapse/expand functionality is added with CSS.
     * Wrapping `<label>` instead of placing it after the checkbox to avoid having to set a unique id on each input.
     */
    const expansion_toggle = createElement("label", {class: ["ports-expansion-toggle", "unselectable"]},
        [
            createElement("input", {type: "checkbox"}),
            "View Ports"
        ]
    );
    container.appendChild(expansion_toggle);

    // Expandable container for the ports list
    const ports_ul = createElement("ul", {class: "ports-expansion-target"});
    for (const port of ports) {
        ports_ul.append(
            createElement("li", {class: "port"}, port),
        );
    }
    container.appendChild(ports_ul);

    // Item finally fully populated
    return container;
}

/**
 * An item in the popup dispay for "Blocked Tracking Scripts"
 * @param {string} host A threatmetrix domain that got blocked
 * @returns {Element} A `<li>` wrapping the host string
 */
function blocked_hosts_item(host) {
    return createElement("li", {}, host);
}

// Populate `#blocked_ports`
const blocked_ports_wrapper = document.getElementById("blocked_ports");
const blocked_ports_contents = blocked_ports_wrapper.querySelector(".dropzone");
async function load_blocked_ports(blocked_ports_object) {
    // If not provided, fetch the data from storage
    blocked_ports_object ??= await fetch_tabs_blocking_data("blocked_ports");

    // Clear stale contents, if any
    blocked_ports_contents.replaceChildren();

    // Early return, hiding wrapper if no data provided
    if(!blocked_ports_object || Object.keys(blocked_ports_object).length === 0) {
        blocked_ports_wrapper.setAttribute("hidden", "");
        return;
    }

    // Populate the list items
    for(const host in blocked_ports_object) {
        const item = blocked_ports_item(host, blocked_ports_object[host]);

        blocked_ports_contents.appendChild(item);
    };

    // Unhide the container wrapper at end
    blocked_ports_wrapper.removeAttribute("hidden");

    // Read and pass the in-DOM height for animation of the collapsible ports lists
    // This can be removed once Firefox supports `interpolate-size: allow-keywords`,
    // `height: auto` will work as a final animation value then.
    blocked_ports_contents.querySelectorAll(".ports-expansion-target").forEach((expansion_container) => {
        expansion_container.style = `--expanded-height: ${expansion_container.scrollHeight}px`;    
    });
}

// Populate `#blocked_hosts`
const blocked_hosts_wrapper = document.getElementById("blocked_hosts");
const blocked_hosts_contents = blocked_hosts_wrapper.querySelector('.dropzone');
async function load_blocked_hosts(blocked_hosts_list) {
    // If not provided, fetch the data from storage
    blocked_hosts_list ??= await fetch_tabs_blocking_data("blocked_hosts");

    // Clear stale contents, if any
    blocked_hosts_contents.replaceChildren();

    // Early return, hiding wrapper if no data provided
    if(!blocked_hosts_list || blocked_hosts_list.length === 0) {
        blocked_hosts_wrapper.setAttribute("hidden", "");
        return;
    }

    // Populate the list items
    for(const host of blocked_hosts_list) {
        const item = blocked_hosts_item(host);

        blocked_hosts_contents.appendChild(item);
    };

    // Unhide the container wrapper at end
    blocked_hosts_wrapper.removeAttribute("hidden");
}

// TODO live rerendering on data change, could use storage event coordinating as discussed in issue #50: https://github.com/ACK-J/Port_Authority/issues/50
load_blocked_ports();
load_blocked_hosts();
