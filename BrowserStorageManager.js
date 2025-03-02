// TODO remove these eventually, that they're needed is a sign of bad code encapsulation
import { updateBadges, notifyThreatMetrix, notifyPortScanning } from "./browserActions.js";
import { getPortForProtocol } from "./constants.js";

// Key required to access the same lock that's used to control write access to localStorage
const STORAGE_LOCK_KEY = "port_authority_storage_lock";

/**
 * @private
 * @param {string} key - Used to reference stored value from `browser.storage.local`
 * @param {any} [default_value] - Will be returned if there is no value in storage under `key`
 * @returns {Promise<any>} Type is probably the same as `default_value` due to convention yet isn't checked or guaranteed at all
 * 
 * @remarks
 * Doesn't have any atomicity or transaction guarantees like the exported functions do.
 * Need to use a lock to prevent race conditions like:
 * 
 *      1. (trying to execute A++: read A=1 here)
 *      2. [A=5 written from other location]
 *      3. (write A++ based on old value, A=2, != 6 to reflect latest data) 
 * 
 * Also it's {@link https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/storage#:~:text=values%20stored%20can%20be%20any%20JSON%2Difiable%20value | likely} 
 * that `JSON.stringify` can be abandoned and was never needed in the first place, extension `storage` access supports types other than strings by default.
 * 
 * @see {@linkcode getItemFromLocal} For lock-safe storage reading version
 * @see {@linkcode modifyItemInLocal} If you need to change a value in addition to reading it (safely)
 */
async function UNLOCKED_getItemFromLocal(key, default_value) {
    let storage_value;
    try {
        storage_value = await browser.storage.local.get(key);

        // Objects not in storage return an empty object and don't need to be parsed as JSON
        if(Object.keys(storage_value).length === 0) {
            console.warn("No value found for [" + key + "], using provided default: ", {
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
 * @param {string} key - Used to reference stored value from `browser.storage.local`
 * @param {any} [default_value] - Will be returned if there is no value in storage under `key`
 * @returns {Promise<any>} Type is probably the same as `default_value` due to convention yet isn't checked or guaranteed at all
 * 
 * @remarks
 * Don't need `exclusive` lock for reading, just writing and modifying.
 * *Do* still need `shared` lock to prevent reading in the middle of a modify action.
 * 
 * @see {@linkcode modifyItemInLocal} If you need to change a value in addition to reading it
 * @see {@linkcode UNLOCKED_getItemFromLocal} For the lock-free function this wraps
 */
export async function getItemFromLocal(key, default_value) {
    return navigator.locks.request(STORAGE_LOCK_KEY,
        { mode: "shared" }, // allows for simultaneous reads that are guaranteed to not occur in the middle of a `modifyItemInLocal` call
        async (lock) => {
            const value = await UNLOCKED_getItemFromLocal(key, default_value);
            console.debug("Reading storage:", {[key]: value});
            return value;
        }
    );
}

/**
 * @template T
 * @param {string} key Used to reference stored value from `browser.storage.local`
 * @param {T} value Stored blindly, overwrites any previous value
 * @returns {Promise<T>} Resolves once operation is finished, returning the new stored value
 * 
 * @see {@linkcode modifyItemInLocal} If you need to read a value, mutate it, then save it (with transaction safety)
 * @see {@linkcode clearItemsInLocal} To clear and set all stored values at once
 */
export async function setItemInLocal(key, value) {
    if (!value && value !== false) console.warn("Storing empty value to key [" + key + "]: " + value);

    const stringifiedValue = JSON.stringify(value);

    // Acquire lock for write access before updating
    return navigator.locks.request(STORAGE_LOCK_KEY, async (lock) => {
        await browser.storage.local.set({ [key]: stringifiedValue });
        console.debug("Setting storage:", {[key]: value});
        return value;
    });
}

/**
 * @template T
 * @param {string} key Used to reference stored value from `browser.storage.local`
 * @param {T} default_value Will be passed as the original value to `mutate` if nothing is found in storage
 * @param {(original_value: T)=>(T | Promise<T>)} mutate Pass a function that takes the stored value and returns the new value to write. Function can be async.
 * @returns {Promise<T>} Resolves once operation is finished, returning the new stored value
 * 
 * @example
 * // Starting storage state: `{key_example: 1}`
 * modifyItemInLocal("key_example", 0, (v)=>v++) 
 * // Result storage state:  `{key_example: 2}`
 * 
 * @example
 * modifyItemInLocal("key", [],
 *     async (storageValue) => {   // storageValue: string[]
 *         // Storage access is locked until the function returns
 *         // no reads or writes can interrupt it
 * 
 *         storageValue.push("new item");
 *         storageValue.sort();
 * 
 *         return storageValue;    // returned value will be written to storage
 * });
 * 
 * @remarks
 * Need to use a lock to allow atomic and reliable modification of stored values.
 * Without locking, race conditions can occur.
 *
 *      1. (trying to execute A++: read A=1 here)
 *      2. [A=5 written from other location]
 *      3. (write A++ based on old value, A=2, != 6 to reflect latest data) 
 */
export async function modifyItemInLocal(key, default_value, mutate) {
    return navigator.locks.request(STORAGE_LOCK_KEY, async (lock) => {
        // Fetch the value to be modified, storing it in `initial_value`
        const initial_value = await UNLOCKED_getItemFromLocal(key, default_value);

        // Apply the mutation function (adding a list item, removing an element based on a filter, etc)
        const new_value = await mutate(initial_value);

        // Re-stringify and save the changed value
        await browser.storage.local.set({
            [key]: JSON.stringify(new_value)
        }); 

        console.debug("Updating storage value: ", key, {
            ["old " + key]: initial_value,
            ["new " + key]: new_value
        });
        
        // Return result of modification so can use later
        return new_value;
    });
}

/**
 * @param {{[key: string]: any}} [default_structure] Specify initial storage values to be written after clearing.
 * The object will be `JSON.stringify`'d transparently, so complex objects can be used.
 * @returns {Promise<{[key: string]: any}>} Resolves once operation is finished, returning the new stored values
 * 
 * @example
 * clearItemsInLocal({
 *     "allowed_domain_list": [],
 *     "blocking_enabled": true,
 *     "notifications_enabled": true
 * });
 * 
 * @remarks
 * Need to obtain the lock to guarantee a clean slate, otherwise
 * could be called in the middle of `modifyItemInLocal` running, clear the store,
 * then the interrupted `modifyItemInLocal` saves its work and overwrites the cleared values.
 */
export async function clearItemsInLocal(default_structure = {}) {
    // Stringify each the value for each key instead of passing directly
    // https://stackoverflow.com/a/14810722/3196151
    // This might not be necessary, matching prior practices for now though
    // https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/storage#:~:text=values%20stored%20can%20be%20any%20JSON%2Difiable%20value
    const default_structure_stringified =
        Object.fromEntries(Object.entries(default_structure).map(
            ([key, value]) =>
                [key, JSON.stringify(value)]
        ));

    console.debug("Clearing local storage with default values:", {
        passed: default_structure,
        parsed: default_structure_stringified
    })

    // Acquire lock for write access before clearing
    return navigator.locks.request(STORAGE_LOCK_KEY, async (lock) => {
        await browser.storage.local.clear();
        await browser.storage.local.set(
            default_structure_stringified
        );

        // Return the values set
        return default_structure;
    });
}





/**
 * Adds the host and port of the provided url to a list of hosts and ports that were blocked from port scanning.
 * 
 * @param {URL} url URL object built from the url of the tab associated with the tabID
 * @param {string} tabId Id the of the browser tab the port check was executed in
 */
export async function addBlockedPortToHost(url, tabIdString) {
    const tabId = parseInt(tabIdString);
    const host = url.host.split(":")[0]; // TODO replace with more robust method to get host, this might act funky around IPv6 addresses
    const port = "" + (url.port || getPortForProtocol(url.protocol));

    // Grab the blocked ports object from extensions storage
    return modifyItemInLocal("blocked_ports", {}, (blocked_ports) => {
        // Grab the array of ports blocked for the host url
        const tab_hosts = blocked_ports[tabId] || {};
        let hosts_ports = tab_hosts[host];
        if (Array.isArray(hosts_ports)) {
            // Add the port to the array of blocked ports for this host IFF the port doesn't exist
            if (hosts_ports.indexOf(port) === -1) {
                hosts_ports = tab_hosts[host].concat([port]);
                tab_hosts[host] = hosts_ports;
                blocked_ports[tabId] = tab_hosts;
            }
        } else {
            tab_hosts[host] = [port];
            blocked_ports[tabId] = tab_hosts;
        }
        return blocked_ports;
    });
}

/**
 * Adds the host and port of the provided url to a list of hosts and ports that were blocked from port scanning.
 * 
 * @param {URL} url URL object built from the url of the tab associated with the tabID
 * @param {string} tabId Id the of the browser tab the port check was executed in
 */
export async function addBlockedTrackingHost(url, tabIdString) {
    const tabId = parseInt(tabIdString);
    const host = url.host;

    return modifyItemInLocal("blocked_hosts", {}, (blocked_hosts_tabs) => {
        let blocked_hosts = blocked_hosts_tabs[tabId] || [];

        if (blocked_hosts.indexOf(host) === -1) {
            blocked_hosts = blocked_hosts.concat([host]);
        }

        blocked_hosts_tabs[tabId] = blocked_hosts;

        return blocked_hosts_tabs;
    });
}
/**
 * Increases the badged by one.
 * Borrowed and modified from https://gitlab.com/KevinRoebert/ClearUrls/-/blob/master/core_js/badgedHandler.js
 */
export async function increaseBadge(request, isThreatMetrix) {
    const tabId = request?.tabId;
    const url = request?.url;

    // Error checking for invalid request
    if (!request || tabId === -1) {
        console.error('Invalid `request` passed to increaseBadge:', {request, isThreatMetrix});
        return;
    };

    // Actual badge update
    return modifyItemInLocal("badges", {}, async (badges) => {
        // Initialize badge info for the tab if empty
        if (!badges[tabId]) {
            badges[tabId] = {
                counter: 0,
                alerted: 0,
                lastURL: url
            };
        }

        // Update badge number
        badges[tabId].counter += 1;

        // TODO better separate concerns between storage related things and browser actions
        // Update badge text
        updateBadges(badges[tabId].counter, tabId);

        // TODO better separate concerns between storage related things and browser actions
        // Update notification alerted status
        const notifications_enabled = await UNLOCKED_getItemFromLocal("notificationsAllowed", true);
        if (badges[tabId].alerted === 0 && notifications_enabled) {
            badges[tabId].alerted += 1;
            if (isThreatMetrix) {
                notifyThreatMetrix(new URL(request.originUrl).host);
            } else {
                notifyPortScanning(new URL(request.originUrl).host);
            }
        }

        return badges;
    });
}
