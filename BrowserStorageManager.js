/* The storage mutex allows us to prevent multiple updates to local storage at the same time. Requests to local storage from this file execute in a FIFO order. */
let storageMutex = Promise.resolve();

/**
 * **Use getItemFromLocal for files outside of this one.**
 * Private function to fetch an item from local storage. This function is NOT locked to the storageMutex.
 * 
 * @param {string} item Key of the item to fetch from local storage
 * @param {any} defaultValue Default value to return if the item is not found in local storage
 * @returns {any} The item from local storage or the default value if the item is not found
 */
async function _getItemFromLocalGuts(item, defaultValue) {
  const result = await browser.storage.local.get(item);
  try {
    return item in result ? JSON.parse(result[item]) : defaultValue;
  } catch {
    return defaultValue;
  }
}
/**
 * Gets an item from local storage.
 * This function is locked to the storageMutex to prevent overwriting data.
 * 
 * @param {string} item Key of the item to fetch from local storage
 * @param {any} defaultValue Default value to return if the item is not found in local storage
 * @returns {any} The item from local storage or the default value if the item is not found
 */
async function getItemFromLocal(item, defaultValue) {
  return storageMutex = storageMutex.then(async () => {
    const result = await _getItemFromLocalGuts(item, defaultValue);
    return result;
  });
}

/**
 * **Use setItemInLocal for files outside of this one.**
 * Private function to set an item in local storage. This function is NOT locked to the storageMutex.
 * 
 * @param {string} key Key of the item to fetch from local storage
 * @param {any} value The value to set the item to in local storage
 * @returns void
 */
async function _setItemInLocalGuts(key, value) {
  return browser.storage.local.set({
    [key]: JSON.stringify(value)
  });
}
/**
 * Sets an item in local storage. 
 * This function is locked to the storageMutex to prevent overwriting data.
 * 
 * @param {string} key Key of the item to fetch from local storage
 * @param {any} value The value to set the item to in local storage
 * @returns void
 */
async function setItemInLocal(key, value) {
  return storageMutex = storageMutex.then(async () => {
    await _setItemInLocalGuts(key, value);
  });
}

/**
 * Adds the host and port of the provided url to a list of hosts and ports that were blocked from port scanning.
 * 
 * @param {string} tabId Id the of the browser tab the port check was executed in
 * @param {URL} url URL object built from the url of the tab associated with the tabID
 */
const addBlockedPortToHost = async (url, tabIdString) => {
  return storageMutex = storageMutex.then(async () => {
    const tabId = parseInt(tabIdString);
    const host = url.host.split(":")[0];
    const port = "" + (url.port || getPortForProtocol(url.protocol));

    // Grab the blocked ports object from extensions storage
    const blocked_ports = await _getItemFromLocalGuts("blocked_ports", {});

    // Grab the array of ports blocked for the host url
    const tab_hosts = blocked_ports[tabId] || {};
    let hosts_ports = tab_hosts[host];
    if (Array.isArray(hosts_ports)) {
      // Add the port to the array of blocked ports for this host IFF the port doesn't exist
      if (hosts_ports.indexOf(port) === -1) {
        hosts_ports = tab_hosts[host].concat([port]);
        tab_hosts[host] = hosts_ports;
        blocked_ports[tabId] = tab_hosts;
        await _setItemInLocalGuts("blocked_ports", blocked_ports);
      }

    } else {
      tab_hosts[host] = [port];
      blocked_ports[tabId] = tab_hosts;
      await _setItemInLocalGuts("blocked_ports", blocked_ports);
    }
  });
}


/**
 * Adds the host and port of the provided url to a list of hosts and ports that were blocked from port scanning.
 * 
 * @param {string} tabId Id the of the browser tab the port check was executed in
 * @param {URL} url URL object built from the url of the tab associated with the tabID
 */
async function addBlockedTrackingHost(url, tabIdString) {
  return storageMutex = storageMutex.then(async () => {
    const tabId = parseInt(tabIdString);
    const host = url.host;

    const blocked_hosts_tabs = await _getItemFromLocalGuts("blocked_hosts", {});

    let blocked_hosts = blocked_hosts_tabs[tabId] || [];

    if (blocked_hosts.indexOf(host) === -1) {
      blocked_hosts = blocked_hosts.concat([host]);
    }

    blocked_hosts_tabs[tabId] = blocked_hosts;

    await _setItemInLocalGuts("blocked_hosts", blocked_hosts_tabs);
  })
}

/**
 * Increases the badged by one.
 * Borrowed and modified from https://gitlab.com/KevinRoebert/ClearUrls/-/blob/master/core_js/badgedHandler.js
 */
async function increaseBadge(request, isThreatMetrix) {
  return storageMutex = storageMutex.then(async () => {
    // Error check
    if (request === null) return;

    const tabId = request.tabId;
    const url = request.url;
    const badges = await _getItemFromLocalGuts("badges", {});

    if (tabId === -1) return;

    if (badges[tabId] == null) {
      badges[tabId] = {
        counter: 1,
        alerted: 0,
        lastURL: url
      };
    } else {
      badges[tabId].counter += 1;
    }
    // Update badge text
    browser.browserAction.setBadgeText({
      text: (badges[tabId]).counter.toString(),
      tabId: tabId
    }).catch();

    // Update notification alerted status
    if (badges[tabId].alerted === 0 && await _getItemFromLocalGuts("notificationsAllowed", true)) {
      badges[tabId].alerted += 1;
      if (isThreatMetrix) {
        notifyThreatMetrix(new URL(request.originUrl).host);
      } else {
        notifyPortScanning(new URL(request.originUrl).host);
      }
    }

    await _setItemInLocalGuts("badges", badges);
  });
}


