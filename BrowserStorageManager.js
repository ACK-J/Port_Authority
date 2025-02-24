let storageMutex = Promise.resolve();

async function _getItemFromLocalGuts(item, defaultValue) {
  const result = await browser.storage.local.get(item);
  try {
    return item in result ? JSON.parse(result[item]) : defaultValue;
  } catch {
    return defaultValue;
  }
}
async function getItemFromLocal(item, defaultValue) {
  return storageMutex = storageMutex.then(async () => {
    const result = await _getItemFromLocalGuts(item, defaultValue);
    return result;
  });
}


async function _setItemInLocalGuts(key, value) {
  return browser.storage.local.set({
    [key]: JSON.stringify(value)
  });
}
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



async function clearLocalItems() {
  return storageMutex = storageMutex.then(async () => {
    await browser.storage.local.clear();
  });
}