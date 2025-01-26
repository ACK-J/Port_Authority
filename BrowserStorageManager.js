let storageMutex = Promise.resolve();

async function getItemFromLocal(item, defaultValue) {
  return storageMutex = storageMutex.then(async () => {
    const result = await browser.storage.local.get(item);
    try {
      return item in result ? JSON.parse(result[item]) : defaultValue;
    } catch {
      return defaultValue;
    }
  });
}

async function setItemInLocal(key, value) {
  return storageMutex = storageMutex.then(async () => {
    await browser.storage.local.set({
      [key]: JSON.stringify(value)
    });
  });
}

async function clearLocalItems() {
  return browser.storage.local.clear();
}