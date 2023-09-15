function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function getItemFromLocal(item, default_value) {
    const value_from_storage = await browser.storage.local.get({ [item]: default_value });

    try{
        return JSON.parse(value_from_storage[item]);
    }catch {
        return default_value;
    }
}

async function lockStorage(){
    const stringifiedValue = JSON.stringify(true);
    await browser.storage.local.set({ [updating_storage]: stringifiedValue });
}

async function unlockStorage(){
    const stringifiedValue = JSON.stringify(false);
    await browser.storage.local.set({ [updating_storage]: stringifiedValue });
}

async function setItemInLocal(key, value) {
    var updating_storage = await getItemFromLocal('updating_storage', false);
    while (updating_storage) {
        await sleep(5);
    }
    await lockStorage();
    const stringifiedValue = JSON.stringify(value);
    await browser.storage.local.set({ [key]: stringifiedValue });
    await unlockStorage();
    return;
}

async function clearLocalItems() {
    var updating_storage = await getItemFromLocal('updating_storage', false);
    while (updating_storage) {
        await sleep(5);
    }
    await lockStorage();
    await browser.storage.local.clear();
    await unlockStorage();
    return;
}

async function startupStorage() {
    // Check if 'updating_storage' exists in local storage, otherwise set it to the default value (false)
    const storedUpdatingStorage = await getItemFromLocal('updating_storage', false);

    // If 'updating_storage' is not found in local storage, set it to the default value
    if (typeof storedUpdatingStorage === 'undefined') {
        await setItemInLocal('updating_storage', false);
    }
}

startupStorage();
