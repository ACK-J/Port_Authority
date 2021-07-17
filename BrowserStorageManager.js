let updating_storage = false;

async function getItemFromLocal(item, default_value) {
    while (updating_storage) {
        await sleep(500);
    }
    updating_storage = true;
    const value_from_storage = await browser.storage.local.get({ [item]: default_value });
    updating_storage = false;
    return value_from_storage;
}

async function setItemInLocal(key, value) {
    while (updating_storage) {
        await sleep(500);
    }
    updating_storage = true;
    await browser.storage.local.set({ [key]: JSON.stringify(value) });
    updating_storage = false;
    return;
}

async function clearLocal() {
    while (updating_storage) {
        await sleep(500);
    }
    updating_storage = true;
    await browser.storage.local.clear();
    updating_storage = false;
    return;
}