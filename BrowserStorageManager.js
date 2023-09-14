let updating_storage = false;

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function getItemFromLocal(item, default_value) {
    while (updating_storage) {
        await sleep(500);
    }
    const value_from_storage = await browser.storage.local.get({ [item]: default_value });

    try{
        return JSON.parse(value_from_storage[item]);
    }catch {
        return default_value;
    }
}

async function setItemInLocal(key, value) {
    while (updating_storage) {
        await sleep(500);
    }
    updating_storage = true;
    const stringifiedValue = JSON.stringify(value);
    await browser.storage.local.set({ [key]: stringifiedValue });
    updating_storage = false;
    return;
}

async function clearLocalItems() {
    while (updating_storage) {
        await sleep(500);
    }
    updating_storage = true;
    await browser.storage.local.clear();
    updating_storage = false;
    return;
}
