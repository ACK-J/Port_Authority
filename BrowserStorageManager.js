// Key required to access the same lock that's used to control write access to localStorage
const storage_lock_key = "port_authority_storage_lock";

export async function getItemFromLocal(item, default_value) {
    const value_from_storage = await browser.storage.local.get({ [item]: default_value });

    try {
        return JSON.parse(value_from_storage[item]);
    } catch {
        return default_value;
    }
}

export async function setItemInLocal(key, value) {
    const stringifiedValue = JSON.stringify(value);

    // Acquire lock for write access before updating
    navigator.locks.request(storage_lock_key, async (lock) => {
        await browser.storage.local.set({ [key]: stringifiedValue });
    });
}

export async function clearLocalItems() {
    // Acquire lock for write access before clearing
    navigator.locks.request(storage_lock_key, async (lock) => {
        await browser.storage.local.clear();
    });
}
