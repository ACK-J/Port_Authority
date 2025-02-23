// Key required to access the same lock that's used to control write access to localStorage
const storage_lock_key = "port_authority_storage_lock";

// Don't need lock for reading, just writing and modifying
export async function getItemFromLocal(item, default_value) {
    const value_from_storage = await browser.storage.local.get({ [item]: default_value });
    console.log("reading storage: " + item)
    try {
        return JSON.parse(value_from_storage[item]);
    } catch {
        return default_value;
    }
}

export async function setItemInLocal(key, value) {
    const stringifiedValue = JSON.stringify(value);
    console.log("setting storage: ", {[key]: value})
    // Acquire lock for write access before updating
    await navigator.locks.request(storage_lock_key, async (lock) => {
        await browser.storage.local.set({ [key]: stringifiedValue });
    });
}

// Modifying a value requires locking write access for the entire time from the read until the item is written again
// Need to do this to avoid race condition: (trying to execute A++: read A=1 here) [A=5 written from other location] (write A++ based on old value, A=2, != 6) 
export async function modifyItemInLocal(key, default_value, modification) {
    await navigator.locks.request(storage_lock_key, async (lock) => {
        // Fetch the value to be modified, storing it in `initial_value` after parsing as JSON
        const value_from_storage = await browser.storage.local.get({ [key]: default_value });
        let initial_value = default_value;
        try {
            initial_value = JSON.parse(value_from_storage[key]);
        } catch {
            console.warn("Error parsing JSON for stored object ["+key+"]: ", value_from_storage[key]);
        }

        // Apply the modification function (adding a list item, removing an element based on a filter, etc)
        const new_value = modification(initial_value);

        // Re-stringify and save the changed value
        await browser.storage.local.set({
            [key]: JSON.stringify(new_value)
        }); 

        console.log("Modified stored value ["+key+"]:", {
            old: initial_value,
            new: new_value
        });
    });
}

export async function clearLocalItems() {
    // Acquire lock for write access before clearing
    await navigator.locks.request(storage_lock_key, async (lock) => {
        await browser.storage.local.clear();
    });
}
