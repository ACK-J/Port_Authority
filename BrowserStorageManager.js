// Key required to access the same lock that's used to control write access to localStorage
const storage_lock_key = "port_authority_storage_lock";

// Don't need lock for reading, just writing and modifying
export async function getItemFromLocal(key, default_value) {
    const value_from_storage = await browser.storage.local.get({ [key]: default_value });
    console.debug("Reading storage: " + key);

    try {
        return JSON.parse(value_from_storage[key]);
    } catch {
        console.error("Error parsing storage value ["+key+"]: ", value_from_storage, "Using default value: ", default_value);
        return default_value;
    }
}

export async function setItemInLocal(key, value) {
    if(!value) console.warn("Storing empty value to key ["+key+"]: ", value);

    const stringifiedValue = JSON.stringify(value);
    console.debug("Setting storage: ", {[key]: value})

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
            console.error("Error parsing storage value [" + key + "]: ", value_from_storage, "Using default value: ", default_value);
        }

        // Apply the modification function (adding a list item, removing an element based on a filter, etc)
        const new_value = modification(initial_value);

        // Re-stringify and save the changed value
        await browser.storage.local.set({
            [key]: JSON.stringify(new_value)
        }); 

        console.debug("Modified stored value ["+key+"]:", {
            old: initial_value,
            new: new_value
        });
    });
}

export async function clearLocalItems(default_structure = {}) {
    // Stringify each the value for each key instead of passing directly
    // https://stackoverflow.com/a/14810722/3196151
    // This might not be necessary, matching prior practices for now though
    // https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/storage#:~:text=values%20stored%20can%20be%20any%20JSON%2Difiable%20value
    const default_structure_stringified =
        Object.fromEntries(Object.entries(default_structure).map(
            ([key, value]) =>
                [key, JSON.stringify(value)]
        ));

    console.debug("clearing local storage with default values: ", {
        passed: default_structure,
        parsed: default_structure_stringified
    })

    // Acquire lock for write access before clearing
    await navigator.locks.request(storage_lock_key, async (lock) => {
        await browser.storage.local.clear();
        await browser.storage.local.set(
            default_structure_stringified
        );
    });

    console.debug("new state: ", browser.storage.local.get())
}
