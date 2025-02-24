// Key required to access the same lock that's used to control write access to localStorage
const STORAGE_LOCK_KEY = "port_authority_storage_lock";

/**
 * @private
 * @param {string} key - Used to reference stored value from `browser.storage.local`
 * @param {any} [default_value] - Will be returned if there is no value in storage under `key`
 * @returns {any} Type is probably the same as `default_value` due to convention yet isn't checked or guaranteed at all
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
 * @see `getItemFromLocal` For lock-safe storage reading version
 * @see `modifyItemInLocal` If you need to change a value in addition to reading it (safely)
 */
async function UNLOCKED_getItemFromLocal(key, default_value) {
    let storage_value;
    try {
        storage_value = await browser.storage.local.get(key);

        // Objects not in storage return an empty object and don't need to be parsed as JSON
        if(Object.keys(storage_value).length === 0) {
            console.warn("No value found for [" + key + "], using default: ", {
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
 * @returns {any} Type is probably the same as `default_value` due to convention yet isn't checked or guaranteed at all
 * 
 * @remarks
 * Don't need `exclusive` lock for reading, just writing and modifying.
 * *Do* still need `shared` lock to prevent reading in the middle of a modify action.
 * 
 * @see `modifyItemInLocal` If you need to change a value in addition to reading it
 * @see `UNLOCKED_getItemFromLocal` For the lock-free function this wraps
 */
export async function getItemFromLocal(key, default_value) {
    console.debug("Reading storage: " + key);

    return await navigator.locks.request(STORAGE_LOCK_KEY,
        { mode: "shared" }, // allows for simultaneous reads that are guaranteed to not occur in the middle of a `modifyItemInLocal` call
        async (lock) =>
            await UNLOCKED_getItemFromLocal(key, default_value)
    );
}

/**
 * @param {string} key Used to reference stored value from `browser.storage.local`
 * @param {any} value Stored blindly, overwrites any previous value
 * @returns {void}
 * 
 * @see `modifyItemInLocal` If you need to read a value, mutate it, then save it (with transaction safety)
 * @see `clearLocalItems` To clear and set all stored values at once
 */
export async function setItemInLocal(key, value) {
    if (!value) console.warn("Storing empty value to key [" + key + "]: " + value);

    const stringifiedValue = JSON.stringify(value);
    console.debug("Setting storage: ", {[key]: value})

    // Acquire lock for write access before updating
    await navigator.locks.request(STORAGE_LOCK_KEY, async (lock) =>
        await browser.storage.local.set({ [key]: stringifiedValue })
    );
}

/**
 * @template T
 * @param {string} key Used to reference stored value from `browser.storage.local`
 * @param {T} default_value Will be passed as the original value to `mutate` if nothing is found in storage
 * @param {(original_value: T)=>T} mutate Pass a function to be applied to the stored value
 * @returns {void}
 * 
 * @example
 * // Starting storage state: `{key_example: 1}`
 * // Result storage state:  `{key_example: 2}`
 * modifyItemInLocal("key_example", 0, (v)=>v++) 
 * 
 * @example
 * // Starting storage state: `{allowed_domain_list: ["google.com"]}`
 * // Result storage state:  `{allowed_domain_list: ["google.com", "example.com"]}`
 * modifyItemInLocal("allowed_domain_list", [],
 *     (list) => list.concat("example.com")
 * );
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
    await navigator.locks.request(STORAGE_LOCK_KEY, async (lock) => {
        // Fetch the value to be modified, storing it in `initial_value`
        const initial_value = await UNLOCKED_getItemFromLocal(key, default_value);

        // Apply the mutation function (adding a list item, removing an element based on a filter, etc)
        const new_value = await mutate(initial_value);

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

/**
 * @param {Map<string, any>} [default_structure] Used to set initial storage values.
 * The object will be `JSON.stringify`'d transparently, so complex objects can be used.
 * @returns {void}
 * 
 * @example
 * clearLocalItems({
 *     "allowed_domain_list": [],
 *     "blocking_enabled": true,
 *     "notifications_enabled": true
 * });
 * 
 * @remarks
 * Need to obtain the lock to guarantee a clean slate, otherwise
 * the write part of a `modifyItemInLocal` call could pollute it.
 */
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

    console.debug("Clearing local storage with default values: ", {
        passed: default_structure,
        parsed: default_structure_stringified
    })

    // Acquire lock for write access before clearing
    await navigator.locks.request(STORAGE_LOCK_KEY, async (lock) => {
        await browser.storage.local.clear();
        await browser.storage.local.set(
            default_structure_stringified
        );
    });
}
