import { getItemFromLocal, setItemInLocal } from "../global/BrowserStorageManager.js";

// Can attach settings page link instantly, no state reading needed
document.getElementById('settings').addEventListener("click", () =>
    browser.runtime.openOptionsPage());

// Blocking switch state bindings (wrapped in `.then()` to allow for parallel setup of notifications switch)
const blocking_switch = document.getElementById("blocking_switch");
const blocking_setup = getItemFromLocal("blocking_enabled", true).then((blocking_enabled) => {
    blocking_switch.checked = blocking_enabled;
    blocking_switch.addEventListener("change", (ev) =>
        browser.runtime.sendMessage({
            type: 'toggleEnabled',
            value: ev.target.checked
        }));
});

// Notifications switch state bindings
const notifications_switch = document.getElementById("notifications_switch");
const notifications_setup = getItemFromLocal("notificationsAllowed", true).then((notificationsAllowed) => {
    notifications_switch.checked = notificationsAllowed;
    notifications_switch.addEventListener("change", (ev) =>
        setItemInLocal("notificationsAllowed", ev.target.checked)
    );
});


// Clear the loading class that was disabling the slider animations when we were setting the initial values
Promise.allSettled([blocking_setup, notifications_setup]).then(() => {
    // Force the styles to be processed by calling a post-layout reliant function
    document.body.getBoundingClientRect();
    document.body.classList.remove("loading");
});
