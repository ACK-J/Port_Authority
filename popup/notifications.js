function notificationsEnabled(){
  browser.runtime.getBackgroundPage().then((bg) => {
    bg.toggleNotificationsAllowed();
  });
}

browser.runtime.getBackgroundPage().then((bg) => {
  document.getElementById("notificationStatusPortAuthority").checked = bg.isNotifying();

  // Add an event listener to the switch
  document.getElementById('notificationStatusPortAuthority').addEventListener("change", notificationsEnabled);

  // Make sure this doesn't run too early
  setTimeout(() => document.documentElement.classList.remove('loading'), 0);
});
