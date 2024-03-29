function toggleEnabled(ev){
  browser.runtime.sendMessage({type: 'toggleEnabled', value: ev.target.checked});
}

function setNotificationsAllowed(ev){
  browser.runtime.sendMessage({type: 'setNotificationsAllowed', value: ev.target.checked});
}

function settingsClicked(ev){
  browser.runtime.openOptionsPage();
}

browser.runtime.sendMessage({type: 'popupInit'}).then((response) => {
  document.getElementById("globalStatusPortAuthority").checked = response.isListening;

  // Add an event listener to the switch
  document.getElementById('globalStatusPortAuthority').addEventListener("change", toggleEnabled);


  document.getElementById("notificationStatusPortAuthority").checked = response.notificationsAllowed;

  // Add an event listener to the switch
  document.getElementById('notificationStatusPortAuthority').addEventListener("change", setNotificationsAllowed);

  // Change to settings page
  document.getElementById('settings').addEventListener("click", settingsClicked);

  // Make sure this doesn't run too early
  setTimeout(() => document.documentElement.classList.remove('loading'), 5);
});
