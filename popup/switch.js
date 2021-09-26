function toggleEnabled(ev){
  browser.runtime.sendMessage({type: 'toggleEnabled', value: ev.target.checked});
}

function setNotificationsAllowed(ev){
  browser.runtime.sendMessage({type: 'setNotificationsAllowed', value: ev.target.checked});
}

browser.runtime.sendMessage({type: 'popupInit'}).then((response) => {
  document.getElementById("globalStatusPortAuthority").checked = response.isListening;

  // Add an event listener to the switch
  document.getElementById('globalStatusPortAuthority').addEventListener("change", toggleEnabled);


  document.getElementById("notificationStatusPortAuthority").checked = response.notificationsAllowed;

  // Add an event listener to the switch
  document.getElementById('notificationStatusPortAuthority').addEventListener("change", setNotificationsAllowed);


  // Make sure this doesn't run too early
  setTimeout(() => document.documentElement.classList.remove('loading'), 0);
});
