import { start, stop } from "../background.js";

function toggleEnabled(e) {
  // Error check
  if (e === null){
    return;
  }
  // Check the storage to see the position of the toggle
  let checkPosition = localStorage.getItem("check");
  // If the function is on
  if (checkPosition == "true"){
    stop();
    console.log("Stopped");
    localStorage.removeItem('check');
    localStorage.setItem('check', false);
  }else{  // If the function is off
    start();
    console.log("Started");
    localStorage.removeItem('check');
    localStorage.setItem('check', true);
	if (Notification.permission !== "denied") {
	    Notification.requestPermission().then(function (permission) {
	      // If the user accepts, let's create a notification
	      if (permission === "granted") {
	        var notification = new Notification("Hi there!");
	      }
	    });
	}
  }
}

function checkIfEnabled(){
  // Check the storage to see the position of the toggle
  let check = localStorage.getItem("check");
  // Returns either true or false 
  let position = document.getElementById("PortAuthorityCheckbox").checked;
  // If the function of the addon and the toggle are mis-matched, click it
  if (check != position){
    document.getElementById("onOffSwitch").click();
  }
}

checkIfEnabled();
// Add an event listener to the switch
document.getElementById("PortAuthoritySlidingSwitch").addEventListener("click", toggleEnabled);




