import { start, stop } from "../background.js";

function toggleEnabled(e){
  let state = localStorage.getItem("state");
  // If the function is on
  if (state == "true"){
    stop();
    //document.getElementById('globalStatusPortAuthority').click();
    console.log("Stopped");
    //e.preventDefault();
    return;
  }else{ 
    start();
    //document.getElementById('globalStatusPortAuthority').click();
    console.log("Started");
    //e.preventDefault();
    return;
  }
}
function checkIfEnabled(){
  // Check the storage to see the position of the toggle
  let check = localStorage.getItem("status");
  // Returns either true or false 
  let position = document.getElementById("globalStatusPortAuthority").checked;
  // If the function of the addon and the toggle are mis-matched, click it
  if (check != position){
    document.getElementById("globalStatusPortAuthority").click();
  }
}


checkIfEnabled();

// Add an event listener to the switch
document.getElementById('globalStatusPortAuthority').addEventListener("click", toggleEnabled);
