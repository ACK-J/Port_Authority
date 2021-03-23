import { start, stop } from "../background.js";

let enabled = true;

function toggleEnabled(e) {
  if (e === null){
    return;
  }
  if (enabled){
    stop();
    console.log("Stopped");
    enabled = false;
  }else{
    start();
    console.log("Started");
    enabled = true;
  }
}

document.getElementById("PortAuthoritySlidingSwitch").addEventListener("click", toggleEnabled);



