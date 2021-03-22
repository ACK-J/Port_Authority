const Background = require('../background.js');

let enabled = true;

function toggleEnabled() {
  if (enabled){
    Background.stop();
    enabled = false;
  }else{
    Background.start();
    enables = true;
  }
}

document.getElementById("ortAuthoritySlidingSwitch").addEventListener("click", toggleEnabled);





