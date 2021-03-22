export var enabled = true;

function toggleEnabled(id) {
  enabled = !enabled;
  return;
}

document.addEventLisstener("click", function(e) {
  if (!e.target.classList.contains("slider")) {
    return;
  }

  toggleEnabled(id);

});





