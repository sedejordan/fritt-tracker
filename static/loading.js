// Fixes the frozen loading screen
window.addEventListener("pageshow", function (e) {
  if (e.persisted) {
    const overlay = document.getElementById("loading-overlay");
    const ring = document.getElementById("loading-ring");
    overlay.classList.add("hidden");
    overlay.classList.remove("flex");
    ring.style.strokeDashoffset = "81.68";
  }
});

// Shows the branded loading overlay for anything that leaves the current
// page: a form submit, or clicking a link to another page on this site.
document.addEventListener("DOMContentLoaded", function () {
  const overlay = document.getElementById("loading-overlay");
  const ring = document.getElementById("loading-ring");

  function showLoading() {
    overlay.classList.remove("hidden");
    overlay.classList.add("flex");
    requestAnimationFrame(function () {
      ring.style.strokeDashoffset = "0";
    });
  }

  document.querySelectorAll("form").forEach(function (form) {
    // Skip forms with 'no-loading' class (delete confirm dialogs)
    if (form.classList.contains('no-loading')) {
      return;
    }
    
    form.addEventListener("submit", function () {
      if (form.checkValidity()) {
        showLoading();
      }
    });
  });

  document.querySelectorAll('a[href^="/"]').forEach(function (link) {
    if (link.hasAttribute('download')) {
      return;
    }

    link.addEventListener("click", function (e) {
      if (e.defaultPrevented) {
        return;
      }
      if (!e.metaKey && !e.ctrlKey && !e.shiftKey) {
        showLoading();
      }
    });
  });
});