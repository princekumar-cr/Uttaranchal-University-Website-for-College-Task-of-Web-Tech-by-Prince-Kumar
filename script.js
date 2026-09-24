/* =========================================================
   PROJECT : College Student Information Portal
   COLLEGE : Uttaranchal University
   FILE    : script.js  (SHARED JavaScript for all 4 pages)
   TECH    : Pure JavaScript, no libraries/frameworks
   PURPOSE : Adds two common features used on every page:
             1) Mobile hamburger menu (open/close the nav links)
             2) Scroll-to-top button (appears after scrolling)
   --------------------------------------------------------- */

/* "(function(){...})();" = Immediately Invoked Function Expression (IIFE).
   It runs the code right away but keeps all variables private,
   so nothing leaks into the global scope and pages never clash. */
(function () {
  /* --- Grab the elements we need from the HTML page --- */
  const hamburger = document.getElementById("hamburger"); // 3-line menu button
  const navLinks = document.getElementById("nav-links");  // the menu list
  const scrollTop = document.getElementById("scrollTop"); // up-arrow button

  /* ------------- 1) MOBILE HAMBURGER MENU ------------- */
  /* Only runs if the button and menu actually exist on this page. */
  if (hamburger && navLinks) {
    /* Every click on the hamburger toggles the "open" class.
       The CSS uses .open to slide the menu down on small screens. */
    hamburger.addEventListener("click", () => {
      navLinks.classList.toggle("open");
    });
  }

  /* ------------- 2) SCROLL-TO-TOP BUTTON ------------- */
  /* Only runs if the button exists on this page. */
  if (scrollTop) {
    /* Listen to the window scroll event... */
    window.addEventListener("scroll", () => {
      /* ...and show the button only after 400px of scrolling. */
      scrollTop.style.display = window.scrollY > 400 ? "block" : "none";
    });

    /* Clicking the button smoothly scrolls back to the top (y = 0). */
    scrollTop.addEventListener("click", () => {
      window.scrollTo({ top: 0, behavior: "smooth" });
    });
  }
})();