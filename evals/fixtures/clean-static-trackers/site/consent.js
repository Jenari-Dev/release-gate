// Cookie consent banner. The analytics tracker is only injected after an explicit "accept".
(function () {
  var TRACKER = 'http://127.0.0.1:3156/tracker.js';
  var banner = document.getElementById('consent-banner');

  function loadTracker() {
    var s = document.createElement('script');
    s.src = TRACKER;
    document.head.appendChild(s);
  }

  function choose(choice) {
    try { localStorage.setItem('consent', choice); } catch (e) {}
    banner.style.display = 'none';
    if (choice === 'accept') loadTracker();
  }

  var stored = null;
  try { stored = localStorage.getItem('consent'); } catch (e) {}
  if (stored) {
    banner.style.display = 'none';
    if (stored === 'accept') loadTracker();
  }
  document.getElementById('consent-accept').addEventListener('click', function () { choose('accept'); });
  document.getElementById('consent-reject').addEventListener('click', function () { choose('reject'); });
})();
