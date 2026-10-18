// Cookie consent banner. Remembers the visitor's choice and hides the banner.
(function () {
  var banner = document.getElementById('consent-banner');
  function choose(choice) {
    try { localStorage.setItem('consent', choice); } catch (e) {}
    banner.style.display = 'none';
  }
  var stored = null;
  try { stored = localStorage.getItem('consent'); } catch (e) {}
  if (stored) banner.style.display = 'none';
  document.getElementById('consent-accept').addEventListener('click', function () { choose('accept'); });
  document.getElementById('consent-reject').addEventListener('click', function () { choose('reject'); });
})();
