## Base HTML layout — uses tux.css semantic elements.

import karax/[karaxdsl, vdom]

when defined(ssg):
  const basePath* = "/matchstick"
else:
  const basePath* = ""

proc layout*(title: string, content: VNode): string =
  const bp = basePath
  let page = buildHtml(html(lang="en")):
    head:
      meta(charset="utf-8")
      meta(name="viewport", content="width=device-width, initial-scale=1")
      title: text title & " — matchstick"
      link(rel="preconnect", href="https://fonts.googleapis.com")
      link(rel="preconnect", href="https://fonts.gstatic.com", crossorigin="")
      link(rel="stylesheet", href="https://fonts.googleapis.com/css2?family=Cousine:ital,wght@0,400;0,700;1,400;1,700&display=swap")
      link(rel="stylesheet", href=bp & "/static/tux.css")
      link(rel="stylesheet", href=bp & "/static/style.css")
    body:
      header:
        a(href=bp & "/"): text "matchstick"
        nav:
          a(href=bp & "/"): text "home"
          a(href=bp & "/docs/"): text "docs"
          a(href=bp & "/playground/"): text "playground"
          a(href="https://github.com/elee1766/matchstick", target="_blank"): text "github"
          button(id="theme-toggle", `data-variant`="ghost"): text "theme"
      main:
        content
      footer:
        p: text "matchstick — lua-based nftables firewall configuration"
      verbatim """
<script>
function getTheme() { return localStorage.getItem('theme') || 'auto'; }
function applyTheme(t) {
  if (t === 'auto') document.documentElement.removeAttribute('data-theme');
  else document.documentElement.setAttribute('data-theme', t);
}
function cycleTheme() {
  var order = ['auto','light','dark'];
  var cur = order.indexOf(getTheme());
  var next = order[(cur+1) % 3];
  localStorage.setItem('theme', next);
  applyTheme(next);
  document.getElementById('theme-toggle').textContent = next === 'auto' ? 'theme' : next;
}
(function() {
  var t = getTheme();
  applyTheme(t);
  var el = document.getElementById('theme-toggle');
  if (el) {
    if (t !== 'auto') el.textContent = t;
    el.addEventListener('click', cycleTheme);
  }
})();
</script>
"""

  result = "<!DOCTYPE html>\n" & $page
