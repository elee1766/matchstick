## Playground page — live check on edit, render on demand.

import karax/[karaxdsl, vdom]
import ./layout

const defaultConfig = """local ssh  = fw:service("ssh", "tcp", 22)
local http = fw:service("http", "tcp", 80)
local ping = fw:service("ping", "icmp", "echo-request")

local self = fw:zone("fw")
local wan  = fw:zone("wan", "eth0")
local lan  = fw:zone("lan", "eth1")

fw:policy(wan, self, "drop", { log = true })
fw:policy(self, wan, "accept")
fw:policy(lan, self, "accept")
fw:policy(lan, wan, "accept")

fw:rule(wan, self, "accept", ssh)
fw:rule(wan, self, "accept", http)
fw:rule(wan, self, "accept", ping)
"""

proc playgroundPage*(): string =
  let content = buildHtml(tdiv):
    tdiv(class="pg-toolbar"):
      h2: text "playground"
      tdiv(class="pg-actions"):
        button(id="btn-render"): text "render"
        select(id="output-format"):
          option(value="text", selected="selected"): text "nftables text"
          option(value="json"): text "nftables json"
          option(value="sysctl"): text "sysctl"

    tdiv(class="pg-grid"):
      section:
        header: text "firewall.lua"
        textarea(id="config-input", rows="28", spellcheck="false",
                 autocomplete="off", autocorrect="off", autocapitalize="off"):
          text defaultConfig

      section:
        header:
          span(id="check-status"): text "check"
        pre(id="output", class="pg-output"):
          code(id="output-code"):
            text ""

    verbatim """
<script>
var checkTimer = null;
var lastConfig = '';

function doCheck() {
  var config = document.getElementById('config-input').value;
  if (config === lastConfig) return;
  lastConfig = config;
  var status = document.getElementById('check-status');
  var out = document.getElementById('output-code');
  status.textContent = 'checking...';
  fetch('/api/check', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({config: config}),
  }).then(function(r) {
    if (!r.ok) throw new Error('api not available (status ' + r.status + ')');
    return r.json();
  }).then(function(data) {
    if (data.error) {
      status.textContent = 'error';
      out.textContent = data.error;
    } else {
      var ok = data.output.indexOf('ok') !== -1;
      status.textContent = ok ? 'ok' : 'errors';
      out.textContent = data.output;
    }
  }).catch(function(e) {
    status.textContent = 'no server';
    out.textContent = 'api not available — run the matchstick web server locally:\n  nimble webrun';
  });
}

document.getElementById('config-input').addEventListener('input', function() {
  clearTimeout(checkTimer);
  checkTimer = setTimeout(doCheck, 400);
});

document.getElementById('btn-render').addEventListener('click', function() {
  var config = document.getElementById('config-input').value;
  var format = document.getElementById('output-format').value;
  var status = document.getElementById('check-status');
  var out = document.getElementById('output-code');
  status.textContent = 'rendering...';
  fetch('/api/render', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({config: config, format: format}),
  }).then(function(r) {
    if (!r.ok) throw new Error('api not available');
    return r.json();
  }).then(function(data) {
    if (data.error) {
      status.textContent = 'error';
      out.textContent = data.error;
    } else {
      status.textContent = 'rendered';
      out.textContent = data.output;
    }
  }).catch(function(e) {
    status.textContent = 'no server';
    out.textContent = 'api not available — run the matchstick web server locally:\n  nimble webrun';
  });
});

// initial check on load
setTimeout(doCheck, 100);
</script>
"""

  layout("playground", content)
