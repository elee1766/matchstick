## Playground page — runs matchstick entirely client-side via WASM.

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
  let bp = basePath
  let content = buildHtml(tdiv):
    tdiv(class="pg-toolbar"):
      h2: text "playground"
      tdiv(class="pg-actions"):
        button(id="btn-render"): text "render"
        select(id="output-format"):
          option(value="text", selected="selected"): text "nftables text"
          option(value="json"): text "nftables json"
          option(value="sysctl"): text "sysctl"
        span(id="engine-badge", class="pg-badge"): text "loading wasm..."

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

    verbatim("""
<script>
var engine = null;
var checkTimer = null;
var lastConfig = '';

function callMatchstick(config, format) {
  if (!engine) return JSON.stringify({error: 'wasm not loaded yet'});
  return engine.ccall('loadAndRender', 'string', ['string','string'], [config, format]);
}

function doCheck() {
  var config = document.getElementById('config-input').value;
  if (config === lastConfig) return;
  lastConfig = config;
  var status = document.getElementById('check-status');
  var out = document.getElementById('output-code');
  if (!engine) { status.textContent = 'loading...'; return; }
  status.textContent = 'checking...';
  try {
    var data = JSON.parse(callMatchstick(config, 'check'));
    if (data.error) {
      status.textContent = 'error';
      out.textContent = data.error;
    } else {
      var ok = data.output.indexOf('\nok') !== -1;
      status.textContent = ok ? 'ok' : 'errors';
      out.textContent = data.output;
    }
  } catch (e) {
    status.textContent = 'error';
    out.textContent = e.message;
  }
}

document.getElementById('config-input').addEventListener('input', function() {
  clearTimeout(checkTimer);
  checkTimer = setTimeout(doCheck, 300);
});

document.getElementById('btn-render').addEventListener('click', function() {
  var config = document.getElementById('config-input').value;
  var format = document.getElementById('output-format').value;
  var status = document.getElementById('check-status');
  var out = document.getElementById('output-code');
  if (!engine) { status.textContent = 'loading...'; return; }
  status.textContent = 'rendering...';
  try {
    var data = JSON.parse(callMatchstick(config, format));
    if (data.error) {
      status.textContent = 'error';
      out.textContent = data.error;
    } else {
      status.textContent = 'rendered';
      out.textContent = data.output;
    }
  } catch (e) {
    status.textContent = 'error';
    out.textContent = e.message;
  }
});

// Load WASM — playground.js defines createMatchstick via MODULARIZE
var s = document.createElement('script');
s.src = '""" & bp & """/static/playground.js';
s.onload = function() {
  createMatchstick().then(function(mod) {
    engine = mod;
    document.getElementById('engine-badge').textContent = 'wasm';
    doCheck();
  }).catch(function(e) {
    document.getElementById('engine-badge').textContent = 'failed';
    document.getElementById('output-code').textContent = 'failed to load wasm: ' + e.message;
  });
};
s.onerror = function() {
  document.getElementById('engine-badge').textContent = 'no wasm';
  document.getElementById('output-code').textContent = 'playground.js not found — build with: nimble wasm';
};
document.body.appendChild(s);
</script>
""")

  layout("playground", content)
