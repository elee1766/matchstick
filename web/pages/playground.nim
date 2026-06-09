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
      tdiv(class="pg-actions"):
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
          span(id="check-status"): text "output"
        pre(id="output", class="pg-output"):
          code(id="output-code"):
            text ""

    verbatim("""
<script>
var engine = null;
var renderTimer = null;
var lastConfig = '';
var lastFormat = '';

function doRender() {
  var config = document.getElementById('config-input').value;
  var format = document.getElementById('output-format').value;
  if (config === lastConfig && format === lastFormat) return;
  lastConfig = config;
  lastFormat = format;
  var status = document.getElementById('check-status');
  var out = document.getElementById('output-code');
  if (!engine) { status.textContent = 'loading...'; return; }
  try {
    var data = JSON.parse(engine.ccall('loadAndRender', 'string', ['string','string'], [config, format]));
    if (data.error) {
      status.textContent = 'error';
      out.textContent = data.error;
    } else {
      status.textContent = format;
      out.textContent = data.output;
    }
  } catch (e) {
    status.textContent = 'error';
    out.textContent = e.message;
  }
}

document.getElementById('config-input').addEventListener('input', function() {
  clearTimeout(renderTimer);
  renderTimer = setTimeout(doRender, 300);
});

document.getElementById('output-format').addEventListener('change', function() {
  lastFormat = '';
  doRender();
});

var s = document.createElement('script');
s.src = '""" & bp & """/static/playground.js';
s.onload = function() {
  createMatchstick().then(function(mod) {
    engine = mod;
    document.getElementById('engine-badge').textContent = 'wasm';
    doRender();
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
