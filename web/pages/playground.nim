## Playground page — edit Lua, see nftables output.

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
    h1: text "Playground"
    p: text "Edit the Lua config and see the generated nftables output."

    tdiv(class="playground"):
      tdiv(class="playground-editor"):
        h3: text "firewall.lua"
        textarea(id="config-input", rows="20", spellcheck="false"):
          text defaultConfig
        tdiv(class="controls"):
          button(id="btn-render", class="btn"): text "Render"
          button(id="btn-check", class="btn btn-outline"): text "Check"
          select(id="output-format"):
            option(value="text", selected="selected"): text "nftables text"
            option(value="json"): text "nftables JSON"
            option(value="sysctl"): text "sysctl"

      tdiv(class="playground-output"):
        h3: text "Output"
        pre(id="output"):
          code(id="output-code"):
            text "Click Render to see output..."

    verbatim """
<script>
document.getElementById('btn-render').addEventListener('click', async () => {
  const config = document.getElementById('config-input').value;
  const format = document.getElementById('output-format').value;
  const out = document.getElementById('output-code');
  out.textContent = 'Rendering...';
  try {
    const resp = await fetch('/api/render', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({config: config, format: format}),
    });
    const data = await resp.json();
    if (data.error) {
      out.textContent = 'Error:\n' + data.error;
    } else {
      out.textContent = data.output;
    }
  } catch (e) {
    out.textContent = 'Request failed: ' + e.message;
  }
});

document.getElementById('btn-check').addEventListener('click', async () => {
  const config = document.getElementById('config-input').value;
  const out = document.getElementById('output-code');
  out.textContent = 'Checking...';
  try {
    const resp = await fetch('/api/check', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({config: config}),
    });
    const data = await resp.json();
    if (data.error) {
      out.textContent = 'Error:\n' + data.error;
    } else {
      out.textContent = data.output;
    }
  } catch (e) {
    out.textContent = 'Request failed: ' + e.message;
  }
});
</script>
"""

  layout("Playground", content)
