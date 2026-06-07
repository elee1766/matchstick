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
    h1: text "playground"
    p: text "edit the lua config and see the generated nftables output."

    tdiv(class="pg-grid"):
      section:
        header:
          text "firewall.lua"
        textarea(id="config-input", rows="24", spellcheck="false",
                 autocomplete="off", autocorrect="off", autocapitalize="off"):
          text defaultConfig
        tdiv(class="pg-controls"):
          button(id="btn-render"): text "render"
          button(id="btn-check", `data-variant`="soft"): text "check"
          select(id="output-format"):
            option(value="text", selected="selected"): text "nftables text"
            option(value="json"): text "nftables json"
            option(value="sysctl"): text "sysctl"

      section:
        header: text "output"
        pre(id="output", class="pg-output"):
          code(id="output-code"):
            text "click render to see output..."

    verbatim """
<script>
document.getElementById('btn-render').addEventListener('click', async () => {
  const config = document.getElementById('config-input').value;
  const format = document.getElementById('output-format').value;
  const out = document.getElementById('output-code');
  out.textContent = 'rendering...';
  try {
    const resp = await fetch('/api/render', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({config, format}),
    });
    const data = await resp.json();
    out.textContent = data.error ? 'error:\n' + data.error : data.output;
  } catch (e) {
    out.textContent = 'request failed: ' + e.message;
  }
});
document.getElementById('btn-check').addEventListener('click', async () => {
  const config = document.getElementById('config-input').value;
  const out = document.getElementById('output-code');
  out.textContent = 'checking...';
  try {
    const resp = await fetch('/api/check', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({config}),
    });
    const data = await resp.json();
    out.textContent = data.error ? 'error:\n' + data.error : data.output;
  } catch (e) {
    out.textContent = 'request failed: ' + e.message;
  }
});
</script>
"""

  layout("playground", content)
