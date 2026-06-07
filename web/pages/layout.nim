## Base HTML layout for all pages.

import karax/[karaxdsl, vdom]

proc layout*(title: string, content: VNode): string =
  let page = buildHtml(html(lang="en")):
    head:
      meta(charset="utf-8")
      meta(name="viewport", content="width=device-width, initial-scale=1")
      title: text title & " - matchstick"
      link(rel="stylesheet", href="/static/tux.css")
      link(rel="stylesheet", href="/static/style.css")
    body:
      nav(class="nav"):
        tdiv(class="nav-inner"):
          a(href="/", class="logo"): text "matchstick"
          tdiv(class="nav-links"):
            a(href="/"): text "Home"
            a(href="/docs"): text "Docs"
            a(href="/playground"): text "Playground"
            a(href="https://github.com/elee1766/matchstick", target="_blank"): text "GitHub"
      main(class="container"):
        content
      footer(class="footer"):
        tdiv(class="container"):
          text "matchstick — Lua-based nftables firewall configuration tool"

  result = "<!DOCTYPE html>\n" & $page
