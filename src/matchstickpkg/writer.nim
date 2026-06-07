## writer.nim - Indentation-aware text builder.
##
## Follows the pattern used by Nim's own compiler backends.
## Tracks indent level, handles line starts, provides `braced` template
## for nftables block syntax.

type
  Writer* = object
    buf*: string
    indent*: int
    atLineStart*: bool

proc newWriter*(cap: int = 4096): Writer =
  Writer(buf: newStringOfCap(cap), indent: 0, atLineStart: true)

proc addIndent*(w: var Writer) =
  if w.atLineStart:
    for i in 0 ..< w.indent:
      w.buf.add "    "  # 4-space indent (nftables convention)
    w.atLineStart = false

proc add*(w: var Writer, s: string) =
  w.addIndent()
  w.buf.add s

proc line*(w: var Writer, s: string) =
  w.addIndent()
  w.buf.add s
  w.buf.add '\n'
  w.atLineStart = true

proc emptyLine*(w: var Writer) =
  w.buf.add '\n'
  w.atLineStart = true

template indented*(w: var Writer, body: untyped) =
  inc w.indent
  body
  dec w.indent

template braced*(w: var Writer, header: string, body: untyped) =
  ## Emit "header {\n    body\n}\n"
  w.addIndent()
  w.buf.add header
  w.buf.add " {\n"
  w.atLineStart = true
  inc w.indent
  body
  dec w.indent
  w.line("}")

proc result*(w: Writer): string = w.buf
