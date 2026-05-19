# matchstick

[![CI](https://github.com/elee1766/matchstick/actions/workflows/ci.yml/badge.svg)](https://github.com/elee1766/matchstick/actions/workflows/ci.yml)

a lua-based nftables configuration generator, mostly a nim experiment

first of all, this is a bad idea. nobody should use this

## what it do

so the idea is that there are a bunch of lua functions. and you call them to declare a nftabltes config.

so you could potentially write lua functions or loops for common tasks, for instance, exposing different services to a different set of hosts with the same configuration

and then this thing like makes json/nftables text config from it, that you can apply to your system

it is inspired by shorewall.
