## Test ipaddr module: CIDR normalization, IPv4 parsing

import unittest
import ../src/matchstickpkg/ipaddr

suite "IPv4 parsing":
  test "basic addresses":
    check $parseIpv4("192.168.0.1") == "192.168.0.1"
    check $parseIpv4("10.0.0.0") == "10.0.0.0"
    check $parseIpv4("0.0.0.0") == "0.0.0.0"
    check $parseIpv4("255.255.255.255") == "255.255.255.255"

  test "invalid addresses":
    expect ValueError:
      discard parseIpv4("not-an-ip")
    expect ValueError:
      discard parseIpv4("1.2.3")
    expect ValueError:
      discard parseIpv4("1.2.3.4.5")

suite "CIDR normalization":
  test "already normalized":
    check normalizeCidr("192.168.0.0/24") == "192.168.0.0/24"
    check normalizeCidr("10.0.0.0/8") == "10.0.0.0/8"
    check normalizeCidr("172.16.0.0/12") == "172.16.0.0/12"

  test "needs normalization":
    check normalizeCidr("172.17.0.0/12") == "172.16.0.0/12"
    check normalizeCidr("10.0.0.5/8") == "10.0.0.0/8"
    check normalizeCidr("192.168.1.100/24") == "192.168.1.0/24"
    check normalizeCidr("192.168.0.1/32") == "192.168.0.1/32"

  test "edge cases":
    check normalizeCidr("0.0.0.0/0") == "0.0.0.0/0"
    check normalizeCidr("255.255.255.255/32") == "255.255.255.255/32"

  test "plain IPs unchanged":
    check normalizeCidr("192.168.0.1") == "192.168.0.1"
    check normalizeCidr("10.0.0.1") == "10.0.0.1"

suite "IP detection":
  test "isIpv4":
    check isIpv4("192.168.0.1")
    check isIpv4("10.0.0.0")
    check not isIpv4("::1")
    check not isIpv4("fe80::1")
    check not isIpv4("hello")

  test "isIpv6":
    check isIpv6("::1")
    check isIpv6("fe80::1")
    check not isIpv6("192.168.0.1")

  test "isCidr":
    check isCidr("192.168.0.0/24")
    check isCidr("10.0.0.0/8")
    check not isCidr("192.168.0.1")
    check not isCidr("hello/world")
