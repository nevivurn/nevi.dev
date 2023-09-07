+++
title = "Yet Another NixOS Router on the APU2"
date = 2023-09-20T16:58:41+00:00
+++

## Motivation

I was having trouble with my previous all-in-one router-switch-AP (TP-Link
Archer C7 running OpenWRT):

- I was running into [this issue][kernel-rtlbug] occasionally killing the
  network, but I could not troubleshoot it because my router could only be
  accessed through the network, which was dead.
- It could not run NixOS.
- I was dropping connections due to conntrack limits.

[kernel-rtlbug]: https://bugzilla.kernel.org/show_bug.cgi?id=209839

## Hardware

After a bit of research, I settled on the [APU2E5][teklager-apu2e5] with the
[wle600vx][teklager-wle600vx] WiFi card, for the following reasons:

- low-powered and fanless
- x86_64 and plenty of memory
- tons of reports of people running NixOS successfully
  - https://francis.begyn.be/blog/nixos-home-router
  - https://www.jjpdev.com/posts/home-router-nixos/
  - https://skogsbrus.xyz/building-a-router-with-nixos/
  - https://dataswamp.org/~solene/2022-08-03-nixos-with-live-usb-router.html

[teklager-apu2e5]: https://teklager.se/en/products/routers/apu2e5-open-source-router
[teklager-wle600vx]: https://teklager.se/en/products/router-components/wle600vx-wireless-wifi-kit

I ordered the router pre-assembled, but it was damaged during shipping, bending
the case and the board inside. The router itself still worked, so I left it
as-is. I also wanted to use a 2.5" SATA SSD for storage, but it would not fit
in the case,[^apu-ssd-fit] so I bought a separate SD card.

{{< picture src="router-shipping-damage.jpg" alt="photo of router with shipping damage" >}}

I could not screw in one of the corners because the holes no longer aligned
without uncomfortably bending the board.

[^apu-ssd-fit]: If I had done a [tiny bit][teklager-sata] [more
    research][ssd-fit-blog], I would have known that there was no way to fit a
    full 2.5" SSD in there.

[teklager-sata]: https://teklager.se/en/products/router-components/sata-data-power-cable
[ssd-fit-blog]: https://voidst.one/posts/comprehensive-guide-to-pc-engines-apu-2-part-1-hardware/#sata-ssd

## Initial configuration

I performed the initial installation with `nixos-install --flake .#funi --root
/mount/point` after partitioning the SD card. Later deployments (once the
network was up) were done with `nix copy --to ssh://funi.nevi.network` before a
`nixos-rebuild switch` on the APU.

I could have built the configuration from the router iself with just the
`nixos-rebuild switch`, but my configuration requires rebuilding some large
packages, including the kernel, which would have taken forever on the low-power
SoC.

I also updated the firmware to the latest recommended version following the
instructions on the [TekLager website][teklager-update] (method 4, using my
existing NixOS system instead of a live USB). For the serial console, I used
picocom (`picocom -b 115200 /dev/ttyUSB0`).

[teklager-update]: https://teklager.se/en/knowledge-base/apu-bios-upgrade/

## Network configuration

### DHCP: dnsmasq

I [configured][config-dnsmasq] dnsmasq to handle local DHCP (both v4 and v6)
and RA, and DNS. I am not using SLAAC for IPv6, because I wanted proper DNS6
address resolution for hosts in my local network. This way, I can configure
static assignments on the router, and let every host automatically configure
itself with DHCP.

[config-dnsmasq]: https://github.com/nevivurn/nixos-config/blob/d390b1e8f3422907c6de9a115e9ffd6ec597dcf4/systems/funi/services/dns.nix#L18

### DNS: dnsmasq & unbound

Dnsmasq handles any local domains, overrides, filtering, and ad blocking.
Unbound then receives any upstream queries, acting as a caching, recursing,
validating resolver. By letting dnsmasq handle the local side, I get DHCP
address resolution for free, both IPv4 and IPv6. At the same time, Unbound can
handle DNSSEC (without having to worry about conflicts with local blocklists)
and  recursion (not supported by dnsmasq).

#### DNS blocking

I implemented DNS ad blocking by adding the [hosts][hosts-list] blocklist to
dnsmasq. I packaged the hosts list itself [here][config-hosts].

Initially, I had configured this by simply using `addn-hosts`. However, I ran
into an issue where non-A or AAAA queries (such as HTTPS, used in Apple
systems) would still forward and respond to queries.[^dnsmasq-local] To work
around this, I set both `local=` and `address=` options for each host in the
blocklist.


```nix
{
  services.dnsmasq.settings = {
    conf-file = (pkgs.runCommand "dnsmasq-hosts" { } ''
      < ${self.packages.${pkgs.system}.hosts}/hosts \
          grep ^0.0.0.0 \
        | awk '{print $2}' \
        | tail -n+2 \
      > hosts
      awk '{print "local=/" $0 "/"}' hosts >> $out
      awk '{print "address=/" $0 "/0.0.0.0"}' hosts >> $out
    '').outPath;
  };
}
```

[^dnsmasq-local]: This behavior is quite recent, since dnsmasq 2.86, and is
    documented in the manpage since 2.87:
    > Note that the behaviour for queries which don't match the specified
    > address literal changed in version 2.86. Previous versions, configured
    > with (eg) --address=/example.com/1.2.3.4 and then queried for a RR type
    > other than A would return a NoData answer. From 2.86, the query is sent
    > upstream. To restore the pre-2.86 behaviour, use the configuration
    > --address=/example.com/1.2.3.4 --local=/example.com/

[hosts-list]: https://github.com/StevenBlack/hosts
[config-hosts]: https://github.com/nevivurn/nixos-config/blob/d390b1e8f3422907c6de9a115e9ffd6ec597dcf4/pkgs/hosts/default.nix

### Firewall: nft

I wanted to have fine-grained control over my firewall, so I configured it
manually instead of using the NixOS firewall module. My firewall
([configuration][config-firewall]) is a straightforward stateful firewall, but I
tried using flowtables to let existing flows bypass the firewall once accepted.

[config-firewall]: https://github.com/nevivurn/nixos-config/blob/d390b1e8f3422907c6de9a115e9ffd6ec597dcf4/systems/funi/router.nix#L94

You can see the effects of offloading here:

{{< picture src="nft-flowtable-netstat.png" alt="netstat dashboard for testing offloading" >}}

The middle period (where the graph is non~zero) is when I disabled flow
offloading. However, despite the very obvious effect as seen on the graph, it
did not measurably improve network performance or reduce CPU usage in my
testing. I kept the flowtable configuration enabled on my system regardless,
for the good feelings.

While configuring the firewall, I referenced the following resources:

- [RFC-4890](https://www.rfc-editor.org/rfc/rfc4890) sections 4.3 and 4.4.
- [Kernel flowtable documentation](https://www.kernel.org/doc/html/latest/networking/nf_flowtable.html)
- [nftables flowtable documentation](https://wiki.nftables.org/wiki-nftables/index.php/Flowtables)
- [`nft(8)`](https://www.netfilter.org/projects/nftables/manpage.html)

### WiFi: hostapd

WiFi is cursed and [so is hostapd][hostapd-cursed]. My configuration can be
found [here][config-hostapd].

[hostapd-cursed]: https://github.com/NixOS/nixpkgs/blob/5cf58fd4f4d6c96f610739871872cc44aec9a797/nixos/modules/services/networking/hostapd.nix#L2-L7
[config-hostapd]: https://github.com/nevivurn/nixos-config/blob/d390b1e8f3422907c6de9a115e9ffd6ec597dcf4/systems/funi/services/hostapd.nix

- The NixOS 23.05 [hostapd module][nixpkgs-hostapd-23.05] is severely lacking.
  In particular, it puts the the WPA password in the world-readable Nix store
  by default.
- There is [a rewrite][nixpkgs-pr222536] on nixpkgs-unstable with significant
  improvements, with easier configuration and an alternative to the
  world-readable password. The rewrite also enables a few important features
  such as OCV in the hostapd package.

For these reasons, I pulled in the unstable hostapd module and package into my
otherwise mostly 23.05 system:

```nix
{
  disabledModules = [ "${nixpkgs}/nixos/modules/services/networking/hostapd.nix" ];
  imports = [ "${nixpkgs-unstable}/nixos/modules/services/networking/hostapd.nix" ];
  services.hostapd.package = pkgs.pkgsUnstable.hostapd;
}
```

[nixpkgs-hostapd-23.05]: https://github.com/NixOS/nixpkgs/blob/nixos-23.05/nixos/modules/services/networking/hostapd.nix
[nixpkgs-pr222536]: https://github.com/NixOS/nixpkgs/pull/222536

To get WiFi working properly on this hardware, I also had to apply a couple
kernel configurations:

- The `ATH_USER_REGD` [patch][nixpkgs-pr108725] adapted from OpenWRT overrides
  the buggy firmware to allow changing the regulatory domain.
  - Without this change, I am unable to use the 5GHz band in AP mode, forcing me
    to use the 2.4GHz band.
  ```nix
  {
    networking.wireless.athUserRegulatoryDomain = true;
  }
  ```
- Enabling `ATH10K_DFS_CERTIFIED` allows me to use the DFS channels.
  ```nix
  {
    boot.kernelPatches = [{
      name = "enable-ath-DFS-JP";
      patch = null;
      extraStructuredConfig = with lib.kernel; {
        EXPERT = yes;
        CFG80211_CERTIFICATION_ONUS = yes;
        ATH10K_DFS_CERTIFIED = yes;
      };
    }];
  }
  ```

[nixpkgs-pr108725]: https://github.com/NixOS/nixpkgs/pull/108725

## Things to investigate

- VLANs
