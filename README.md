tiny-dhcp

i find myself needing device ip addrs all the time. usually that means grabbing a router just to use its dhcp server. tiny-dhcp is the same idea without the extra gear: set your host to `192.168.33.4/24`, run it, provision the device, move on.

run:

```bash
zig build && ./zig-out/bin/tiny-dhcp
```

cross compile:

```bash
# windows
zig build -Dtarget=x86_64-windows-gnu -Doptimize=ReleaseFast

# linux
zig build -Dtarget=x86_64-linux-gnu -Doptimize=ReleaseFast
```
