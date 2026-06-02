tiny-dhcp

i find myself needing to give devices ip addrs all the time. usually that means grabbing a router just to use its dhcp server. tiny-dhcp is the same idea without the extra gear: set your host to `192.168.33.4/24`, run `zig build && ./zig-out/bin/tiny-dhcp` in the repo, then connect to your device at `192.168.33.7`. 

run:

```bash
zig build && ./zig-out/bin/tiny-dhcp
```

optional flags:

```bash
./zig-out/bin/tiny-dhcp --lease-addr 192.168.33.10 --lease-duration 3600
```

cross compile:

```bash
# windows
zig build -Dtarget=x86_64-windows-gnu -Doptimize=ReleaseFast

# linux
zig build -Dtarget=x86_64-linux-gnu -Doptimize=ReleaseFast
```
