# ky-broker — a single entry point to several Kyber containers

Players only use **one IP and two ports** (443/tcp for the web page, 9000/udp for the stream).
The broker assigns each new player a **free** Kyber container, skips busy ones,
queues players when everything is taken, and **restarts the container between two players**.

```
Player 192.168.1.50 ─┬─ TCP 443 ─► HAProxy ─┬─ valid cookie ────────────► container k1 (Kyber page, WebSocket)
                     │                      └─ no cookie ─► broker ─► picks a FREE container,
                     │                                                sets the cookie, programs nft
                     └─ UDP 9000 ─► kernel (nftables): DNAT by source IP ─► container k1:9000
```

## 1. The idea: control plane and data plane

| Role | Who | What it does |
|---|---|---|
| **Control plane** | `ky_broker.py` (Python) | Decides who goes where, monitors activity and health, recycles containers |
| **Web data plane** | HAProxy | Routes each request by the `KYBER_SESSION` cookie, through a *map* updated live |
| **UDP data plane** | Linux kernel (nftables) | Redirects packets by player IP, through an nft *map* updated live |

**No game packet goes through Python**: zero added latency, and the container sees the player's
real IP. HAProxy Community cannot relay UDP, which is why UDP is handed to the kernel.

## 2. The state machine

```
FREE ──(player assigned)──► RESERVED ──(UDP traffic seen)──► IN_USE
 ▲                              │ (nothing within 60 s)        │ (no traffic for N s)
 │                              ▼                              ▼
 └────────── RECYCLING ◄────────┴──────────────────────────────┘
          (podman restart, then back to FREE)

Any state ──(health check fails)──► DOWN ──(healthy again / automatic retry)──► RECYCLING
```

| Transition | Trigger | Broker actions |
|---|---|---|
| FREE → RESERVED | A player without a session arrives | Random token + cookie, HAProxy entry, nft entry, conntrack flush |
| RESERVED → IN_USE | The player's IP shows up in the nft `seen` set | — |
| RESERVED → RECYCLING | No UDP packet for `reserve_timeout_s` (60 s) | Revocation (see below) + `podman restart` |
| IN_USE → RECYCLING | The IP left the `seen` set (no packet for `idle_timeout_s`) or the player opens `/_kyber/leave` | Revocation + `podman restart` |
| RECYCLING → FREE | `rise` successful health checks after the restart | — |
| RECYCLING → DOWN | Restart failed, or not healthy after `recycle_timeout_s` | — |
| * → DOWN | `fall` consecutive failed health checks | Revocation of any session |
| DOWN → RECYCLING | Container healthy again, or every `down_retry_s` (automatic retry) | `podman restart` |

**Revocation** = remove the token from HAProxy (the old cookie no longer leads anywhere),
remove the IP from the nft maps, flush the UDP flows from conntrack.

**Invariant**: the only way to FREE goes through RECYCLING. A player never inherits the game
or the Steam session of the previous player.

### How UDP activity is measured

The rule `udp dport 9000 update @seen { ip saddr }` sits at *mangle* priority, so it sees
**every** packet (*nat* chains only see the first packet of a flow). Each packet resets the
IP's countdown to `idle_timeout_s`. The broker simply reads the set every 2 s:
IP present = recent traffic, IP absent = idle for N s. All the counting happens in the kernel.

### Self-healing

Every `reconcile_s` seconds, the broker compares the desired state with the real system:
nft table wiped by a firewall reload → rebuilt; missing or orphan entry → fixed;
HAProxy restarted → map resynced. After a rebuild, a grace period prevents kicking out
ongoing players while the `seen` set fills up again.
When the broker restarts, state is reloaded from `/var/lib/kyber/state.json`: ongoing games
carry on.

## 3. Requirements

- CachyOS, Python ≥ 3.11 (no external library)
- `sudo pacman -S --needed haproxy nftables conntrack-tools curl socat`
- Working Kyber Podman containers (rootful), **each with a fixed IP**
- The same Kyber UDP port in every container (default here: 9000)

### Check this on Kyber first

During a session, inside a container: `podman exec kyber-1 ss -tulpn`.
Note the web server's **TCP port** (→ `web_port`) and the stream's **UDP port** (→ `udp_port`).
Set `public_port` to that UDP port: the webclient usually connects to the same port as the
server. If the stream goes over WebTransport on the HTTPS port (443/udp), set `public_port = 443`.

## 4. Installation

### 4.1 Containers: fixed IPs, no published ports

The broker routes straight to each container's IP. Remove `-p`/`--publish` and pin the IP:

```bash
sudo podman run -d --name kyber-1 --ip 10.88.0.11 ...   # your usual options (--privileged, CDI…)
sudo podman run -d --name kyber-2 --ip 10.88.0.12 ...
sudo podman inspect -f '{{.Name}} {{.NetworkSettings.IPAddress}}' kyber-1 kyber-2
```

With `--network host` instead: `ip` = the host's LAN IP, and a different port per container.

### 4.2 Files

```bash
sudo install -d /opt/kyber /etc/kyber
sudo install -m 755 ky_broker.py /opt/kyber/
sudo install -m 644 README.md /opt/kyber/
sudo install -m 640 broker.toml /etc/kyber/broker.toml
sudo nano /etc/kyber/broker.toml        # IPs, ports, container names, admin network
sudo python3 /opt/kyber/ky_broker.py -c /etc/kyber/broker.toml check
```

### 4.3 HTTPS certificate

The Kyber webclient uses APIs (WebAssembly, WebCodecs, WebTransport…) that browsers only
allow on HTTPS pages. On a local network, a self-signed certificate is enough:

```bash
sudo install -d -m 750 -g haproxy /etc/haproxy/certs
sudo openssl req -x509 -newkey rsa:2048 -nodes -days 825 -subj "/CN=kyber.lan" \
  -addext "subjectAltName=DNS:kyber.lan,IP:192.168.1.10" \
  -keyout /tmp/kyber.key -out /tmp/kyber.crt
sudo sh -c 'cat /tmp/kyber.crt /tmp/kyber.key > /etc/haproxy/certs/kyber.pem && rm /tmp/kyber.key'
sudo chmod 640 /etc/haproxy/certs/kyber.pem && sudo chgrp haproxy /etc/haproxy/certs/kyber.pem
```

Replace `192.168.1.10` with the server's IP. Each client must accept (or import) the certificate
once. Without HTTPS: `tls_cert = ""` and `cookie_secure = false`.

### 4.4 HAProxy

```bash
sudo install -m 644 systemd/kyber.tmpfiles.conf /etc/tmpfiles.d/kyber.conf
sudo systemd-tmpfiles --create /etc/tmpfiles.d/kyber.conf    # creates the empty map: HAProxy requires it
sudo cp /etc/haproxy/haproxy.cfg /etc/haproxy/haproxy.cfg.orig
sudo sh -c 'python3 /opt/kyber/ky_broker.py -c /etc/kyber/broker.toml render-haproxy > /etc/haproxy/haproxy.cfg'
sudo haproxy -c -f /etc/haproxy/haproxy.cfg
sudo systemctl enable --now haproxy
```

Adding a container = one more `[[slot]]` block, then regenerate `haproxy.cfg` and
`sudo systemctl reload haproxy`.

### 4.5 Firewall

Open both entry ports, and allow **forwarding** to the Podman network
(DNAT sends UDP packets through the *forward* chain). With ufw:

```bash
sudo ufw allow 443/tcp
sudo ufw allow 9000/udp
sudo ufw route allow proto udp to 10.88.0.0/16 port 9000
```

With firewalld: `sudo firewall-cmd --permanent --add-port={443/tcp,9000/udp} && sudo firewall-cmd --reload`.

### 4.6 systemd service

```bash
sudo install -m 644 systemd/ky-broker.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ky-broker
journalctl -u ky-broker -f
```

On the very first start, the broker restarts every container (it cannot know who used them
before it): allow a few dozen seconds before the stations turn FREE.

## 5. Usage

| Who | Address | Effect |
|---|---|---|
| Player | `https://<server>/` | Assigns a free station, or queues (self-reloading page) |
| Player | `https://<server>/_kyber/leave` | Ends the session immediately and frees the station |
| Admin | `https://<server>/_kyber/admin` | Station table, "Recycle" button |
| Admin | `https://<server>/_kyber/status` | State as JSON |
| Admin | `https://<server>/_kyber/metrics` | Prometheus metrics (for Grafana) |

The admin pages only answer the networks listed in `admin_networks`.

## 6. Checks

```bash
sudo nft list table ip kyber                    # rules, sessions, active IPs (seen set)
echo "show map /etc/haproxy/maps/kyber-sessions.map" | sudo socat - /run/haproxy/admin.sock
sudo conntrack -L -p udp --orig-port-dst 9000    # ongoing UDP flows and their redirection
curl -sk https://127.0.0.1/_kyber/status | python3 -m json.tool
```

## 7. Tests

```bash
python3 -m unittest -v test_ky_broker.py         # 20 state machine tests, no root needed
sudo ./maquette/maquette.sh                      # real network mock-up (~1 min), see below
```

The mock-up creates three isolated network namespaces (host, fake Kyber containers, players) with a
real HAProxy and real nftables rules, and walks through: assignment, load balancing, queue, UDP on
the single port, idleness and recycling, firewall reload, container failure.
It touches neither the host network nor the containers. Its output makes a good capture for a report.

## 8. Troubleshooting

| Symptom | Lead |
|---|---|
| HAProxy won't start: *failed to open pattern file* | The map does not exist: `sudo systemd-tmpfiles --create /etc/tmpfiles.d/kyber.conf` |
| Web page OK, but no picture | UDP port: check `udp_port`/`public_port` (§3), the firewall (§4.5), then `sudo conntrack -L -p udp` |
| The station stays RESERVED, then gets recycled | No UDP packet reaches `public_port`: `sudo nft list set ip kyber seen` while connecting |
| Stations go DOWN | `podman ps`, `curl http://10.88.0.11:8080/`, then the container's log |
| Testing from the server itself | Does not work for UDP: local traffic does not go through *prerouting*. Test from another PC |
| "Preparing your session…" loops forever | The broker cannot write to HAProxy: check the `/run/haproxy/admin.sock` socket |

## 9. Known limitations

- **One session per IP.** UDP is routed by source IP: two players behind the same router
  would share the same station. Harmless on a LAN; for the Internet, use a VPN
  (WireGuard gives each player a distinct IP).
- **IPv4 only.**
- **Single host.** The broker manages the containers of one machine; several servers would
  require shared state.
