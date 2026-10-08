#!/usr/bin/env python3
"""
Umbria broker — un point d'entrée unique (IP + port) vers plusieurs conteneurs Kyber.

Chaque conteneur (« slot ») suit la machine à états :

    FREE ──(joueur attribué)──► RESERVED ──(trafic UDP reçu)──► IN_USE
     ▲                              │ (rien reçu en 60 s)          │ (plus de trafic depuis N s)
     │                              ▼                              ▼
     └────────── RECYCLING ◄────────┴──────────────────────────────┘
              (podman restart, puis retour à FREE)

    N'importe quel état ──(health check échoue)──► DOWN
    DOWN ──(conteneur de nouveau sain, ou relance auto)──► RECYCLING

Invariant : le seul chemin vers FREE passe par RECYCLING. Un joueur ne retrouve
donc jamais la session (jeu, compte Steam) du joueur précédent.

Répartition des rôles :
  * plan de contrôle : ce programme (décide qui va où, surveille, recycle) ;
  * plan de données  : HAProxy pour le web (cookie -> conteneur, via une map
    modifiée à chaud par le socket d'administration) et le noyau (nftables)
    pour l'UDP (IP du joueur -> conteneur). Aucun paquet de jeu ne passe par
    Python, donc aucune latence ajoutée.

Dépendances : Python >= 3.11 (bibliothèque standard uniquement), nft,
conntrack (conntrack-tools), podman, haproxy.
"""
from __future__ import annotations

import argparse
import asyncio
import html
import ipaddress
import json
import logging
import os
import secrets
import shlex
import ssl
import sys
import time
import tomllib
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

__version__ = "1.0.0"
log = logging.getLogger("umbria")


# ═══════════════════════════════════════════════════════════════════════════
#  Configuration
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class SlotConfig:
    name: str            # identifiant court (k1, k2…) — sert aussi au nom du backend HAProxy
    container: str       # nom du conteneur Podman
    ip: str              # IP du conteneur (bridge Podman) ou de l'hôte (--network host)
    web_port: int        # port du serveur web Kyber dans le conteneur
    udp_port: int        # port UDP du flux Kyber dans le conteneur
    web_tls: bool = False  # le serveur web Kyber parle-t-il HTTPS ?


@dataclass
class Config:
    # [broker]
    listen_host: str = "127.0.0.1"
    listen_port: int = 8099
    state_file: str = "/var/lib/umbria/state.json"
    tick_s: float = 2.0
    reserve_timeout_s: float = 60.0
    idle_timeout_s: int = 30
    cookie_name: str = "UMBRIA_SESSION"
    cookie_secure: bool = True
    admin_networks: list[str] = field(default_factory=lambda: ["127.0.0.0/8"])
    queue_ttl_s: float = 20.0
    reconcile_s: float = 15.0
    # [udp]
    udp_public_port: int = 9000
    udp_interface: str = ""
    nft_table: str = "umbria"
    # [haproxy]
    haproxy_socket: str = "/run/haproxy/admin.sock"
    haproxy_map: str = "/etc/haproxy/maps/umbria-sessions.map"
    haproxy_bind: str = "*:443"
    haproxy_tls_cert: str = ""
    # [health]
    health_mode: str = "tcp"         # tcp | http
    health_path: str = "/"
    health_interval_s: float = 5.0
    health_timeout_s: float = 2.0
    health_fall: int = 3
    health_rise: int = 2
    recycle_timeout_s: float = 180.0
    down_retry_s: float = 120.0
    # [recycle]
    recycle_command: list[str] = field(
        default_factory=lambda: ["podman", "restart", "--time", "10", "{container}"])
    # [[slot]]
    slots: list[SlotConfig] = field(default_factory=list)

    @classmethod
    def load(cls, path: str | Path) -> "Config":
        with open(path, "rb") as f:
            raw = tomllib.load(f)
        c = cls()
        b, u, h, hc, r = (raw.get(k, {}) for k in ("broker", "udp", "haproxy", "health", "recycle"))
        listen = b.get("listen", f"{c.listen_host}:{c.listen_port}")
        c.listen_host, _, port = listen.rpartition(":")
        c.listen_port = int(port)
        for key, attr in [("state_file", "state_file"), ("tick_s", "tick_s"),
                          ("reserve_timeout_s", "reserve_timeout_s"),
                          ("idle_timeout_s", "idle_timeout_s"), ("cookie_name", "cookie_name"),
                          ("cookie_secure", "cookie_secure"), ("admin_networks", "admin_networks"),
                          ("queue_ttl_s", "queue_ttl_s"), ("reconcile_s", "reconcile_s")]:
            if key in b:
                setattr(c, attr, b[key])
        for key, attr in [("public_port", "udp_public_port"), ("interface", "udp_interface"),
                          ("table", "nft_table")]:
            if key in u:
                setattr(c, attr, u[key])
        for key, attr in [("socket", "haproxy_socket"), ("map_file", "haproxy_map"),
                          ("bind", "haproxy_bind"), ("tls_cert", "haproxy_tls_cert")]:
            if key in h:
                setattr(c, attr, h[key])
        for key in ("mode", "path", "interval_s", "timeout_s", "fall", "rise",
                    "recycle_timeout_s", "down_retry_s"):
            if key in hc:
                attr = key if key in ("recycle_timeout_s", "down_retry_s") else f"health_{key}"
                setattr(c, attr, hc[key])
        if "command" in r:
            c.recycle_command = list(r["command"])
        c.slots = [SlotConfig(**s) for s in raw.get("slot", [])]
        c.validate()
        return c

    def validate(self) -> None:
        if not self.slots:
            raise ValueError("aucun [[slot]] défini dans la configuration")
        names = set()
        for s in self.slots:
            if not s.name.replace("-", "").replace("_", "").isalnum():
                raise ValueError(f"nom de slot invalide : {s.name!r}")
            if s.name in names:
                raise ValueError(f"slot en double : {s.name}")
            names.add(s.name)
            ipaddress.IPv4Address(s.ip)
        for net in self.admin_networks:
            ipaddress.ip_network(net, strict=False)
        if self.health_mode not in ("tcp", "http"):
            raise ValueError("health.mode doit valoir 'tcp' ou 'http'")
        if int(self.idle_timeout_s) < 1:
            raise ValueError("idle_timeout_s doit être >= 1 (le set nftables compte en secondes)")
        if not any("{container}" in a for a in self.recycle_command):
            raise ValueError("recycle.command doit contenir {container}")


# ═══════════════════════════════════════════════════════════════════════════
#  Générateurs : règles nftables et haproxy.cfg (une seule source de vérité)
# ═══════════════════════════════════════════════════════════════════════════

def render_nft(cfg: Config) -> str:
    iif = f'iifname "{cfg.udp_interface}" ' if cfg.udp_interface else ""
    t, p = cfg.nft_table, cfg.udp_public_port
    return f"""\
# Généré par umbria_broker — ne pas modifier à la main.
# « table puis delete table » rend le chargement idempotent.
table ip {t}
delete table ip {t}
table ip {t} {{
    # IP du joueur -> IP du conteneur . port UDP Kyber (rempli par le broker)
    map sessions {{
        type ipv4_addr : ipv4_addr . inet_service
    }}

    # Activité : chaque paquet UDP rafraîchit l'IP source pour {int(cfg.idle_timeout_s)} s.
    # Présente dans le set = trafic récent ; absente = inactif depuis N s.
    set seen {{
        type ipv4_addr
        size 4096
        flags dynamic,timeout
        timeout {int(cfg.idle_timeout_s)}s
    }}

    # Priorité mangle : vue AVANT le DNAT et pour CHAQUE paquet
    # (les chaînes nat ne voient que le premier paquet d'un flux).
    chain activity {{
        type filter hook prerouting priority mangle; policy accept;
        {iif}udp dport {p} update @seen {{ ip saddr }}
    }}

    chain prerouting {{
        type nat hook prerouting priority dstnat; policy accept;
        {iif}udp dport {p} dnat ip to ip saddr map @sessions
    }}
}}
"""


def render_haproxy(cfg: Config) -> str:
    tls = cfg.haproxy_tls_cert
    bind = f"bind {cfg.haproxy_bind}"
    if tls:
        bind += f" ssl crt {tls} alpn h2,http/1.1"
    lines = [
        "# Généré par umbria_broker render-haproxy — régénérer plutôt que modifier.",
        "global",
        "    log /dev/log local0",
        f"    stats socket {cfg.haproxy_socket} mode 660 level admin expose-fd listeners",
        "    stats timeout 30s",
        "    user haproxy",
        "    group haproxy",
        "",
        "defaults",
        "    mode http",
        "    log global",
        "    option httplog",
        "    option dontlognull",
        "    timeout connect 5s",
        "    timeout client  60s",
        "    timeout server  60s",
        "    timeout tunnel  4h     # WebSocket Kyber : une partie peut durer longtemps",
        "",
        "frontend fe_umbria",
        f"    {bind}",
        "    # L'IP vue par le broker doit être celle posée par HAProxy, jamais celle du client",
        "    http-request del-header X-Forwarded-For",
        "    option forwardfor",
        f"    http-request set-header X-Forwarded-Proto {'https' if tls else 'http'}",
        "    # Pages du broker : file d'attente, quitter, administration",
        "    use_backend bk_broker if { path_beg /_umbria/ }",
        "    # Cookie de session valide -> conteneur attribué ; sinon -> broker",
        f"    use_backend %[req.cook({cfg.cookie_name}),map({cfg.haproxy_map},bk_broker)]",
        "    default_backend bk_broker",
        "",
        "backend bk_broker",
        f"    server broker {cfg.listen_host}:{cfg.listen_port}",
        "",
    ]
    for s in cfg.slots:
        ssl_opt = " ssl verify none" if s.web_tls else ""
        lines += [
            f"backend bk_{s.name}",
            f"    # conteneur {s.container}",
            f"    server {s.name} {s.ip}:{s.web_port}{ssl_opt}",
            "",
        ]
    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════
#  Infra : tout ce qui touche au système (remplacé par un faux dans les tests)
# ═══════════════════════════════════════════════════════════════════════════

class InfraError(RuntimeError):
    pass


class Infra:
    """Accès au noyau (nft, conntrack), à HAProxy et à Podman."""

    def __init__(self, cfg: Config):
        self.cfg = cfg

    async def _run(self, *argv: str, stdin: str | None = None,
                   timeout: float = 30.0, check: bool = True) -> tuple[int, str, str]:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            out, err = await asyncio.wait_for(
                proc.communicate(stdin.encode() if stdin is not None else None), timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise InfraError(f"délai dépassé : {shlex.join(argv)}")
        rc = proc.returncode
        o, e = out.decode(errors="replace"), err.decode(errors="replace")
        if check and rc != 0:
            raise InfraError(f"{shlex.join(argv)} -> code {rc} : {e.strip() or o.strip()}")
        return rc, o, e

    # ── nftables ───────────────────────────────────────────────────────────
    async def nft_load(self) -> None:
        await self._run("nft", "-f", "-", stdin=render_nft(self.cfg))

    async def nft_table_ok(self) -> bool:
        rc, _, _ = await self._run("nft", "list", "table", "ip", self.cfg.nft_table, check=False)
        return rc == 0

    async def nft_session_add(self, client_ip: str, slot: SlotConfig) -> None:
        t = self.cfg.nft_table
        await self._run("nft", "delete", "element", "ip", t, "sessions",
                        f"{{ {client_ip} }}", check=False)
        elem = f"{{ {client_ip} : {slot.ip} . {slot.udp_port} }}"
        await self._run("nft", "add", "element", "ip", t, "sessions", elem)

    async def nft_session_del(self, client_ip: str) -> None:
        for obj in ("sessions", "seen"):
            # absent = déjà supprimé, ce n'est pas une erreur
            await self._run("nft", "delete", "element", "ip", self.cfg.nft_table, obj,
                            f"{{ {client_ip} }}", check=False)

    async def nft_sessions(self) -> dict[str, str]:
        """IP joueur -> 'ip_conteneur.port' actuellement dans la map du noyau."""
        _, out, _ = await self._run("nft", "-j", "list", "map", "ip", self.cfg.nft_table, "sessions")
        res = {}
        for obj in json.loads(out).get("nftables", []):
            for e in obj.get("map", {}).get("elem", []) or []:
                key, val = e
                ip, port = val["concat"]
                res[key] = f"{ip}.{port}"
        return res

    async def nft_seen(self) -> set[str]:
        """IP ayant envoyé de l'UDP sur le port public dans les N dernières secondes."""
        _, out, _ = await self._run("nft", "-j", "list", "set", "ip", self.cfg.nft_table, "seen")
        seen = set()
        for obj in json.loads(out).get("nftables", []):
            for e in obj.get("set", {}).get("elem", []) or []:
                if isinstance(e, str):
                    seen.add(e)
                elif isinstance(e, dict):
                    val = e.get("elem", e).get("val")
                    if isinstance(val, str):
                        seen.add(val)
        return seen

    async def conntrack_flush(self, client_ip: str) -> None:
        """Oublie les flux UDP en cours : sinon le noyau garde l'ancienne redirection."""
        try:
            await self._run("conntrack", "-D", "-p", "udp", "--orig-src", client_ip,
                            "--orig-port-dst", str(self.cfg.udp_public_port), check=False)
        except FileNotFoundError:
            log.warning("conntrack introuvable (paquet conntrack-tools) : flux non purgés")

    # ── HAProxy (socket d'administration) ─────────────────────────────────
    async def haproxy_cmd(self, cmd: str) -> str:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_unix_connection(self.cfg.haproxy_socket), 3)
        except (OSError, asyncio.TimeoutError) as exc:
            raise InfraError(f"socket HAProxy injoignable ({self.cfg.haproxy_socket}) : {exc}")
        try:
            writer.write((cmd + "\n").encode())
            await writer.drain()
            data = await asyncio.wait_for(reader.read(), 5)
        finally:
            writer.close()
        return data.decode(errors="replace").strip()

    async def haproxy_set(self, token: str, backend: str) -> None:
        m = self.cfg.haproxy_map
        await self.haproxy_cmd(f"del map {m} {token}")          # « Key not found » : normal
        res = await self.haproxy_cmd(f"add map {m} {token} {backend}")
        if res:                                                  # succès = réponse vide
            raise InfraError(f"HAProxy a refusé l'entrée : {res}")

    async def haproxy_del(self, token: str) -> None:
        await self.haproxy_cmd(f"del map {self.cfg.haproxy_map} {token}")

    async def haproxy_entries(self) -> dict[str, str]:
        out = await self.haproxy_cmd(f"show map {self.cfg.haproxy_map}")
        res = {}
        for line in out.splitlines():
            parts = line.split()
            if len(parts) == 3:  # « 0x55… clé valeur »
                res[parts[1]] = parts[2]
        return res

    def write_map_file(self, entries: dict[str, str]) -> None:
        """Copie disque de la map : HAProxy la relit à chaque (re)démarrage."""
        path = Path(self.cfg.haproxy_map)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text("".join(f"{k} {v}\n" for k, v in sorted(entries.items())))
        os.chmod(tmp, 0o640)
        try:
            import grp
            os.chown(tmp, 0, grp.getgrnam("haproxy").gr_gid)
        except (KeyError, PermissionError, ImportError):
            pass
        os.replace(tmp, path)

    # ── Podman et health checks ───────────────────────────────────────────
    async def recycle(self, slot: SlotConfig) -> None:
        argv = [a.replace("{container}", slot.container) for a in self.cfg.recycle_command]
        await self._run(*argv, timeout=120)

    async def health(self, slot: SlotConfig) -> bool:
        t = self.cfg.health_timeout_s
        try:
            if self.cfg.health_mode == "tcp":
                _, w = await asyncio.wait_for(asyncio.open_connection(slot.ip, slot.web_port), t)
                w.close()
                return True
            ctx = None
            if slot.web_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE   # certificat auto-signé du conteneur
            r, w = await asyncio.wait_for(
                asyncio.open_connection(slot.ip, slot.web_port, ssl=ctx), t)
            w.write(f"GET {self.cfg.health_path} HTTP/1.1\r\nHost: {slot.ip}\r\n"
                    f"User-Agent: umbria-health\r\nConnection: close\r\n\r\n".encode())
            await w.drain()
            status = await asyncio.wait_for(r.readline(), t)
            w.close()
            parts = status.split()
            return len(parts) >= 2 and parts[1].isdigit() and int(parts[1]) < 500
        except (OSError, asyncio.TimeoutError, ssl.SSLError, ValueError):
            return False


# ═══════════════════════════════════════════════════════════════════════════
#  Machine à états
# ═══════════════════════════════════════════════════════════════════════════

class State(str, Enum):
    FREE = "FREE"
    RESERVED = "RESERVED"
    IN_USE = "IN_USE"
    RECYCLING = "RECYCLING"
    DOWN = "DOWN"


@dataclass
class Slot:
    cfg: SlotConfig
    state: State = State.RECYCLING
    client_ip: str | None = None
    token: str | None = None
    since: float = field(default_factory=time.time)   # entrée dans l'état courant
    last_activity: float = 0.0
    reason: str = ""                                   # pourquoi on est dans cet état
    fails: int = 0
    oks: int = 0
    task: asyncio.Task | None = None

    @property
    def name(self) -> str:
        return self.cfg.name

    @property
    def backend(self) -> str:
        return f"bk_{self.cfg.name}"

    def to_json(self) -> dict:
        return {"state": self.state.value, "client_ip": self.client_ip, "token": self.token,
                "since": self.since, "last_activity": self.last_activity, "reason": self.reason}

    def public(self, now: float) -> dict:
        return {"slot": self.name, "container": self.cfg.container, "state": self.state.value,
                "client_ip": self.client_ip, "for_s": round(now - self.since),
                "reason": self.reason, "health_fails": self.fails}


# Transitions autorisées — documente le schéma et attrape les bugs.
ALLOWED = {
    State.FREE:      {State.RESERVED, State.RECYCLING, State.DOWN},
    State.RESERVED:  {State.IN_USE, State.RECYCLING, State.DOWN},
    State.IN_USE:    {State.RECYCLING, State.DOWN},
    State.RECYCLING: {State.FREE, State.DOWN},
    State.DOWN:      {State.RECYCLING},
}


class Broker:
    def __init__(self, cfg: Config, infra: Infra, clock=time.time):
        self.cfg = cfg
        self.infra = infra
        self.now = clock
        self.slots: dict[str, Slot] = {s.name: Slot(s) for s in cfg.slots}
        self.lock = asyncio.Lock()
        self.queue: dict[str, float] = {}          # IP en attente -> dernière visite (ordre FIFO)
        self.admin_nets = [ipaddress.ip_network(n, strict=False) for n in cfg.admin_networks]
        self.stats = {"sessions_total": 0, "recycles_total": 0, "down_total": 0}
        self._bg: set[asyncio.Task] = set()
        self._stopping = False
        # Après (re)chargement de la table nft, le set « seen » est vide : on laisse
        # aux joueurs en cours le temps d'y réapparaître avant de les juger inactifs.
        self.grace_until = 0.0

    # ── utilitaires ───────────────────────────────────────────────────────
    def by_token(self, token: str | None) -> Slot | None:
        if not token:
            return None
        return next((s for s in self.slots.values() if s.token and
                     secrets.compare_digest(s.token, token)), None)

    def by_ip(self, ip: str) -> Slot | None:
        return next((s for s in self.slots.values()
                     if s.client_ip == ip and s.state in (State.RESERVED, State.IN_USE)), None)

    def _set_state(self, slot: Slot, new: State, reason: str) -> None:
        if new not in ALLOWED[slot.state] and new != slot.state:
            raise RuntimeError(f"transition interdite {slot.state.value} -> {new.value}")
        old = slot.state
        slot.state, slot.since, slot.reason = new, self.now(), reason
        log.info("[%s] %s -> %s (%s)%s", slot.name, old.value, new.value, reason,
                 f" joueur {slot.client_ip}" if slot.client_ip else "")

    def persist(self) -> None:
        data = {"version": 1, "saved_at": self.now(),
                "slots": {n: s.to_json() for n, s in self.slots.items()},
                "stats": self.stats}
        path = Path(self.cfg.state_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2))
        os.chmod(tmp, 0o600)                 # contient les jetons de session
        os.replace(tmp, path)
        try:
            self.infra.write_map_file(self._desired_map())
        except OSError as exc:
            log.warning("écriture de la map HAProxy impossible : %s", exc)

    def _desired_map(self) -> dict[str, str]:
        return {s.token: s.backend for s in self.slots.values()
                if s.token and s.state in (State.RESERVED, State.IN_USE)}

    def _grace(self) -> None:
        self.grace_until = self.now() + self.cfg.idle_timeout_s + self.cfg.tick_s

    def _spawn(self, coro) -> asyncio.Task:
        t = asyncio.create_task(coro)
        self._bg.add(t)
        t.add_done_callback(self._bg.discard)
        return t

    # ── démarrage : restaurer l'état et resynchroniser le plan de données ─
    async def start(self) -> None:
        saved = {}
        p = Path(self.cfg.state_file)
        if p.exists():
            try:
                data = json.loads(p.read_text())
                saved = data.get("slots", {})
                self.stats.update(data.get("stats", {}))
            except (ValueError, OSError) as exc:
                log.error("état illisible (%s) : on repart de zéro", exc)
        await self.infra.nft_load()
        self._grace()
        now = self.now()
        for name, slot in self.slots.items():
            st = saved.get(name)
            if st is None:
                # Conteneur inconnu : on ne sait pas qui l'a utilisé -> recyclage.
                self._begin_recycle(slot, "premier démarrage")
                continue
            state = State(st["state"])
            if state in (State.RESERVED, State.IN_USE) and st.get("client_ip") and st.get("token"):
                slot.state, slot.client_ip, slot.token = state, st["client_ip"], st["token"]
                slot.since, slot.last_activity = now, now        # délai de grâce
                slot.reason = "restauré"
                await self.infra.nft_session_add(slot.client_ip, slot.cfg)
            elif state == State.FREE:
                slot.state, slot.since, slot.reason = State.FREE, now, "restauré"
            elif state == State.DOWN:
                slot.state, slot.since, slot.reason = State.DOWN, now, st.get("reason", "restauré")
            else:   # RECYCLING interrompu
                self._begin_recycle(slot, "recyclage interrompu, reprise")
        self.persist()
        await self._sync_haproxy()
        log.info("broker démarré : %s", ", ".join(f"{s.name}={s.state.value}"
                                                    for s in self.slots.values()))

    async def _sync_haproxy(self) -> None:
        """Aligne la map vivante de HAProxy sur l'état voulu.

        Sous verrou : sinon une synchro calculée juste avant un recyclage
        pourrait remettre le jeton révoqué d'un ancien joueur."""
        async with self.lock:
            want = self._desired_map()
            try:
                have = await self.infra.haproxy_entries()
                for tok in have.keys() - want.keys():
                    await self.infra.haproxy_del(tok)
                for tok, be in want.items():
                    if have.get(tok) != be:
                        await self.infra.haproxy_set(tok, be)
            except InfraError as exc:
                log.warning("synchro HAProxy reportée : %s", exc)

    # ── attribution (appelée par le serveur HTTP) ─────────────────────────
    async def assign(self, ip: str) -> tuple[str, Slot | None, int]:
        """Retourne (« assigned » | « queued »), slot, position dans la file (1 = premier)."""
        async with self.lock:
            now = self.now()
            existing = self.by_ip(ip)
            if existing:                       # même joueur (autre onglet, cookie perdu)
                self.queue.pop(ip, None)
                return "assigned", existing, 0

            # File FIFO : on oublie ceux qui ne rechargent plus la page d'attente.
            self.queue = {k: v for k, v in self.queue.items() if now - v < self.cfg.queue_ttl_s}
            self.queue[ip] = now               # nouvelle entrée en fin ; sinon garde sa place
            position = list(self.queue).index(ip)
            free = [s for s in self.slots.values() if s.state == State.FREE]
            if position >= len(free):          # pas de poste libre pour mon rang
                return "queued", None, position + 1

            # Load balancing : le premier conteneur FREE ; les occupés sont sautés.
            slot = free[0]
            self.queue.pop(ip)
            slot.client_ip, slot.token = ip, secrets.token_urlsafe(24)
            slot.last_activity, slot.fails = 0.0, 0
            self._set_state(slot, State.RESERVED, "joueur attribué")
            self.stats["sessions_total"] += 1
            try:
                await self.infra.nft_session_add(ip, slot.cfg)
                # Un flux UDP déjà ouvert avant l'attribution (onglet qui réessaie) a une
                # entrée conntrack SANS NAT : le noyau ne le redirigerait jamais.
                await self.infra.conntrack_flush(ip)
            except InfraError as exc:
                log.error("[%s] nft : %s (réparé par la réconciliation)", slot.name, exc)
            try:
                await self.infra.haproxy_set(slot.token, slot.backend)
            except InfraError as exc:
                log.error("[%s] HAProxy : %s (resynchro au prochain cycle)", slot.name, exc)
            self.persist()
            return "assigned", slot, 0

    async def leave(self, token: str | None, ip: str) -> bool:
        """Le joueur clique « Quitter » : recyclage immédiat."""
        async with self.lock:
            slot = self.by_token(token)
            if not slot or slot.client_ip != ip or slot.state not in (State.RESERVED, State.IN_USE):
                return False
            self._begin_recycle(slot, "le joueur a quitté")
            return True

    async def admin_recycle(self, name: str) -> bool:
        async with self.lock:
            slot = self.slots.get(name)
            if not slot or slot.state == State.RECYCLING:
                return False
            self._begin_recycle(slot, "demande de l'administrateur")
            return True

    # ── recyclage ─────────────────────────────────────────────────────────
    def _begin_recycle(self, slot: Slot, reason: str) -> None:
        """Passe en RECYCLING et lance la tâche (à appeler sous self.lock ou au démarrage)."""
        if slot.state == State.RECYCLING and slot.task and not slot.task.done():
            return
        ip, token = slot.client_ip, slot.token
        if slot.state != State.RECYCLING:
            self._set_state(slot, State.RECYCLING, reason)
        else:
            slot.reason, slot.since = reason, self.now()
        slot.client_ip = slot.token = None
        slot.oks = slot.fails = 0
        self.stats["recycles_total"] += 1
        self.persist()
        slot.task = self._spawn(self._recycle(slot, ip, token))

    async def _revoke(self, slot_name: str, ip: str | None, token: str | None) -> None:
        if ip:
            try:
                await self.infra.nft_session_del(ip)
                await self.infra.conntrack_flush(ip)
            except InfraError as exc:
                log.error("[%s] retrait nft : %s", slot_name, exc)
        if token:
            try:
                await self.infra.haproxy_del(token)
            except InfraError as exc:
                log.error("[%s] retrait HAProxy : %s", slot_name, exc)

    async def _recycle(self, slot: Slot, ip: str | None, token: str | None) -> None:
        await self._revoke(slot.name, ip, token)
        try:
            await self.infra.recycle(slot.cfg)
        except (InfraError, OSError) as exc:
            async with self.lock:
                self._mark_down(slot, f"échec du redémarrage : {exc}")
            return
        deadline = self.now() + self.cfg.recycle_timeout_s
        oks = 0
        poll = min(2.0, self.cfg.health_interval_s)
        while self.now() < deadline and not self._stopping:
            if await self.infra.health(slot.cfg):
                oks += 1
                if oks >= self.cfg.health_rise:
                    async with self.lock:
                        if slot.state == State.RECYCLING:
                            slot.fails = slot.oks = 0
                            self._set_state(slot, State.FREE, "recyclé, conteneur sain")
                            self.persist()
                    return
            else:
                oks = 0
            await asyncio.sleep(poll)
        async with self.lock:
            if slot.state == State.RECYCLING:
                self._mark_down(slot, f"pas sain {self.cfg.recycle_timeout_s:.0f} s après redémarrage")

    def _mark_down(self, slot: Slot, reason: str) -> None:
        ip, token = slot.client_ip, slot.token
        self._set_state(slot, State.DOWN, reason)
        slot.client_ip = slot.token = None
        slot.oks = 0
        self.stats["down_total"] += 1
        self.persist()
        if ip or token:
            self._spawn(self._revoke(slot.name, ip, token))

    # ── boucles de surveillance ───────────────────────────────────────────
    async def activity_tick(self) -> None:
        """RESERVED -> IN_USE, RESERVED/IN_USE -> RECYCLING selon le trafic UDP."""
        try:
            seen = await self.infra.nft_seen()
        except (InfraError, ValueError) as exc:
            log.warning("lecture de l'activité UDP impossible (%s) : aucune décision ce cycle", exc)
            return
        async with self.lock:
            now = self.now()
            for slot in self.slots.values():
                if slot.state == State.RESERVED:
                    if slot.client_ip in seen:
                        slot.last_activity = now
                        self._set_state(slot, State.IN_USE, "trafic UDP reçu")
                        self.persist()
                    elif now - slot.since >= self.cfg.reserve_timeout_s:
                        self._begin_recycle(
                            slot, f"aucun trafic UDP en {self.cfg.reserve_timeout_s:.0f} s")
                elif slot.state == State.IN_USE:
                    if slot.client_ip in seen:
                        slot.last_activity = now
                    elif now >= self.grace_until:
                        self._begin_recycle(
                            slot, f"plus de trafic depuis {self.cfg.idle_timeout_s} s")

    async def health_tick(self) -> None:
        targets = [s for s in self.slots.values() if s.state != State.RECYCLING]
        results = await asyncio.gather(*(self.infra.health(s.cfg) for s in targets))
        async with self.lock:
            now = self.now()
            for slot, ok in zip(targets, results):
                if slot.state == State.RECYCLING:      # a changé pendant le check
                    continue
                if ok:
                    slot.fails, slot.oks = 0, slot.oks + 1
                    if slot.state == State.DOWN and slot.oks >= self.cfg.health_rise:
                        self._begin_recycle(slot, "conteneur de nouveau joignable")
                else:
                    slot.oks, slot.fails = 0, slot.fails + 1
                    if slot.state != State.DOWN and slot.fails >= self.cfg.health_fall:
                        self._mark_down(slot, f"{slot.fails} health checks échoués")
                # relance automatique d'un conteneur en panne
                if (slot.state == State.DOWN and
                        now - slot.since >= self.cfg.down_retry_s):
                    self._begin_recycle(slot, "relance automatique après panne")

    async def reconcile_tick(self) -> None:
        """Auto-réparation : table nft effacée (reload du pare-feu), HAProxy redémarré…"""
        try:
            async with self.lock:
                if not await self.infra.nft_table_ok():
                    log.warning("table nftables absente (pare-feu rechargé ?) : reconstruction")
                    await self.infra.nft_load()
                    self._grace()
                have = await self.infra.nft_sessions()
                want = {s.client_ip: s for s in self.slots.values()
                        if s.client_ip and s.state in (State.RESERVED, State.IN_USE)}
                for ip, slot in want.items():
                    if have.get(ip) != f"{slot.cfg.ip}.{slot.cfg.udp_port}":
                        log.warning("[%s] redirection UDP manquante pour %s : rétablie",
                                    slot.name, ip)
                        await self.infra.nft_session_add(ip, slot.cfg)
                for ip in have.keys() - want.keys():
                    log.warning("redirection UDP orpheline pour %s : supprimée", ip)
                    await self.infra.nft_session_del(ip)
                    await self.infra.conntrack_flush(ip)
        except (InfraError, ValueError) as exc:
            log.warning("réconciliation nft : %s", exc)
        await self._sync_haproxy()

    async def _loop(self, period: float, fn) -> None:
        while not self._stopping:
            try:
                await fn()
            except Exception:                     # une boucle ne doit jamais mourir
                log.exception("erreur dans %s", fn.__name__)
            await asyncio.sleep(period)

    def run_loops(self) -> list[asyncio.Task]:
        return [self._spawn(self._loop(self.cfg.tick_s, self.activity_tick)),
                self._spawn(self._loop(self.cfg.health_interval_s, self.health_tick)),
                self._spawn(self._loop(self.cfg.reconcile_s, self.reconcile_tick))]

    async def stop(self) -> None:
        self._stopping = True
        for t in list(self._bg):
            t.cancel()
        await asyncio.gather(*self._bg, return_exceptions=True)
        # Un recyclage interrompu reste RECYCLING dans l'état : il sera repris au démarrage.
        self.persist()

    # ── observabilité ─────────────────────────────────────────────────────
    def status(self) -> dict:
        now = self.now()
        return {"slots": [s.public(now) for s in self.slots.values()],
                "queue": len(self.queue), "stats": self.stats, "version": __version__}

    def metrics(self) -> str:
        out = ["# HELP umbria_slot_state 1 si le slot est dans cet état",
               "# TYPE umbria_slot_state gauge"]
        for s in self.slots.values():
            for st in State:
                out.append(f'umbria_slot_state{{slot="{s.name}",state="{st.value}"}} '
                           f"{int(s.state == st)}")
        out += ["# TYPE umbria_queue_length gauge", f"umbria_queue_length {len(self.queue)}"]
        for k, v in self.stats.items():
            out += [f"# TYPE umbria_{k} counter", f"umbria_{k} {v}"]
        return "\n".join(out) + "\n"

    def is_admin(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in n for n in self.admin_nets)


# ═══════════════════════════════════════════════════════════════════════════
#  Serveur HTTP minimal (derrière HAProxy, en local uniquement)
# ═══════════════════════════════════════════════════════════════════════════

PAGE_CSS = """
:root{--bg:#0f1115;--fg:#e8e8ea;--mut:#9aa0aa;--acc:#7c9cff;--card:#181b22;--ok:#4cc38a;
--warn:#f2b84b;--bad:#f06a6a}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;
background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,sans-serif;padding:16px}
.card{background:var(--card);border-radius:14px;padding:28px 32px;max-width:720px;width:100%}
h1{margin:0 0 8px;font-size:1.4rem}p{color:var(--mut);margin:6px 0}
.big{font-size:3rem;font-weight:700;color:var(--acc);margin:12px 0}
table{width:100%;border-collapse:collapse;margin-top:12px;font-size:.92rem}
td,th{text-align:left;padding:7px 6px;border-bottom:1px solid #262a33}
.s-FREE{color:var(--ok)}.s-RESERVED,.s-RECYCLING{color:var(--warn)}.s-IN_USE{color:var(--acc)}
.s-DOWN{color:var(--bad)}button{background:#262a33;color:var(--fg);border:0;border-radius:8px;
padding:5px 10px;cursor:pointer}button:hover{background:#333846}
"""


def page(title: str, body: str, refresh: int | None = None) -> str:
    meta = f'<meta http-equiv="refresh" content="{refresh}">' if refresh else ""
    return (f'<!doctype html><html lang="fr"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">{meta}'
            f"<title>{html.escape(title)}</title><style>{PAGE_CSS}</style></head>"
            f'<body><div class="card">{body}</div></body></html>')


class HttpServer:
    MAX_HEADER = 16 * 1024

    def __init__(self, broker: Broker):
        self.b = broker
        self.cfg = broker.cfg

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
            if len(raw) > self.MAX_HEADER:
                raise ValueError("en-têtes trop longs")
            head = raw.decode("latin-1").split("\r\n")
            method, target, _ = head[0].split(" ", 2)
            headers: dict[str, str] = {}
            for line in head[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    k = k.strip().lower()
                    headers[k] = f"{headers[k]}, {v.strip()}" if k in headers else v.strip()
            peer = writer.get_extra_info("peername")[0]
            status, hdrs, body = await self.route(method, target, headers, peer)
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError,
                asyncio.TimeoutError, ValueError, ConnectionError):
            status, hdrs, body = 400, {"Content-Type": "text/plain"}, "requête invalide\n"
        except Exception:
            log.exception("erreur HTTP")
            status, hdrs, body = 500, {"Content-Type": "text/plain"}, "erreur interne\n"
        data = body.encode() if isinstance(body, str) else body
        reasons = {200: "OK", 303: "See Other", 400: "Bad Request", 403: "Forbidden",
                   404: "Not Found", 405: "Method Not Allowed", 409: "Conflict",
                   500: "Internal Server Error", 503: "Service Unavailable"}
        hdrs = {"Cache-Control": "no-store", **hdrs,
                "Content-Length": str(len(data)), "Connection": "close"}
        resp = f"HTTP/1.1 {status} {reasons.get(status, 'OK')}\r\n"
        resp += "".join(f"{k}: {v}\r\n" for k, v in hdrs.items()) + "\r\n"
        try:
            writer.write(resp.encode("latin-1") + data)
            await writer.drain()
        except ConnectionError:
            pass
        finally:
            writer.close()

    def client_ip(self, headers: dict[str, str], peer: str) -> str | None:
        # On ne fait confiance à X-Forwarded-For que s'il vient de HAProxy (connexion locale).
        ip = peer
        if ipaddress.ip_address(peer).is_loopback and headers.get("x-forwarded-for"):
            ip = headers["x-forwarded-for"].split(",")[-1].strip()
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if isinstance(addr, ipaddress.IPv6Address):
            return str(addr.ipv4_mapped) if addr.ipv4_mapped else None
        return str(addr)

    def cookie(self, headers: dict[str, str]) -> str | None:
        for part in headers.get("cookie", "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == self.cfg.cookie_name and v:
                return v
        return None

    def set_cookie(self, token: str, clear: bool = False) -> str:
        c = f"{self.cfg.cookie_name}={'' if clear else token}; Path=/; HttpOnly; SameSite=Lax"
        if self.cfg.cookie_secure:
            c += "; Secure"
        if clear:
            c += "; Max-Age=0"
        return c

    async def route(self, method: str, target: str, headers: dict[str, str], peer: str):
        url = urlsplit(target)
        path, query = url.path, parse_qs(url.query)
        ip = self.client_ip(headers, peer)
        html_ct = {"Content-Type": "text/html; charset=utf-8"}

        if path == "/_umbria/health":
            return 200, {"Content-Type": "text/plain"}, "ok\n"

        if ip is None:
            return 400, html_ct, page("Umbria", "<h1>Adresse non prise en charge</h1>"
                                      "<p>Umbria n'accepte que les clients IPv4.</p>")

        # ── administration ────────────────────────────────────────────────
        if path.startswith("/_umbria/admin") or path in ("/_umbria/status", "/_umbria/metrics"):
            if not self.b.is_admin(ip):
                return 403, {"Content-Type": "text/plain"}, "interdit\n"
            if path == "/_umbria/status":
                return 200, {"Content-Type": "application/json"}, json.dumps(self.b.status(), indent=2)
            if path == "/_umbria/metrics":
                return 200, {"Content-Type": "text/plain; version=0.0.4"}, self.b.metrics()
            if path == "/_umbria/admin/recycle":
                if method != "POST":
                    return 405, {"Content-Type": "text/plain"}, "POST attendu\n"
                ok = await self.b.admin_recycle(query.get("slot", [""])[0])
                return 303, {"Location": "/_umbria/admin"}, ""
            return 200, html_ct, self.admin_page()

        token = self.cookie(headers)

        # ── le joueur quitte ──────────────────────────────────────────────
        if path == "/_umbria/leave":
            await self.b.leave(token, ip)
            return 200, {**html_ct, "Set-Cookie": self.set_cookie("", clear=True)}, page(
                "Session terminée", "<h1>Session terminée</h1><p>Le poste est en cours de "
                "nettoyage pour le joueur suivant. Merci d'avoir joué !</p>"
                '<p><a href="/" style="color:var(--acc)">Rejouer</a></p>')

        # ── cookie valide mais HAProxy nous a quand même envoyé ici ──────
        slot = self.b.by_token(token)
        if slot and slot.state in (State.RESERVED, State.IN_USE) and not path.startswith("/_umbria/"):
            self.b._spawn(self.b._sync_haproxy())
            return 503, {**html_ct, "Retry-After": "2"}, page(
                "Préparation…", "<h1>Préparation de votre session…</h1>"
                "<p>Encore un instant.</p>", refresh=2)

        if method not in ("GET", "HEAD"):
            return 409, {"Content-Type": "text/plain"}, "aucune session : rechargez la page\n"

        # ── attribution d'un conteneur ───────────────────────────────────
        if "_ub" in query and not token:
            return 400, html_ct, page("Cookies requis", "<h1>Cookies désactivés</h1><p>Umbria "
                                      "utilise un cookie pour vous relier à votre poste.</p>")
        result, slot, pos = await self.b.assign(ip)
        if result == "assigned":
            back = path if not path.startswith("/_umbria/") else "/"
            return 303, {"Location": f"{back}?_ub=1" if back == "/" else back,
                         "Set-Cookie": self.set_cookie(slot.token)}, ""
        total = len(self.b.slots)
        return 503, {**html_ct, "Retry-After": "5"}, page(
            "File d'attente", "<h1>Tous les postes sont occupés</h1>"
            f"<p>Votre position dans la file d'attente :</p><div class=big>{pos}</div>"
            f"<p>{total} poste(s) au total. Cette page se recharge toute seule : "
            "gardez-la ouverte.</p>", refresh=5)

    def admin_page(self) -> str:
        st = self.b.status()
        rows = "".join(
            f"<tr><td>{html.escape(s['slot'])}</td><td>{html.escape(s['container'])}</td>"
            f"<td class='s-{s['state']}'>{s['state']}</td>"
            f"<td>{html.escape(s['client_ip'] or '—')}</td><td>{s['for_s']} s</td>"
            f"<td>{html.escape(s['reason'])}</td>"
            f"<td><form method=post action='/_umbria/admin/recycle?slot={html.escape(s['slot'])}'>"
            f"<button>Recycler</button></form></td></tr>" for s in st["slots"])
        stats = st["stats"]
        return page("Umbria — administration",
                    "<h1>Umbria — postes</h1>"
                    f"<p>File d'attente : {st['queue']} · sessions : {stats['sessions_total']} · "
                    f"recyclages : {stats['recycles_total']} · pannes : {stats['down_total']}</p>"
                    "<table><tr><th>Slot</th><th>Conteneur</th><th>État</th><th>Joueur</th>"
                    f"<th>Depuis</th><th>Raison</th><th></th></tr>{rows}</table>", refresh=5)


# ═══════════════════════════════════════════════════════════════════════════
#  Point d'entrée
# ═══════════════════════════════════════════════════════════════════════════

async def serve(cfg: Config) -> None:
    import signal
    broker = Broker(cfg, Infra(cfg))
    await broker.start()
    server = await asyncio.start_server(HttpServer(broker).handle, cfg.listen_host,
                                        cfg.listen_port, limit=HttpServer.MAX_HEADER)
    loops = broker.run_loops()
    log.info("écoute sur http://%s:%d", cfg.listen_host, cfg.listen_port)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    await stop.wait()
    log.info("arrêt demandé")
    server.close()
    await server.wait_closed()
    await broker.stop()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Umbria — broker de sessions Kyber")
    ap.add_argument("-c", "--config", default="/etc/umbria/broker.toml")
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("run", help="lancer le broker")
    sub.add_parser("check", help="valider la configuration")
    sub.add_parser("render-haproxy", help="afficher le haproxy.cfg correspondant")
    sub.add_parser("render-nft", help="afficher les règles nftables")
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(levelname)s %(message)s" if os.environ.get("INVOCATION_ID")
                        else "%(asctime)s %(levelname)s %(message)s")
    try:
        cfg = Config.load(a.config)
    except (OSError, ValueError, TypeError, tomllib.TOMLDecodeError) as exc:
        print(f"configuration invalide : {exc}", file=sys.stderr)
        return 2
    if a.cmd == "check":
        print(f"OK — {len(cfg.slots)} slot(s) : " + ", ".join(
            f"{s.name}→{s.container} ({s.ip})" for s in cfg.slots))
        return 0
    if a.cmd == "render-haproxy":
        print(render_haproxy(cfg))
        return 0
    if a.cmd == "render-nft":
        print(render_nft(cfg))
        return 0
    asyncio.run(serve(cfg))
    return 0


if __name__ == "__main__":
    sys.exit(main())
