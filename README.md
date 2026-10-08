# ky-broker — un point d'entrée unique vers plusieurs conteneurs Kyber

Les joueurs n'utilisent qu'**une IP et deux ports** (443/tcp pour la page web, 9000/udp pour le flux).
Le broker attribue à chaque nouveau joueur un conteneur Kyber **libre**, saute ceux qui sont occupés,
met les joueurs en file d'attente quand tout est pris, et **redémarre le conteneur entre deux joueurs**.

```
Joueur 192.168.1.50 ─┬─ TCP 443 ─► HAProxy ─┬─ cookie valide ──────────► conteneur k1 (page Kyber, WebSocket)
                     │                      └─ pas de cookie ─► broker ─► choisit un conteneur FREE,
                     │                                                    pose le cookie, programme nft
                     └─ UDP 9000 ─► noyau (nftables) : DNAT selon l'IP source ─► conteneur k1:9000
```

## 1. Le principe : plan de contrôle et plan de données

| Rôle | Qui | Ce qu'il fait |
|---|---|---|
| **Plan de contrôle** | `ky_broker.py` (Python) | Décide qui va où, surveille l'activité et la santé, recycle les conteneurs |
| **Plan de données web** | HAProxy | Route chaque requête selon le cookie `KYBER_SESSION`, via une *map* modifiée à chaud |
| **Plan de données UDP** | Noyau Linux (nftables) | Redirige les paquets selon l'IP du joueur, via une *map* nft modifiée à chaud |

**Aucun paquet de jeu ne passe par Python** : la latence ajoutée est nulle et le conteneur voit la vraie IP
du joueur. HAProxy Community ne sait pas relayer l'UDP, c'est pourquoi l'UDP est confié au noyau.

## 2. La machine à états

```
FREE ──(joueur attribué)──► RESERVED ──(trafic UDP reçu)──► IN_USE
 ▲                              │ (rien reçu en 60 s)          │ (plus de trafic depuis N s)
 │                              ▼                              ▼
 └────────── RECYCLING ◄────────┴──────────────────────────────┘
          (podman restart, puis retour à FREE)

N'importe quel état ──(health check échoue)──► DOWN ──(de nouveau sain / relance auto)──► RECYCLING
```

| Transition | Déclencheur | Actions du broker |
|---|---|---|
| FREE → RESERVED | Un joueur sans session arrive | Jeton aléatoire + cookie, entrée HAProxy, entrée nft, purge conntrack |
| RESERVED → IN_USE | L'IP du joueur apparaît dans le set nft `seen` | — |
| RESERVED → RECYCLING | Aucun paquet UDP pendant `reserve_timeout_s` (60 s) | Révocation (voir ci-dessous) + `podman restart` |
| IN_USE → RECYCLING | L'IP a disparu du set `seen` (aucun paquet depuis `idle_timeout_s`) ou le joueur ouvre `/_kyber/leave` | Révocation + `podman restart` |
| RECYCLING → FREE | `rise` health checks réussis après le redémarrage | — |
| RECYCLING → DOWN | Redémarrage en échec, ou pas sain après `recycle_timeout_s` | — |
| * → DOWN | `fall` health checks échoués d'affilée | Révocation de la session éventuelle |
| DOWN → RECYCLING | Conteneur de nouveau sain, ou toutes les `down_retry_s` (relance auto) | `podman restart` |

**Révocation** = suppression du jeton dans HAProxy (l'ancien cookie ne mène plus nulle part),
suppression de l'IP dans les maps nft, purge des flux UDP dans conntrack.

**Invariant** : le seul chemin vers FREE passe par RECYCLING. Un joueur ne retrouve jamais le jeu
ni la session Steam du joueur précédent.

### Comment l'activité UDP est mesurée

La règle `udp dport 9000 update @seen { ip saddr }` est placée en priorité *mangle*, donc vue par
**chaque** paquet (les chaînes *nat* ne voient que le premier paquet d'un flux). Chaque paquet remet le
compte à rebours de l'IP à `idle_timeout_s`. Le broker lit simplement le set toutes les 2 s :
IP présente = trafic récent, IP absente = inactif depuis N s. Tout le comptage se fait dans le noyau.

### Auto-réparation

Toutes les `reconcile_s` secondes, le broker compare l'état voulu au système réel :
table nft effacée par un rechargement du pare-feu → reconstruite ; entrée manquante ou orpheline
→ corrigée ; HAProxy redémarré → map resynchronisée. Après une reconstruction, un délai de grâce
évite d'éjecter les joueurs en cours pendant que le set `seen` se remplit à nouveau.
Au redémarrage du broker, l'état est relu depuis `/var/lib/kyber/state.json` : les parties en cours
continuent.

## 3. Prérequis

- CachyOS, Python ≥ 3.11 (aucune bibliothèque externe)
- `sudo pacman -S --needed haproxy nftables conntrack-tools curl socat`
- Les conteneurs Kyber Podman (rootful) déjà fonctionnels, **avec une IP fixe chacun**
- Un port UDP Kyber identique dans chaque conteneur (par défaut ici : 9000)

### Point à vérifier sur Kyber avant tout

Pendant une session, dans un conteneur : `podman exec kyber-1 ss -tulpn`.
Notez le **port TCP** du serveur web (→ `web_port`) et le **port UDP** du flux (→ `udp_port`).
Mettez `public_port` égal à ce port UDP : le webclient se connecte en général au même port que celui
du serveur. Si le flux passe par WebTransport sur le port HTTPS (443/udp), mettez `public_port = 443`.

## 4. Installation

### 4.1 Conteneurs : IP fixes, aucun port publié

Le broker route directement vers l'IP de chaque conteneur. Retirez les `-p`/`--publish` et fixez l'IP :

```bash
sudo podman run -d --name kyber-1 --ip 10.88.0.11 ...   # vos options habituelles (--privileged, CDI…)
sudo podman run -d --name kyber-2 --ip 10.88.0.12 ...
sudo podman inspect -f '{{.Name}} {{.NetworkSettings.IPAddress}}' kyber-1 kyber-2
```

Avec `--network host` à la place : `ip` = IP LAN de l'hôte et des ports différents par conteneur.

### 4.2 Fichiers

```bash
sudo install -d /opt/kyber /etc/kyber
sudo install -m 755 ky_broker.py /opt/kyber/
sudo install -m 644 README.md /opt/kyber/
sudo install -m 640 broker.toml /etc/kyber/broker.toml
sudo nano /etc/kyber/broker.toml        # IP, ports, noms des conteneurs, réseau admin
sudo python3 /opt/kyber/ky_broker.py -c /etc/kyber/broker.toml check
```

### 4.3 Certificat HTTPS

Le webclient Kyber utilise des API (WebAssembly, WebCodecs, WebTransport…) que les navigateurs
réservent aux pages HTTPS. Pour le réseau local, un certificat auto-signé suffit :

```bash
sudo install -d -m 750 -g haproxy /etc/haproxy/certs
sudo openssl req -x509 -newkey rsa:2048 -nodes -days 825 -subj "/CN=kyber.lan" \
  -addext "subjectAltName=DNS:kyber.lan,IP:192.168.1.10" \
  -keyout /tmp/kyber.key -out /tmp/kyber.crt
sudo sh -c 'cat /tmp/kyber.crt /tmp/kyber.key > /etc/haproxy/certs/kyber.pem && rm /tmp/kyber.key'
sudo chmod 640 /etc/haproxy/certs/kyber.pem && sudo chgrp haproxy /etc/haproxy/certs/kyber.pem
```

Remplacez `192.168.1.10` par l'IP du serveur. Chaque client doit accepter (ou importer) le certificat
une fois. Sans HTTPS : `tls_cert = ""` et `cookie_secure = false`.

### 4.4 HAProxy

```bash
sudo install -m 644 systemd/kyber.tmpfiles.conf /etc/tmpfiles.d/kyber.conf
sudo systemd-tmpfiles --create /etc/tmpfiles.d/kyber.conf    # crée la map vide : HAProxy l'exige
sudo cp /etc/haproxy/haproxy.cfg /etc/haproxy/haproxy.cfg.orig
sudo sh -c 'python3 /opt/kyber/ky_broker.py -c /etc/kyber/broker.toml render-haproxy > /etc/haproxy/haproxy.cfg'
sudo haproxy -c -f /etc/haproxy/haproxy.cfg
sudo systemctl enable --now haproxy
```

Ajouter un conteneur = un bloc `[[slot]]` de plus, puis régénérer `haproxy.cfg` et
`sudo systemctl reload haproxy`.

### 4.5 Pare-feu

Ouvrez les deux ports d'entrée, et autorisez le **transfert** vers le réseau Podman
(le DNAT fait passer les paquets UDP dans la chaîne *forward*). Avec ufw :

```bash
sudo ufw allow 443/tcp
sudo ufw allow 9000/udp
sudo ufw route allow proto udp to 10.88.0.0/16 port 9000
```

Avec firewalld : `sudo firewall-cmd --permanent --add-port={443/tcp,9000/udp} && sudo firewall-cmd --reload`.

### 4.6 Service systemd

```bash
sudo install -m 644 systemd/ky-broker.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ky-broker
journalctl -u ky-broker -f
```

Au tout premier démarrage, le broker redémarre chaque conteneur (il ne sait pas qui les a utilisés
avant lui) : comptez quelques dizaines de secondes avant que les postes passent en FREE.

## 5. Utilisation

| Qui | Adresse | Effet |
|---|---|---|
| Joueur | `https://<serveur>/` | Attribution d'un poste libre, ou file d'attente (page qui se recharge seule) |
| Joueur | `https://<serveur>/_kyber/leave` | Termine la session tout de suite et libère le poste |
| Admin | `https://<serveur>/_kyber/admin` | Tableau des postes, bouton « Recycler » |
| Admin | `https://<serveur>/_kyber/status` | État en JSON |
| Admin | `https://<serveur>/_kyber/metrics` | Métriques Prometheus (pour Grafana) |

Les pages d'administration ne répondent qu'aux réseaux listés dans `admin_networks`.

## 6. Vérifications

```bash
sudo nft list table ip kyber                    # règles, sessions, IP actives (set seen)
echo "show map /etc/haproxy/maps/kyber-sessions.map" | sudo socat - /run/haproxy/admin.sock
sudo conntrack -L -p udp --orig-port-dst 9000    # flux UDP en cours et leur redirection
curl -sk https://127.0.0.1/_kyber/status | python3 -m json.tool
```

## 7. Tests

```bash
python3 -m unittest -v test_ky_broker.py         # 20 tests de la machine à états, sans root
sudo ./maquette/maquette.sh                      # maquette réseau réelle (~1 min), voir ci-dessous
```

La maquette crée trois namespaces réseau isolés (hôte, faux conteneurs Kyber, joueurs) avec un vrai
HAProxy et de vraies règles nftables, et déroule : attribution, load balancing, file d'attente, UDP sur
le port unique, inactivité et recyclage, rechargement du pare-feu, panne d'un conteneur.
Elle ne touche ni au réseau de l'hôte ni aux conteneurs. Sa sortie est une bonne capture pour le rapport.

## 8. Dépannage

| Symptôme | Piste |
|---|---|
| HAProxy ne démarre pas : *failed to open pattern file* | La map n'existe pas : `sudo systemd-tmpfiles --create /etc/tmpfiles.d/kyber.conf` |
| Page web OK, mais pas d'image | Port UDP : vérifier `udp_port`/`public_port` (§3), le pare-feu (§4.5), puis `sudo conntrack -L -p udp` |
| Le poste reste RESERVED puis est recyclé | Aucun paquet UDP n'arrive sur `public_port` : `sudo nft list set ip kyber seen` pendant la connexion |
| Les postes passent DOWN | `podman ps`, `curl http://10.88.0.11:8080/`, puis le journal du conteneur |
| Tests depuis le serveur lui-même | Ne marchent pas pour l'UDP : le trafic local ne passe pas par *prerouting*. Testez depuis un autre PC |
| « Préparation de votre session… » en boucle | Le broker n'arrive pas à écrire dans HAProxy : vérifier le socket `/run/haproxy/admin.sock` |

## 9. Limites connues

- **Une session par IP.** L'UDP est routé selon l'IP source : deux joueurs derrière la même box
  partageraient le même poste. Sans conséquence sur un réseau local ; pour Internet, prévoir un VPN
  (WireGuard donne une IP distincte à chaque joueur).
- **IPv4 uniquement.**
- **Un seul hôte.** Le broker gère les conteneurs d'une machine ; plusieurs serveurs demanderaient
  un état partagé.
