"""
simulador_aula.py — Simula N equipos del aula enviando tráfico realista al servidor
====================================================================================
Cada equipo simulado tiene su propio hilo y envía paquetes DNS/TCP aleatorios.
Algunos equipos "traviesos" intentan acceder a dominios vigilados (ChatGPT, etc.)

Uso:
    python simulador_aula.py                    # 22 equipos, servidor en 127.0.0.1
    python simulador_aula.py --n 10             # 10 equipos
    python simulador_aula.py --servidor 192.168.1.5  # servidor remoto
    python simulador_aula.py --traviesos 4      # 4 equipos que usan IA
"""

import socket
import json
import time
import random
import threading
import argparse
from datetime import datetime

# ─── Configuración ───────────────────────────────────────────────
SERVIDOR_HOST  = '127.0.0.1'
SERVIDOR_PORT  = 9998
N_EQUIPOS      = 22
N_TRAVIESOS    = 3      # Cuántos equipos intentan acceder a dominios vigilados
FLUSH_INTERVAL = 3      # Segundos entre envíos
INTERVALO_PKT  = 0.4    # Segundos entre paquetes generados por equipo

# ─── Dominios normales de clase ───────────────────────────────────
DOMINIOS_NORMALES = [
    "nebrija.es", "www.nebrija.es", "moodle.nebrija.es",
    "google.com", "www.google.com", "accounts.google.com",
    "github.com", "raw.githubusercontent.com", "api.github.com",
    "stackoverflow.com", "docs.python.org", "pypi.org",
    "microsoft.com", "office.com", "teams.microsoft.com",
    "youtube.com", "www.youtube.com", "googlevideo.com",
    "fonts.googleapis.com", "ajax.googleapis.com",
    "cdn.jsdelivr.net", "cdnjs.cloudflare.com",
    "wikipedia.org", "es.wikipedia.org",
    "elpais.com", "elmundo.es", "marca.com",
    "twitch.tv", "discord.com", "spotify.com",
    "windowsupdate.microsoft.com", "update.microsoft.com",
    "ocsp.digicert.com", "clients1.google.com",
    "connectivitycheck.gstatic.com", "www.gstatic.com",
]

# ─── Dominios vigilados (los "traviesos" los usan) ───────────────
DOMINIOS_VIGILADOS = [
    "chatgpt.com", "chat.openai.com", "openai.com",
    "claude.ai", "anthropic.com",
    "copilot.microsoft.com", "gemini.google.com",
    "perplexity.ai", "you.com",
    "chegg.com", "coursehero.com",
]

# ─── IPs ficticias de destino ────────────────────────────────────
IPS_DESTINO = [
    "142.250.185.46", "104.21.45.100", "151.101.1.140",
    "185.199.108.133", "140.82.112.4", "172.217.16.142",
    "93.184.216.34", "13.107.42.14", "52.96.189.162",
    "23.211.15.236", "104.83.34.182", "162.247.241.14",
]

PUERTOS_TCP = [443, 443, 443, 443, 80, 8080]
FLAGS_TCP   = ["SYN", "ACK", "ACK | PSH", "ACK | FIN", "ACK | RST", "SYN | ACK"]

# ─── Generador de paquetes falsos ────────────────────────────────
def generar_paquete_dns(dominio, es_respuesta=False):
    ip_src = f"192.168.1.{random.randint(10,30)}"
    return {
        'ts':         datetime.now().strftime('%H:%M:%S.') + str(random.randint(100,999)),
        'tipo':       'DNS_RESP' if es_respuesta else 'DNS',
        'dominio':    dominio,
        'ip_src':     '192.168.1.1' if es_respuesta else ip_src,
        'ip_dst':     ip_src if es_respuesta else '192.168.1.1',
        'puerto_dst': 53,
        'protocolo':  'DNS',
        'tamano':     random.randint(70, 180),
        'ttl':        64 if es_respuesta else 128,
        'flags':      None,
    }

def generar_paquete_tcp(dominio=None):
    ip_equipo = f"192.168.1.{random.randint(10,30)}"
    return {
        'ts':         datetime.now().strftime('%H:%M:%S.') + str(random.randint(100,999)),
        'tipo':       'TCP',
        'dominio':    dominio,
        'ip_src':     ip_equipo,
        'ip_dst':     random.choice(IPS_DESTINO),
        'puerto_dst': random.choice(PUERTOS_TCP),
        'protocolo':  'HTTPS',
        'tamano':     random.choice([54, 66, 134, 1484, 2197, 512, 256]),
        'ttl':        128,
        'flags':      random.choice(FLAGS_TCP),
    }

# ─── Equipo simulado ─────────────────────────────────────────────
class EquipoSimulado(threading.Thread):
    def __init__(self, hostname, es_travieso=False):
        super().__init__(daemon=True)
        self.hostname    = hostname
        self.es_travieso = es_travieso
        self.cola        = []
        self.cola_lock   = threading.Lock()
        self.sock        = None
        self.running     = True
        # Los traviesos esperan un tiempo aleatorio antes de "pecar"
        self.proximo_pecado = time.time() + random.randint(15, 45)

    def conectar(self):
        while self.running:
            try:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.settimeout(10)
                self.sock.connect((SERVIDOR_HOST, SERVIDOR_PORT))
                print(f"  [+] {self.hostname} conectado {'(TRAVIESO)' if self.es_travieso else ''}")
                return True
            except Exception:
                print(f"  [!] {self.hostname} no puede conectar. Reintentando en 5s...")
                time.sleep(5)
        return False

    def generar_trafico(self):
        """Genera un lote de paquetes realistas."""
        pkts = []

        # Tráfico de fondo siempre presente
        for _ in range(random.randint(2, 6)):
            dom = random.choice(DOMINIOS_NORMALES)
            pkts.append(generar_paquete_dns(dom))
            pkts.append(generar_paquete_dns(dom, es_respuesta=True))
            pkts.append(generar_paquete_tcp(dom))
            if random.random() < 0.3:
                pkts.append(generar_paquete_tcp(dom))

        # Equipo travieso: accede a dominio vigilado después del tiempo de espera
        if self.es_travieso and time.time() > self.proximo_pecado:
            dom_malo = random.choice(DOMINIOS_VIGILADOS)
            print(f"  [!!!] {self.hostname} accediendo a {dom_malo}")
            pkts.append(generar_paquete_dns(dom_malo))
            pkts.append(generar_paquete_dns(dom_malo, es_respuesta=True))
            pkts.append(generar_paquete_tcp(dom_malo))
            pkts.append(generar_paquete_tcp(dom_malo))
            # Próximo pecado entre 30s y 2 minutos después
            self.proximo_pecado = time.time() + random.randint(30, 120)

        return pkts

    def run(self):
        if not self.conectar():
            return

        while self.running:
            pkts = self.generar_trafico()
            msg  = json.dumps({'hostname': self.hostname, 'paquetes': pkts}) + '\n'
            try:
                self.sock.sendall(msg.encode('utf-8'))
            except Exception:
                print(f"  [!] {self.hostname} perdió conexión. Reconectando...")
                try: self.sock.close()
                except: pass
                self.sock = None
                if not self.conectar():
                    break

            time.sleep(FLUSH_INTERVAL + random.uniform(-0.5, 0.5))

    def stop(self):
        self.running = False
        if self.sock:
            try: self.sock.close()
            except: pass

# ─── Main ────────────────────────────────────────────────────────
def main():
    global SERVIDOR_HOST

    parser = argparse.ArgumentParser(description='Simulador de aula NetMonitor')
    parser.add_argument('--n',         type=int, default=N_EQUIPOS,    help='Número de equipos (default: 22)')
    parser.add_argument('--traviesos', type=int, default=N_TRAVIESOS,  help='Equipos que usan dominios vigilados (default: 3)')
    parser.add_argument('--servidor',  default=SERVIDOR_HOST,           help=f'IP del servidor (default: {SERVIDOR_HOST})')
    args = parser.parse_args()

    SERVIDOR_HOST = args.servidor

    # Elegir equipos traviesos aleatoriamente
    indices_traviesos = set(random.sample(range(args.n), min(args.traviesos, args.n)))

    print("=" * 58)
    print(f"  Simulador NetMonitor Aula")
    print("=" * 58)
    print(f"  Servidor  : {SERVIDOR_HOST}:{SERVIDOR_PORT}")
    print(f"  Equipos   : {args.n}")
    print(f"  Traviesos : {args.traviesos} (accederán a dominios vigilados)")
    print(f"  Flush     : cada {FLUSH_INTERVAL}s por equipo")
    print("=" * 58)
    print()

    equipos = []
    for i in range(args.n):
        nombre      = f"PC-AULA-{i+1:02d}"
        es_travieso = i in indices_traviesos
        if es_travieso:
            print(f"  🔴 {nombre} → TRAVIESO (accederá a IA en ~{15+i*2}s)")
        else:
            print(f"  🟢 {nombre}")
        eq = EquipoSimulado(nombre, es_travieso)
        equipos.append(eq)

    print()
    print(f"  Abriendo dashboard: http://localhost:8080")
    print(f"  Ctrl+C para detener todos los equipos\n")

    # Arrancar con pequeño delay entre equipos para no saturar el servidor
    for i, eq in enumerate(equipos):
        eq.start()
        time.sleep(0.3)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Deteniendo todos los equipos simulados...")
        for eq in equipos:
            eq.stop()
        print("[*] Simulación terminada.")

if __name__ == '__main__':
    main()
