"""
server.py — Servidor central NetMonitor Aula
=============================================
Puertos:
  TCP  9998  → recibe paquetes de los clientes sniffer
  HTTP 8080  → sirve el dashboard (front/index.html) y la API REST

Endpoints REST:
  GET  /             → dashboard HTML
  GET  /api/estado   → estado global: nodos, dominios, alertas
  GET  /api/alertas  → lista de alertas generadas
  POST /api/clear    → vacía el feed (sin tocar alertas)
  GET  /reporte/<id> → HTML estático de una alerta concreta
"""

import socket
import threading
import json
import os
import time
import urllib.request
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from collections import deque

# ─── Rutas ───────────────────────────────────────────────────────
BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
FRONT_DIR    = os.path.join(BASE_DIR, 'front')
ALERTAS_CFG  = os.path.join(BASE_DIR, 'alertas.json')
REPORTES_DIR = os.path.join(BASE_DIR, 'reportes')
os.makedirs(REPORTES_DIR, exist_ok=True)

# ─── Configuración ───────────────────────────────────────────────
TCP_HOST      = '0.0.0.0'
SNIFF_PORT    = 9998
HTTP_PORT     = 8080
MAX_PAQUETES  = 500   # por equipo
MAX_GLOBAL    = 1000  # feed global reciente

# ─── Cargar dominios vigilados ───────────────────────────────────
def cargar_dominios_vigilados():
    try:
        with open(ALERTAS_CFG, 'r', encoding='utf-8') as f:
            cfg = json.load(f)
        todos = cfg.get('dominios_vigilados', []) + cfg.get('alertas_extra', [])
        return set(d.lower().strip('.') for d in todos)
    except Exception as e:
        print(f"[!] Error cargando alertas.json: {e}")
        return {'chatgpt.com', 'claude.ai', 'gemini.google.com', 'copilot.microsoft.com'}

DOMINIOS_VIGILADOS = cargar_dominios_vigilados()
print(f"[*] {len(DOMINIOS_VIGILADOS)} dominios vigilados cargados")

# ─── Estado compartido ───────────────────────────────────────────
lock = threading.Lock()

# equipos[hostname] = {
#   'ip': str, 'hostname': str, 'ultimo_visto': str,
#   'paquetes': deque, 'dominios': dict, 'alertas': list,
#   'conectado': bool
# }
equipos  = {}
feed_global = deque(maxlen=MAX_GLOBAL)  # feed de todos los equipos mezclados
alertas  = []   # lista global de alertas [{id, ts, hostname, ip, dominio, paquetes_snap}]
geoCache = {}
alerta_id_counter = 0

# ─── Geolocalización ─────────────────────────────────────────────
def obtener_geo(host):
    if host in geoCache:
        return geoCache[host]
    try:
        url = f"http://ip-api.com/json/{host}?fields=country,city,lat,lon,isp"
        req = urllib.request.Request(url, headers={'User-Agent': 'NetMonitor/1.0'})
        with urllib.request.urlopen(req, timeout=4) as resp:
            data = json.loads(resp.read().decode())
            geoCache[host] = data
            return data
    except Exception:
        return {}

# ─── Comprobación de alertas ─────────────────────────────────────
def comprobar_alerta(hostname, ip, dominio, pkt):
    global alerta_id_counter
    dominio_lower = dominio.lower().strip('.')

    # Comprobar si algún dominio vigilado está contenido en el dominio consultado
    matched = None
    for vigilado in DOMINIOS_VIGILADOS:
        if vigilado in dominio_lower or dominio_lower.endswith('.' + vigilado):
            matched = vigilado
            break

    if not matched:
        return

    # Evitar duplicados: no alertar si ya hay una alerta reciente (<60s) del mismo equipo+dominio
    ahora = datetime.now()
    with lock:
        for a in reversed(alertas[-20:]):
            if a['hostname'] == hostname and a['dominio_vigilado'] == matched:
                try:
                    prev = datetime.strptime(a['ts'], '%H:%M:%S')
                    if (ahora - prev.replace(year=ahora.year, month=ahora.month, day=ahora.day)).seconds < 60:
                        return
                except Exception:
                    pass

    print(f"[!!!] ALERTA: {hostname} ({ip}) → {dominio} [{matched}]")

    with lock:
        alerta_id_counter += 1
        aid = alerta_id_counter
        snap = list(equipos.get(hostname, {}).get('paquetes', []))

    alerta = {
        'id':              aid,
        'ts':              ahora.strftime('%H:%M:%S'),
        'fecha':           ahora.strftime('%d/%m/%Y'),
        'hostname':        hostname,
        'ip':              ip,
        'dominio':         dominio,
        'dominio_vigilado': matched,
        'pkt':             pkt,
    }

    with lock:
        alertas.append(alerta)
        if hostname in equipos:
            equipos[hostname]['alertas'].append(alerta)

    # Generar reporte HTML en background
    threading.Thread(target=generar_reporte_alerta, args=(alerta, snap), daemon=True).start()

# ─── Handler de clientes sniffer ─────────────────────────────────
def manejar_cliente(conn, addr):
    ip_cliente = addr[0]
    hostname   = None
    print(f"[+] Conexión desde {ip_cliente}")

    try:
        buffer = ""
        while True:
            datos = conn.recv(65536).decode('utf-8', errors='ignore')
            if not datos:
                break
            buffer += datos
            while '\n' in buffer:
                linea, buffer = buffer.split('\n', 1)
                linea = linea.strip()
                if not linea:
                    continue
                try:
                    msg = json.loads(linea)
                    pkts = msg.get('paquetes', [])
                    hn   = msg.get('hostname', ip_cliente)

                    if hostname is None:
                        hostname = hn
                        with lock:
                            if hostname not in equipos:
                                equipos[hostname] = {
                                    'ip':          ip_cliente,
                                    'hostname':    hostname,
                                    'ultimo_visto': datetime.now().strftime('%H:%M:%S'),
                                    'paquetes':    deque(maxlen=MAX_PAQUETES),
                                    'dominios':    {},
                                    'alertas':     [],
                                    'conectado':   True,
                                }
                            else:
                                equipos[hostname]['conectado'] = True
                                equipos[hostname]['ip'] = ip_cliente
                        print(f"  [{hostname}] identificado como {ip_cliente}")

                    with lock:
                        eq = equipos[hostname]
                        eq['ultimo_visto'] = datetime.now().strftime('%H:%M:%S')
                        for p in pkts:
                            p['hostname'] = hostname
                            p['ip_equipo'] = ip_cliente
                            eq['paquetes'].append(p)
                            feed_global.append(p)
                            dom = p.get('dominio')
                            if dom:
                                eq['dominios'][dom] = eq['dominios'].get(dom, 0) + 1

                    # Comprobar alertas fuera del lock
                    for p in pkts:
                        dom = p.get('dominio')
                        if dom:
                            comprobar_alerta(hostname, ip_cliente, dom, p)

                except json.JSONDecodeError:
                    pass

    except (ConnectionResetError, OSError):
        pass
    finally:
        if hostname:
            with lock:
                if hostname in equipos:
                    equipos[hostname]['conectado'] = False
            print(f"[-] {hostname} desconectado")
        conn.close()

# ─── Generación de reporte HTML de alerta ────────────────────────
def generar_reporte_alerta(alerta, snap_pkts):
    aid      = alerta['id']
    hostname = alerta['hostname']
    ip       = alerta['ip']
    dominio  = alerta['dominio']
    vigilado = alerta['dominio_vigilado']
    ts       = alerta['ts']
    fecha    = alerta['fecha']

    filas = ""
    for p in snap_pkts[-200:]:
        tipo  = p.get('tipo', '')
        proto = p.get('protocolo', '')
        dom   = p.get('dominio') or '—'
        es_vigilado = any(v in dom.lower() for v in DOMINIOS_VIGILADOS)

        if tipo == 'DNS':       tag = '<span class="tag tdns">DNS ▶</span>'
        elif tipo == 'DNS_RESP':tag = '<span class="tag tdnsr">DNS ◀</span>'
        elif proto == 'HTTPS':  tag = '<span class="tag thttps">HTTPS</span>'
        elif proto == 'HTTP':   tag = '<span class="tag thttp">HTTP</span>'
        else:                   tag = f'<span class="tag ttcp">{proto or "TCP"}</span>'

        row_class = ' class="alerta-row"' if es_vigilado else ''
        filas += f"""<tr{row_class}>
          <td class="mono">{p.get('ts','')}</td>
          <td>{tag}</td>
          <td class="{'dom-hi' if es_vigilado else ''}" title="{dom}">{dom[:60]}</td>
          <td class="mono muted">{p.get('ip_src','—')}</td>
          <td class="mono muted">{p.get('ip_dst','—')}</td>
          <td class="proto">{proto or '—'}</td>
          <td class="flags">{p.get('flags') or '—'}</td>
          <td class="muted">{p.get('tamano','—')}</td>
        </tr>\n"""

    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>⚠ Alerta #{aid} — {hostname}</title>
<style>
  :root{{--bg:#060a0f;--surf:#0d1520;--border:#1a2d45;--accent:#00d4ff;
    --green:#00ff9d;--warn:#ffb300;--danger:#ff3d5a;--text:#cde4f5;--muted:#4a6a8a;}}
  *{{box-sizing:border-box;margin:0;padding:0;}}
  body{{background:var(--bg);color:var(--text);font-family:'Courier New',monospace;padding:32px;}}
  body::before{{content:'';position:fixed;inset:0;
    background-image:linear-gradient(rgba(255,61,90,0.03) 1px,transparent 1px),
    linear-gradient(90deg,rgba(255,61,90,0.03) 1px,transparent 1px);
    background-size:40px 40px;pointer-events:none;z-index:0;}}
  .wrap{{position:relative;z-index:1;max-width:1300px;margin:0 auto;}}

  .alert-banner{{background:rgba(255,61,90,0.1);border:1px solid rgba(255,61,90,0.4);
    border-radius:12px;padding:24px 28px;margin-bottom:28px;}}
  .alert-title{{font-family:Arial,sans-serif;font-size:24px;font-weight:800;
    color:var(--danger);margin-bottom:12px;}}
  .alert-meta{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-top:16px;}}
  .meta-item{{background:rgba(0,0,0,0.3);border-radius:8px;padding:10px 14px;}}
  .meta-lbl{{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:4px;}}
  .meta-val{{font-size:15px;color:#fff;font-weight:bold;}}
  .meta-val.danger{{color:var(--danger);}}

  .card{{background:var(--surf);border:1px solid var(--border);border-radius:10px;overflow:hidden;margin-bottom:20px;}}
  .card-hdr{{padding:12px 18px;border-bottom:1px solid var(--border);font-family:Arial,sans-serif;
    font-weight:700;font-size:14px;color:#fff;}}
  .table-wrap{{max-height:500px;overflow-y:auto;}}
  table{{width:100%;border-collapse:collapse;font-size:11px;}}
  thead th{{padding:8px 10px;text-align:left;color:var(--muted);font-size:10px;
    text-transform:uppercase;letter-spacing:1px;border-bottom:1px solid var(--border);
    background:var(--surf);position:sticky;top:0;}}
  tbody tr{{border-bottom:1px solid rgba(26,45,69,0.4);}}
  tbody tr:hover{{background:rgba(0,212,255,0.03);}}
  .alerta-row{{background:rgba(255,61,90,0.08)!important;}}
  .alerta-row:hover{{background:rgba(255,61,90,0.14)!important;}}
  td{{padding:6px 10px;vertical-align:middle;}}
  .tag{{display:inline-block;padding:2px 7px;border-radius:10px;font-size:10px;font-weight:bold;}}
  .tdns{{background:rgba(0,212,255,0.15);color:var(--accent);}}
  .tdnsr{{background:rgba(0,212,255,0.07);color:#5aa8cc;}}
  .thttps{{background:rgba(0,255,157,0.12);color:var(--green);}}
  .thttp{{background:rgba(255,179,0,0.12);color:var(--warn);}}
  .ttcp{{background:rgba(100,100,150,0.15);color:#8899bb;}}
  .dom-hi{{color:var(--danger);font-weight:bold;}}
  .mono{{font-family:'Courier New',monospace;}}
  .muted{{color:var(--muted);font-size:10px;}}
  .proto{{color:var(--green);font-size:10px;}}
  .flags{{color:var(--warn);font-size:10px;}}
  footer{{margin-top:24px;text-align:center;font-size:11px;color:var(--muted);padding-top:16px;
    border-top:1px solid var(--border);}}
</style>
</head>
<body>
<div class="wrap">
  <div class="alert-banner">
    <div class="alert-title">⚠ ALERTA #{aid} — ACCESO A IA DETECTADO</div>
    <div style="color:var(--muted);font-size:12px;">Generado automáticamente por NetMonitor Aula · {fecha} {ts}</div>
    <div class="alert-meta">
      <div class="meta-item"><div class="meta-lbl">Equipo</div><div class="meta-val">{hostname}</div></div>
      <div class="meta-item"><div class="meta-lbl">IP</div><div class="meta-val">{ip}</div></div>
      <div class="meta-item"><div class="meta-lbl">Dominio consultado</div><div class="meta-val danger">{dominio}</div></div>
      <div class="meta-item"><div class="meta-lbl">Servicio detectado</div><div class="meta-val danger">{vigilado}</div></div>
    </div>
  </div>

  <div class="card">
    <div class="card-hdr">📦 Historial de paquetes del equipo (filas rojas = dominio vigilado)</div>
    <div class="table-wrap">
      <table>
        <thead><tr>
          <th>Hora</th><th>Tipo</th><th>Dominio</th>
          <th>IP Src</th><th>IP Dst</th><th>Proto</th><th>Flags</th><th>Bytes</th>
        </tr></thead>
        <tbody>{filas}</tbody>
      </table>
    </div>
  </div>
  <footer>NetMonitor Aula · Universidad Nebrija · Programación de Sistemas Distribuidos 2025/2026</footer>
</div>
</body>
</html>"""

    path = os.path.join(REPORTES_DIR, f'alerta_{aid}.html')
    with open(path, 'w', encoding='utf-8') as f:
        f.write(html)
    print(f"[★] Reporte alerta #{aid} guardado: {path}")

# ─── HTTP Handler ─────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        # Dashboard principal
        if self.path == '/' or self.path == '/index.html':
            self._serve_file(os.path.join(FRONT_DIR, 'index.html'), 'text/html; charset=utf-8')

        # API: estado global
        elif self.path == '/api/estado':
            with lock:
                payload = {
                    'equipos': {
                        hn: {
                            'ip':           eq['ip'],
                            'hostname':     eq['hostname'],
                            'ultimo_visto': eq['ultimo_visto'],
                            'conectado':    eq['conectado'],
                            'n_paquetes':   len(eq['paquetes']),
                            'n_alertas':    len(eq['alertas']),
                            'top_dominios': sorted(eq['dominios'].items(), key=lambda x: -x[1])[:10],
                            'ultimos_pkts': list(eq['paquetes'])[-30:],
                        }
                        for hn, eq in equipos.items()
                    },
                    'feed_global': list(feed_global)[-100:],
                    'n_alertas_total': len(alertas),
                    'dominios_vigilados': list(DOMINIOS_VIGILADOS),
                }
            self._json(payload)

        # API: alertas
        elif self.path == '/api/alertas':
            with lock:
                payload = [
                    {k: v for k, v in a.items() if k != 'pkt'}
                    for a in alertas
                ]
            self._json(payload)

        # Servir reporte estático
        elif self.path.startswith('/reporte/'):
            aid = self.path.split('/')[-1]
            path = os.path.join(REPORTES_DIR, f'alerta_{aid}.html')
            self._serve_file(path, 'text/html; charset=utf-8')

        # Ficheros estáticos del front
        elif self.path.startswith('/front/'):
            fname = self.path[7:]
            self._serve_file(os.path.join(FRONT_DIR, fname), 'text/plain')

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == '/api/clear':
            with lock:
                feed_global.clear()
                for eq in equipos.values():
                    eq['paquetes'].clear()
                    eq['dominios'].clear()
            self._json({'ok': True})
            print("[*] Feed limpiado")
        else:
            self.send_response(404)
            self.end_headers()

    def _json(self, data):
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body)

    def _serve_file(self, path, ctype):
        if os.path.exists(path):
            with open(path, 'rb') as f:
                body = f.read()
            self.send_response(200)
            self.send_header('Content-Type', ctype)
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'404 Not Found')

# ─── Arranque ────────────────────────────────────────────────────
def iniciar_http():
    srv = HTTPServer(('0.0.0.0', HTTP_PORT), Handler)
    print(f"[*] Dashboard en http://localhost:{HTTP_PORT}")
    srv.serve_forever()

def iniciar_tcp():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((TCP_HOST, SNIFF_PORT))
    srv.listen(30)
    print(f"[*] TCP:{SNIFF_PORT} esperando clientes...")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=manejar_cliente, args=(conn, addr), daemon=True).start()

if __name__ == '__main__':
    print("=" * 50)
    print("  NetMonitor Aula — Servidor Central")
    print("=" * 50)
    threading.Thread(target=iniciar_http, daemon=True).start()
    time.sleep(0.3)
    try:
        iniciar_tcp()
    except KeyboardInterrupt:
        print("\n[*] Servidor detenido.")
