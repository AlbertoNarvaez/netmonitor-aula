# Cómo subir NetMonitor a GitHub

## 1. Crear el repositorio en GitHub

1. Ve a https://github.com/new
2. Nombre del repo: `netmonitor-aula`
3. Descripción: `Sistema distribuido de monitorización de red en tiempo real para entornos de laboratorio`
4. Público ✓
5. **NO** marques "Add a README file" (ya tenemos uno)
6. Click en "Create repository"

## 2. Preparar la estructura local

Asegúrate de que tienes esta estructura en tu carpeta:

```
netmonitor-aula/
├── server/
│   ├── server.py
│   ├── alertas.json
│   └── front/
│       └── index.html
├── client/
│   └── client_sniffer.py
├── simulador_aula.py
├── deploy_aula.bat
├── README.md
├── .gitignore
└── docs/
    └── screenshots/
        └── dashboard_aula.png   ← pon aquí una captura del dashboard
```

## 3. Inicializar y subir

Abre una terminal en la carpeta raíz del proyecto:

```bash
git init
git add .
git commit -m "feat: NetMonitor Aula — sistema distribuido de monitorización de red"

git branch -M main
git remote add origin https://github.com/AlbertoNarvaez/netmonitor-aula.git
git push -u origin main
```

## 4. Añadir topics al repo (en GitHub)

En la página del repo, click en el engranaje ⚙ junto a "About" y añade:

```
python distributed-systems networking scapy packet-sniffer
cybersecurity real-time-monitoring dashboard university
```

## 5. Captura para el README

Haz una captura del dashboard con los 23 equipos conectados y guárdala en:
`docs/screenshots/dashboard_aula.png`

Luego:
```bash
git add docs/
git commit -m "docs: añadir captura del dashboard"
git push
```
