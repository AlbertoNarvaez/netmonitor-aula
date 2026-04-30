@echo off
REM ============================================================
REM  deploy_aula.bat — Despliegue SILENCIOSO con PsExec
REM  El alumno no ve ninguna ventana ni proceso visible
REM
REM  Requisitos en cada PC del aula (instalación previa):
REM    - Python instalado (pythonw.exe disponible)
REM    - Scapy:  pip install scapy
REM    - Npcap:  https://npcap.com
REM
REM  Uso:
REM    deploy_aula.bat          -> activa monitorizacion silenciosa
REM    deploy_aula.bat stop     -> detiene monitorizacion
REM    deploy_aula.bat status   -> comprueba que PCs estan activos
REM ============================================================

REM ── Configuracion ─────────────────────────────────────────────
SET SERVIDOR_IP=192.168.1.100
SET USUARIO=Administrador
SET PASS=password_del_dominio
SET PSEXEC=PsExec.exe
SET CARPETA_REMOTA=C:\NetMonitor
SET CARPETA_COMPARTIDA=\\%SERVIDOR_IP%\NetMonitor

REM Lista de equipos del aula (nombres de red o IPs)
SET EQUIPOS=PC-AULA-01 PC-AULA-02 PC-AULA-03 PC-AULA-04 PC-AULA-05 PC-AULA-06 PC-AULA-07 PC-AULA-08 PC-AULA-09 PC-AULA-10 PC-AULA-11 PC-AULA-12 PC-AULA-13 PC-AULA-14 PC-AULA-15 PC-AULA-16 PC-AULA-17 PC-AULA-18 PC-AULA-19 PC-AULA-20 PC-AULA-21 PC-AULA-22

REM ── Enrutar segun argumento ────────────────────────────────────
IF "%1"=="stop"   GOTO STOP
IF "%1"=="status" GOTO STATUS
GOTO LAUNCH


REM ════════════════════════════════════════════════════════════
:LAUNCH
REM ════════════════════════════════════════════════════════════
echo.
echo  ╔══════════════════════════════════════════╗
echo  ║   NetMonitor Aula - Despliegue silencioso ║
echo  ╚══════════════════════════════════════════╝
echo.
echo  [*] Servidor : %SERVIDOR_IP%
echo  [*] Copiando script y lanzando en cada equipo...
echo.

FOR %%E IN (%EQUIPOS%) DO (
    echo  [>>] %%E ...

    REM 1) Crear carpeta destino en el equipo remoto
    %PSEXEC% \\%%E -u %USUARIO% -p %PASS% -s ^
        cmd /c "mkdir %CARPETA_REMOTA% 2>nul" >nul 2>&1

    REM 2) Copiar client_sniffer.py desde la carpeta compartida del servidor
    REM    El servidor debe tener compartida la carpeta NetMonitor:
    REM    Ejecutar una vez en el servidor: net share NetMonitor=C:\NetMonitor /grant:everyone,read
    %PSEXEC% \\%%E -u %USUARIO% -p %PASS% -s ^
        cmd /c "xcopy /Y %CARPETA_COMPARTIDA%\client_sniffer.py %CARPETA_REMOTA%\ >nul 2>&1" >nul 2>&1

    REM 3) Lanzar con pythonw.exe — SIN VENTANA, completamente invisible
    REM    -d  no esperar a que termine (proceso en background)
    REM    -s  ejecutar como SYSTEM (necesario para captura de paquetes con Scapy)
    REM    -w  directorio de trabajo
    %PSEXEC% \\%%E -u %USUARIO% -p %PASS% -d -s -w %CARPETA_REMOTA% ^
        pythonw.exe %CARPETA_REMOTA%\client_sniffer.py --servidor %SERVIDOR_IP% >nul 2>&1

    IF ERRORLEVEL 1 (
        echo  [!!] ERROR en %%E - revisar conectividad o credenciales
    ) ELSE (
        echo  [OK] %%E - sniffer activo ^(invisible para el alumno^)
    )
)

echo.
echo  [*] Despliegue completado.
echo  [*] Dashboard en: http://%SERVIDOR_IP%:8080
echo  [*] Para detener: deploy_aula.bat stop
echo.
GOTO END


REM ════════════════════════════════════════════════════════════
:STOP
REM ════════════════════════════════════════════════════════════
echo.
echo  [*] Deteniendo NetMonitor en todos los equipos...
echo.

FOR %%E IN (%EQUIPOS%) DO (
    %PSEXEC% \\%%E -u %USUARIO% -p %PASS% -s ^
        cmd /c "taskkill /F /IM pythonw.exe >nul 2>&1" >nul 2>&1
    echo  [OK] %%E - detenido
)

echo.
echo  [*] Monitorizacion detenida en todos los equipos.
echo.
GOTO END


REM ════════════════════════════════════════════════════════════
:STATUS
REM ════════════════════════════════════════════════════════════
echo.
echo  [*] Comprobando estado de los equipos...
echo.

FOR %%E IN (%EQUIPOS%) DO (
    %PSEXEC% \\%%E -u %USUARIO% -p %PASS% -s ^
        cmd /c "tasklist /FI ""IMAGENAME eq pythonw.exe"" 2>nul | find /I ""pythonw"" >nul 2>&1" >nul 2>&1

    IF ERRORLEVEL 1 (
        echo  [--] %%E - INACTIVO
    ) ELSE (
        echo  [OK] %%E - ACTIVO ^(sniffer corriendo^)
    )
)
echo.

:END
pause
