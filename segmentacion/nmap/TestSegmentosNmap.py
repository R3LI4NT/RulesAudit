#!/usr/bin/env python3
# Importamos las librerías necesarias que usaremos
import argparse
import ipaddress
import os
import subprocess
import shlex
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

def caracteres_archivo_remplazar(s: str) -> str:
    return s.replace("/", "_").replace(".", "-")

def archivo_XML(network: ipaddress.IPv4Network, outdir: str) -> str:
    base = f"scan_result_{network.network_address}_{network.prefixlen}.xml"
    base = caracteres_archivo_remplazar(base)
    return os.path.join(outdir, base)

def nmap_cmd(interface: str, xmlpath: str, target: str, extra_args=None):
    #Secuencia de parámetros que ejecuta Nmap, se pueden cambiar
    cmd = [
        "nmap",
        "-p-",          
        "-e", interface, 
        "--open",
        "-sS",
        "-vvv",
        "-n",
        "-oX", xmlpath,
        target
    ]
    if extra_args:
        cmd = cmd[:-2] + extra_args + cmd[-2:]
    return cmd

def correrEscaneo(target: str, interface: str, outdir: str, timeout: int, dry_run: bool, extra_args=None):
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError as e:
        return (target, False, f"Target inválido: {e}")

    xmlpath = archivo_XML(network, outdir)
    cmd = nmap_cmd(interface, xmlpath, str(network), extra_args)

    cmd_display = " ".join(shlex.quote(p) for p in cmd)
    if dry_run:
        return (target, None, cmd_display)  

    start = datetime.now()
    try:
        print(f"[{start.isoformat()}] Iniciando {target} -> {xmlpath}")
        completed = subprocess.run(cmd, check=False, stdout=None, stderr=None, timeout=timeout)
        end = datetime.now()
        elapsed = (end - start).total_seconds()
        if completed.returncode == 0 or completed.returncode == 2:
            return (target, True, f"OK (rc={completed.returncode}, {elapsed:.1f}s)")
        else:
            return (target, False, f"nmap rc={completed.returncode} ({elapsed:.1f}s)")
    except subprocess.TimeoutExpired:
        return (target, False, "TimeoutExpired")
    except Exception as e:
        return (target, False, f"Exception: {e}")

def main():
    # Parámetros disponibles que podemos usar
    parser = argparse.ArgumentParser(description="Lanza nmap en lote sobre múltiples IPs.")
    parser.add_argument("--archivo", "-a", help="Archivo con targets (uno por línea)", default=None)
    parser.add_argument("--resultado", "-r", help="Directorio output para los XML", default="nmap_resultados")
    parser.add_argument("--interfaz", "-i", help="Interfaz a usar, cambiar a segmentos a llegar", default="eth0")
    parser.add_argument("--workers", "-w", type=int, help="Nº de escaneos concurrentes", default=4)
    parser.add_argument("--timeout", "-t", type=int, help="Timeout por nmap (en segundos)", default=900)
    parser.add_argument("--dry-run", action="store_true", help="No ejecuta nmap; sino que muestra los comandos.")
    parser.add_argument("--extra-args", nargs="*", help="Argumentos adicionales para pasar a nmap", default=None)
    args = parser.parse_args()

    #Agregar la lista de segmentos a escanear con Nmap o utilizar el parámetro --archivo para especificar una lista de targets
    segmentos_lista = """
192.168.1.0/24
10.200.248.0/28
10.200.254.0/24
""".strip().splitlines()

    if args.archivo:
        if not os.path.isfile(args.archivo):
            print(f"ERROR: archivo de targets no encontrado: {args.archivo}")
            return
        with open(args.archivo, "r") as fh:
            targets = [line.strip() for line in fh if line.strip() and not line.strip().startswith("#")]
    else:
        targets = [t.strip() for t in segmentos_lista if t.strip()]

    os.makedirs(args.resultado, exist_ok=True)

    # Chequeo de permisos (nmap -sS suele necesitar root)
    try:
        es_root = (os.geteuid() == 0)
    except AttributeError:
        es_root = False

    if not es_root and not args.dry_run:
        print("AVISO: Debes ejecutar el script con Nmap o quitar el parámetro -sS")

    resultados = []
    if args.workers <= 1:
        for target in targets:
            res = correrEscaneo(target, args.interfaz, args.resultado, args.timeout, args.dry_run, args.extra_args)
            resultados.append(res)
            if args.dry_run:
                print(f"DRY-RUN: {res[2]}")
            else:
                print(f"{res[0]} -> {'OK' if res[1] else 'FALLO'} : {res[2]}")
    else:
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futures = { ex.submit(correrEscaneo, target, args.interfaz, args.resultado, args.timeout, args.dry_run, args.extra_args): target for target in targets }
            for fut in as_completed(futures):
                res = fut.result()
                resultados.append(res)
                if args.dry_run:
                    print(f"DRY-RUN: {res[2]}")
                else:
                    print(f"{res[0]} -> {'OK' if res[1] else 'FALLO'} : {res[2]}")

    ok = [r for r in resultados if r[1] is True]
    fallo = [r for r in resultados if r[1] is False]
    dry = [r for r in resultados if r[1] is None]
    print("="*60)
    print(f"Total targets: {len(resultados)}  OK: {len(ok)}  FALLO: {len(fallo)}  DRY-RUN: {len(dry)}")
    if fallo:
        print("Fallidos:")
        for t, _, reason in fallo:
            print(f"  - {t}  -> {reason}")
    print("XML generados en:", os.path.abspath(args.resultado))

if __name__ == "__main__":
    main()
