#!/usr/bin/env python3
import sys
import os
import time
import shlex
import socket
import shutil
import ipaddress
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QGroupBox, QLabel, QLineEdit, QSpinBox, QPushButton, QComboBox,
    QTextEdit, QFileDialog, QMessageBox, QSplitter,
    QStatusBar, QCheckBox, QTableWidget, QTableWidgetItem, QHeaderView,
    QTabWidget, QSizePolicy
)
from PyQt6.QtCore import QThread, pyqtSignal, Qt
from PyQt6.QtGui import QTextCursor, QColor, QTextCharFormat, QFont, QIcon


# ----------------------------- Helpers --------------------------------------

def sanitizar_nombre_archivo(s: str) -> str:
    return s.replace("/", "_").replace(".", "_")


def archivo_XML(network: ipaddress._BaseNetwork, outdir: str) -> str:
    base = sanitizar_nombre_archivo(f"{network.network_address}_{network.prefixlen}")
    return os.path.join(outdir, f"scan_{base}.xml")


def construir_comando_nmap(interfaz: str, xmlpath: str, target: str,
                           puertos: bool, syn: bool, open_only: bool,
                           verbose: bool, ndns: bool, extra_args=None) -> list:
    flags = []
    if puertos:
        flags.append("-p-")
    if syn:
        flags.append("-sS")
    if open_only:
        flags.append("--open")
    if verbose:
        flags.append("-vvv")
    if ndns:
        flags.append("-n")

    if extra_args:
        if isinstance(extra_args, str):
            extra_args = shlex.split(extra_args)
        flags.extend(extra_args)

    cmd = ["nmap", *flags, "-e", interfaz, "-oX", xmlpath, target]
    return cmd


def listar_interfaces():
    try:
        return sorted([name for _, name in socket.if_nameindex() if name != "lo"]) or ["eth0"]
    except Exception:
        return ["eth0", "wlan0", "ens33", "enp0s3"]


def validar_target(target: str):
    try:
        ipaddress.ip_network(target, strict=False)
        return True, ""
    except ValueError as e:
        return False, str(e)


# -------------------------  Escaneo ---------------------------------

class EscaneoWorker:
    """Encapsula un escaneo individual con un Popen que se puede terminar."""

    def __init__(self, target, interfaz, outdir, timeout, dry_run,
                 puertos, syn, open_only, verbose, ndns, extra_args, log_func):
        self.target = target
        self.interfaz = interfaz
        self.outdir = outdir
        self.timeout = timeout
        self.dry_run = dry_run
        self.puertos = puertos
        self.syn = syn
        self.open_only = open_only
        self.verbose = verbose
        self.ndns = ndns
        self.extra_args = extra_args
        self.log_func = log_func
        self.proc = None
        self._cancelled = False

    def cancelar(self):
        self._cancelled = True
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
            except Exception:
                pass

    def ejecutar(self):
        try:
            network = ipaddress.ip_network(self.target, strict=False)
        except ValueError as e:
            return (self.target, False, f"Target inválido: {e}")

        xmlpath = archivo_XML(network, self.outdir)
        cmd = construir_comando_nmap(self.interfaz, xmlpath, str(network),
                                     self.puertos, self.syn, self.open_only,
                                     self.verbose, self.ndns, self.extra_args)
        cmd_display = " ".join(shlex.quote(p) for p in cmd)

        if self.dry_run:
            self.log_func(f"[DRY-RUN][{self.target}] {cmd_display}", "dry")
            return (self.target, None, cmd_display)

        inicio = datetime.now()
        self.log_func(
            f"[{inicio.strftime('%H:%M:%S')}][{self.target}] ▶ Lanzando escaneo → {os.path.basename(xmlpath)}",
            "info",
        )
        self.log_func(f"  [{self.target}] $ {cmd_display}", "info")

        cmd_run = cmd
        if shutil.which("stdbuf"):
            cmd_run = ["stdbuf", "-oL", "-eL"] + cmd

        timeout_hit = {"flag": False}

        def matar_por_timeout():
            if self.proc and self.proc.poll() is None:
                timeout_hit["flag"] = True
                try:
                    self.proc.terminate()
                except Exception:
                    pass

        try:
            self.proc = subprocess.Popen(
                cmd_run,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,  
            )
        except FileNotFoundError:
            return (self.target, False, "nmap no encontrado en el sistema")
        except Exception as e:
            return (self.target, False, f"Excepción al lanzar nmap: {e}")

        timer = threading.Timer(self.timeout, matar_por_timeout)
        timer.daemon = True
        timer.start()

        try:
            assert self.proc.stdout is not None
            for raw in self.proc.stdout:
                if self._cancelled:
                    break
                line = raw.rstrip("\n").rstrip("\r")
                if line:
                    self.log_func(f"  [{self.target}] {line}", "normal")
            self.proc.wait()
        finally:
            timer.cancel()

        elapsed = (datetime.now() - inicio).total_seconds()

        if timeout_hit["flag"]:
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
            return (self.target, False, f"Timeout agotado ({self.timeout}s)")

        if self._cancelled:
            return (self.target, False, "Cancelado por el usuario")

        rc = self.proc.returncode
        if rc in (0, 2):
            return (self.target, True, f"OK (rc={rc}, {elapsed:.1f}s)")
        if rc is not None and rc < 0:
            return (self.target, False, f"Terminado por señal {-rc} ({elapsed:.1f}s)")
        return (self.target, False, f"nmap rc={rc} ({elapsed:.1f}s)")


class EscaneoThread(QThread):
    log_signal = pyqtSignal(str, str)
    progreso_signal = pyqtSignal(int, int)
    resultado_signal = pyqtSignal(str, object, str)
    finalizado_signal = pyqtSignal(dict)

    def __init__(self, targets, interfaz, outdir, timeout, workers, dry_run,
                 puertos, syn, open_only, verbose, ndns, extra_args):
        super().__init__()
        self.targets = targets
        self.interfaz = interfaz
        self.outdir = outdir
        self.timeout = timeout
        self.workers = workers
        self.dry_run = dry_run
        self.puertos = puertos
        self.syn = syn
        self.open_only = open_only
        self.verbose = verbose
        self.ndns = ndns
        self.extra_args = extra_args
        self._is_running = True
        self._workers_activos = []
        self._lock = threading.Lock()

    def _log(self, msg, tipo="normal"):
        self.log_signal.emit(msg, tipo)

    def _crear_worker(self, target):
        return EscaneoWorker(
            target, self.interfaz, self.outdir, self.timeout, self.dry_run,
            self.puertos, self.syn, self.open_only, self.verbose, self.ndns,
            self.extra_args, self._log
        )

    def _correr_uno(self, target):
        worker = self._crear_worker(target)
        with self._lock:
            if not self._is_running:
                return (target, False, "Cancelado antes de iniciar")
            self._workers_activos.append(worker)
        try:
            return worker.ejecutar()
        finally:
            with self._lock:
                if worker in self._workers_activos:
                    self._workers_activos.remove(worker)

    def run(self):
        total = len(self.targets)
        resultados = []
        completados = 0

        if self.workers <= 1:
            for target in self.targets:
                if not self._is_running:
                    break
                res = self._correr_uno(target)
                resultados.append(res)
                self.resultado_signal.emit(*res)
                completados += 1
                self.progreso_signal.emit(completados, total)
        else:
            with ThreadPoolExecutor(max_workers=self.workers) as ex:
                futures = {ex.submit(self._correr_uno, t): t for t in self.targets}
                for futuro in as_completed(futures):
                    if not self._is_running:
                        # No esperamos a los pendientes; ya fueron cancelados via terminate()
                        pass
                    try:
                        res = futuro.result()
                    except Exception as e:
                        res = (futures[futuro], False, f"Excepción en hilo: {e}")
                    resultados.append(res)
                    self.resultado_signal.emit(*res)
                    completados += 1
                    self.progreso_signal.emit(completados, total)

        ok = sum(1 for r in resultados if r[1] is True)
        fallo = sum(1 for r in resultados if r[1] is False)
        dry = sum(1 for r in resultados if r[1] is None)

        self._log("═" * 60, "normal")
        self._log(f"Total: {len(resultados)}   ✔ OK: {ok}   ✘ FALLO: {fallo}   ⚠ DRY: {dry}",
                  "success" if fallo == 0 else "error")
        if fallo:
            self._log("Targets con error:", "error")
            for t, _, razon in [r for r in resultados if r[1] is False]:
                self._log(f"   · {t} → {razon}", "error")
        self._log(f"XML guardados en: {os.path.abspath(self.outdir)}", "info")

        self.finalizado_signal.emit({
            "total": len(resultados), "ok": ok, "fallo": fallo, "dry": dry,
            "outdir": os.path.abspath(self.outdir)
        })

    def stop(self):
        self._is_running = False
        with self._lock:
            for w in list(self._workers_activos):
                w.cancelar()


# --------------------------- Ventana principal ------------------------------

class VentanaPrincipal(QMainWindow):

    COLORES = {
        "normal":  QColor("#7fd8ff"),
        "info":    QColor("#00d4ff"),
        "success": QColor("#5cff9d"),
        "error":   QColor("#ff6b6b"),
        "dry":     QColor("#ffd166"),
    }

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Test de Segmentación · Nmap GUI")
        self.setMinimumSize(1280, 820)
        self.setStyleSheet(self._estilo_cyberpunk())
        self.thread = None
        self._auto_scroll = True
        self._init_ui()
        self._verificar_nmap()
        self.statusBar().showMessage("Listo · Configurá los parámetros y presioná INICIAR")

    # ------------------ Estilo ------------------

    def _estilo_cyberpunk(self):
        return """
        QMainWindow {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                                        stop:0 #050a15, stop:1 #0d1830);
        }
        QWidget { background-color: transparent; font-family: "Consolas","Courier New",monospace; color: #cfeaff; }
        QGroupBox {
            font: bold 12px "Consolas";
            color: #00e5ff;
            border: 1px solid #1f6e9f;
            border-radius: 8px;
            margin-top: 14px;
            padding: 10px 8px 8px 8px;
            background-color: rgba(10, 22, 40, 0.55);
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            subcontrol-position: top left;
            left: 12px;
            padding: 0 6px;
            color: #00e5ff;
            background-color: #0a1425;
        }
        QLabel { color: #aedcff; font-size: 12px; }
        QLineEdit, QTextEdit, QSpinBox, QComboBox {
            background-color: #0a1424;
            border: 1px solid #1f6e9f;
            border-radius: 5px;
            color: #aef0ff;
            padding: 5px 7px;
            selection-background-color: #00aaff;
            selection-color: #001020;
        }
        QLineEdit:focus, QTextEdit:focus, QSpinBox:focus, QComboBox:focus {
            border: 1px solid #00e5ff;
        }
        QLineEdit[invalid="true"] { border: 1px solid #ff5555; }
        QComboBox::drop-down { border: none; width: 18px; }
        QComboBox QAbstractItemView {
            background-color: #0a1424; color: #aef0ff;
            selection-background-color: #00aaff; selection-color: #001020;
            border: 1px solid #1f6e9f;
        }
        QCheckBox { spacing: 10px; color: #cfeaff; font-size: 12px; }
        QCheckBox::indicator {
            width: 36px; height: 18px; border-radius: 9px;
            background-color: #1a2a3e; border: 1px solid #1f6e9f;
        }
        QCheckBox::indicator:checked { background-color: #00aaff; border: 1px solid #00e5ff; }
        QCheckBox::indicator:unchecked:hover { background-color: #2a3a4e; }
        QCheckBox::indicator:checked:hover { background-color: #00ccff; }

        QPushButton {
            background-color: #0f2a3f;
            border: 1px solid #1f8ec9;
            border-radius: 6px;
            color: #cfeaff;
            padding: 7px 14px;
            font: bold 12px "Consolas";
        }
        QPushButton:hover { background-color: #143a55; border-color: #00e5ff; color: #ffffff; }
        QPushButton:pressed { background-color: #082030; }
        QPushButton:disabled { background-color: #14202c; color: #5a7080; border-color: #2a3a4a; }

        QPushButton#btnStart {
            background-color: #0a3d2c;
            border: 1px solid #34e07a;
            color: #b5ffd6;
            padding: 10px 18px;
            font: bold 13px "Consolas";
        }
        QPushButton#btnStart:hover { background-color: #115a3f; border-color: #5cff9d; color: #ffffff; }
        QPushButton#btnStart:disabled { background-color: #14202c; color: #5a7080; border-color: #2a4a3a; }

        QPushButton#btnStop {
            background-color: #3a1a1a;
            border: 1px solid #ff5555;
            color: #ffb0b0;
            padding: 10px 18px;
            font: bold 13px "Consolas";
        }
        QPushButton#btnStop:hover { background-color: #5a2222; border-color: #ff8888; color: #ffffff; }

        QProgressBar {
            border: 1px solid #1f6e9f; border-radius: 5px;
            text-align: center; color: #001020;
            background-color: #0a1424; height: 18px;
            font-weight: bold;
        }
        QProgressBar::chunk {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                        stop:0 #00aaff, stop:1 #00ffd1);
            border-radius: 4px;
        }
        QSplitter::handle { background-color: #14304a; width: 2px; }
        QStatusBar { background-color: #06101e; color: #00e5ff; border-top: 1px solid #14304a; }
        QStatusBar QLabel { color: #00e5ff; }
        QToolTip {
            background-color: #0a1425; color: #aef0ff;
            border: 1px solid #00e5ff; padding: 4px;
        }
        QTabWidget::pane { border: 1px solid #1f6e9f; border-radius: 6px; top: -1px; background: rgba(10,22,40,0.55); }
        QTabBar::tab {
            background: #0a1424; color: #7fb8d8;
            padding: 6px 14px; border: 1px solid #1f6e9f;
            border-bottom: none; border-top-left-radius: 6px; border-top-right-radius: 6px;
            margin-right: 2px;
        }
        QTabBar::tab:selected { background: #143a55; color: #00e5ff; }
        QTabBar::tab:hover { color: #00e5ff; }
        QTableWidget {
            background-color: #06101e; alternate-background-color: #0a1830;
            color: #cfeaff; gridline-color: #1f4060;
            selection-background-color: #14507a; selection-color: #ffffff;
            border: 1px solid #1f6e9f; border-radius: 6px;
        }
        QHeaderView::section {
            background-color: #0f2a3f; color: #00e5ff;
            padding: 6px; border: none; border-right: 1px solid #14304a;
            font-weight: bold;
        }
        QScrollBar:vertical, QScrollBar:horizontal {
            background: #0a1424; border: none;
        }
        QScrollBar::handle {
            background: #1f6e9f; border-radius: 4px; min-height: 20px;
        }
        QScrollBar::handle:hover { background: #00aaff; }
        QScrollBar:vertical { width: 10px; }
        QScrollBar:horizontal { height: 10px; }
        QScrollBar::add-line, QScrollBar::sub-line { background: none; border: none; }
        """

    # ------------------ UI ------------------

    def _init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(10, 10, 10, 6)
        root.setSpacing(10)

        # Header
        header = QLabel("TEST DE SEGMENTACIÓN · NMAP GUI")
        header.setStyleSheet("color: #00e5ff; font: bold 16px 'Consolas'; padding: 4px 2px;")
        root.addWidget(header)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)
        root.addWidget(splitter, 1)

        splitter.addWidget(self._construir_panel_izquierdo())
        splitter.addWidget(self._construir_panel_derecho())
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([430, 850])

        # Status bar
        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self.lbl_estado = QLabel("⚙ Inactivo")
        self.lbl_estado.setStyleSheet("padding: 0 10px;")
        self.status.addPermanentWidget(self.lbl_estado)

    def _construir_panel_izquierdo(self):
        panel = QWidget()
        lay = QVBoxLayout(panel)
        lay.setSpacing(10)
        lay.setContentsMargins(2, 2, 2, 2)

        # Parámetros
        gp_params = QGroupBox("⚙  PARÁMETROS DE ESCANEO")
        v = QVBoxLayout(gp_params)
        self.chk_puertos = QCheckBox("Escaneo full puertos  (-p-)")
        self.chk_syn     = QCheckBox("SYN scan  (-sS)   [requiere root]")
        self.chk_open    = QCheckBox("Sólo puertos abiertos  (--open)")
        self.chk_verbose = QCheckBox("Verbose extremo  (-vvv)")
        self.chk_ndns    = QCheckBox("Sin resolución DNS  (-n)")
        for c in (self.chk_puertos, self.chk_syn, self.chk_open, self.chk_verbose, self.chk_ndns):
            c.setChecked(True)
            c.toggled.connect(self._actualizar_preview)
            v.addWidget(c)
        self.chk_puertos.setToolTip("Escanea los 65535 puertos TCP")
        self.chk_syn.setToolTip("Escaneo SYN sigiloso (necesita privilegios de root)")
        self.chk_open.setToolTip("Muestra solo puertos abiertos")
        self.chk_verbose.setToolTip("Salida detallada del escaneo")
        self.chk_ndns.setToolTip("Evita consultas DNS inversas")
        lay.addWidget(gp_params)

        # Salida
        gp_out = QGroupBox("📁  GUARDAR RESULTADOS")
        g = QGridLayout(gp_out)
        g.setHorizontalSpacing(8); g.setVerticalSpacing(6)
        g.addWidget(QLabel("Ruta:"), 0, 0)
        self.txt_ruta_base = QLineEdit(os.getcwd())
        self.txt_ruta_base.setToolTip("Directorio base donde se creará la carpeta de resultados")
        g.addWidget(self.txt_ruta_base, 0, 1)
        btn_ex = QPushButton("Examinar…")
        btn_ex.clicked.connect(self._seleccionar_directorio)
        g.addWidget(btn_ex, 0, 2)
        g.addWidget(QLabel("Carpeta:"), 1, 0)
        self.txt_nombre_carpeta = QLineEdit("nmap_resultados")
        self.txt_nombre_carpeta.setToolTip("Subcarpeta donde se guardarán los XML")
        g.addWidget(self.txt_nombre_carpeta, 1, 1, 1, 2)
        lay.addWidget(gp_out)

        # Red / concurrencia
        gp_red = QGroupBox("🌐  INTERFAZ Y CONCURRENCIA")
        g2 = QGridLayout(gp_red)
        g2.setHorizontalSpacing(8); g2.setVerticalSpacing(6)
        g2.addWidget(QLabel("Interfaz:"), 0, 0)
        self.cmb_interfaz = QComboBox()
        self.cmb_interfaz.setEditable(True)
        self.cmb_interfaz.addItems(listar_interfaces())
        self.cmb_interfaz.setToolTip("Interfaz de red de salida para nmap")
        self.cmb_interfaz.currentTextChanged.connect(self._actualizar_preview)
        g2.addWidget(self.cmb_interfaz, 0, 1)
        btn_refrescar = QPushButton("⟳")
        btn_refrescar.setMaximumWidth(34)
        btn_refrescar.setToolTip("Refrescar lista de interfaces")
        btn_refrescar.clicked.connect(self._refrescar_interfaces)
        g2.addWidget(btn_refrescar, 0, 2)

        g2.addWidget(QLabel("Hilos:"), 1, 0)
        self.spin_workers = QSpinBox()
        self.spin_workers.setRange(1, 32); self.spin_workers.setValue(4)
        self.spin_workers.setToolTip("Escaneos en paralelo")
        g2.addWidget(self.spin_workers, 1, 1, 1, 2)

        g2.addWidget(QLabel("Timeout:"), 2, 0)
        self.spin_timeout = QSpinBox()
        self.spin_timeout.setRange(60, 14400); self.spin_timeout.setValue(900)
        self.spin_timeout.setSuffix("  s")
        self.spin_timeout.setToolTip("Tiempo máximo por cada escaneo nmap")
        g2.addWidget(self.spin_timeout, 2, 1, 1, 2)
        lay.addWidget(gp_red)

        # Extra
        gp_extra = QGroupBox("🔧  ARGUMENTOS ADICIONALES")
        ve = QVBoxLayout(gp_extra)
        self.txt_extra = QLineEdit()
        self.txt_extra.setPlaceholderText("Ej:  --stats-every 30s --min-rate 1000 --max-retries 1")
        self.txt_extra.setText("--stats-every 30s")
        self.txt_extra.setToolTip("Parámetros extra que se pasarán a nmap.\n"
                                  "--stats-every 30s te muestra progreso cada 30s sin tener que pulsar nada.")
        self.txt_extra.textChanged.connect(self._actualizar_preview)
        ve.addWidget(self.txt_extra)
        self.chk_dryrun = QCheckBox("⚠  Modo DRY-RUN  (solo mostrar comandos)")
        self.chk_dryrun.setToolTip("No ejecuta nmap, solo muestra los comandos que se lanzarían")
        ve.addWidget(self.chk_dryrun)
        lay.addWidget(gp_extra)

        # Preview
        gp_prev = QGroupBox("👁  COMANDO QUE SE EJECUTARÁ (preview)")
        vp = QVBoxLayout(gp_prev)
        self.txt_preview = QTextEdit()
        self.txt_preview.setReadOnly(True)
        self.txt_preview.setMaximumHeight(70)
        self.txt_preview.setStyleSheet("background-color: #03070f; color: #5cff9d; font-size: 11px;")
        vp.addWidget(self.txt_preview)
        lay.addWidget(gp_prev)

        # Botones acción
        hb = QHBoxLayout()
        self.btn_iniciar = QPushButton("▶️  INICIAR ESCÁNEO")
        self.btn_iniciar.setObjectName("btnStart")
        self.btn_iniciar.clicked.connect(self._iniciar_escaneo)
        self.btn_detener = QPushButton("⏸️  DETENER")
        self.btn_detener.setObjectName("btnStop")
        self.btn_detener.clicked.connect(self._detener_escaneo)
        self.btn_detener.setEnabled(False)
        hb.addWidget(self.btn_iniciar, 2)
        hb.addWidget(self.btn_detener, 1)
        lay.addLayout(hb)

        lay.addStretch(1)
        return panel

    def _construir_panel_derecho(self):
        panel = QWidget()
        lay = QVBoxLayout(panel)
        lay.setSpacing(10)
        lay.setContentsMargins(2, 2, 2, 2)

        # Targets
        gp_t = QGroupBox("🛜  SEGMENTOS  ( IP por línea)")
        vt = QVBoxLayout(gp_t)
        self.txt_targets = QTextEdit()
        self.txt_targets.setPlainText("192.168.1.0/24\n10.200.248.0/28\n10.200.254.0/24")
        self.txt_targets.setToolTip("Una red o IP por línea. Ej: 192.168.1.0/24  ó  10.0.0.1")
        self.txt_targets.setMaximumHeight(140)
        self.txt_targets.textChanged.connect(self._validar_targets)
        vt.addWidget(self.txt_targets)
        self.lbl_targets_info = QLabel("0 objetivos · 0 inválidos")
        self.lbl_targets_info.setStyleSheet("color: #7fb8d8; font-size: 11px;")
        vt.addWidget(self.lbl_targets_info)
        hbt = QHBoxLayout()
        b1 = QPushButton("📂  Cargar archivo");  b1.clicked.connect(self._cargar_targets)
        b2 = QPushButton("🗑  Limpiar");          b2.clicked.connect(self.txt_targets.clear)
        hbt.addWidget(b1); hbt.addWidget(b2); hbt.addStretch(1)
        vt.addLayout(hbt)
        lay.addWidget(gp_t)

        # Tabs: consola + tabla
        tabs = QTabWidget()

        # --- Consola ---
        w_console = QWidget()
        vc = QVBoxLayout(w_console); vc.setContentsMargins(6, 6, 6, 6)
        self.txt_log = QTextEdit()
        self.txt_log.setReadOnly(True)
        self.txt_log.setStyleSheet("background-color: #03070f; font-size: 11px;")
        f = QFont("Consolas"); f.setStyleHint(QFont.StyleHint.Monospace); f.setPointSize(10)
        self.txt_log.setFont(f)
        vc.addWidget(self.txt_log, 1)
        hbc = QHBoxLayout()
        self.chk_autoscroll = QCheckBox("Auto-scroll")
        self.chk_autoscroll.setChecked(True)
        self.chk_autoscroll.toggled.connect(lambda v: setattr(self, "_auto_scroll", v))
        bclr = QPushButton("🧹  Limpiar"); bclr.clicked.connect(self.txt_log.clear)
        bsav = QPushButton("💾  Guardar log"); bsav.clicked.connect(self._guardar_log)
        bopen = QPushButton("📁  Abrir carpeta resultados"); bopen.clicked.connect(self._abrir_outdir)
        hbc.addWidget(self.chk_autoscroll); hbc.addStretch(1)
        hbc.addWidget(bopen); hbc.addWidget(bclr); hbc.addWidget(bsav)
        vc.addLayout(hbc)
        tabs.addTab(w_console, "📡  Consola")

        # --- Tabla resultados ---
        w_table = QWidget()
        vtab = QVBoxLayout(w_table); vtab.setContentsMargins(6, 6, 6, 6)
        self.tbl = QTableWidget(0, 3)
        self.tbl.setHorizontalHeaderLabels(["Target", "Estado", "Detalle"])
        self.tbl.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.tbl.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.tbl.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.tbl.verticalHeader().setVisible(False)
        self.tbl.setAlternatingRowColors(True)
        vtab.addWidget(self.tbl)
        tabs.addTab(w_table, "📊  Resultados")

        lay.addWidget(tabs, 1)
        # Lanzar primera generación de preview
        self._actualizar_preview()
        self._validar_targets()
        return panel

    # ------------------ Acciones ------------------

    def _verificar_nmap(self):
        if shutil.which("nmap") is None:
            QMessageBox.critical(self, "nmap no encontrado",
                                 "No se encontró el binario 'nmap' en el PATH.\n"
                                 "Instalalo con:  sudo apt install nmap")
            self.btn_iniciar.setEnabled(False)
            self.lbl_estado.setText("✘  nmap no está instalado")

    def _refrescar_interfaces(self):
        actual = self.cmb_interfaz.currentText()
        self.cmb_interfaz.clear()
        self.cmb_interfaz.addItems(listar_interfaces())
        if actual:
            self.cmb_interfaz.setCurrentText(actual)

    def _seleccionar_directorio(self):
        d = QFileDialog.getExistingDirectory(self, "Seleccionar directorio base")
        if d:
            self.txt_ruta_base.setText(d)

    def _cargar_targets(self):
        archivo, _ = QFileDialog.getOpenFileName(self, "Cargar lista de objetivos", "",
                                                 "Archivos texto (*.txt);;Todos los archivos (*)")
        if archivo:
            try:
                with open(archivo, "r", encoding="utf-8") as f:
                    lineas = [l.strip() for l in f
                              if l.strip() and not l.strip().startswith("#")]
                self.txt_targets.setPlainText("\n".join(lineas))
                self._log(f"✅ Objetivos cargados desde {archivo}", "success")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"No se pudo leer el archivo:\n{e}")

    def _guardar_log(self):
        ruta, _ = QFileDialog.getSaveFileName(self, "Guardar log", "log_nmap.txt",
                                              "Archivos de texto (*.txt)")
        if ruta:
            try:
                with open(ruta, "w", encoding="utf-8") as f:
                    f.write(self.txt_log.toPlainText())
                self.status.showMessage(f"Log guardado en {ruta}", 4000)
            except Exception as e:
                QMessageBox.critical(self, "Error", f"No se pudo guardar el log:\n{e}")

    def _abrir_outdir(self):
        outdir = self._obtener_outdir()
        if not os.path.isdir(outdir):
            self.status.showMessage("La carpeta de resultados todavía no existe", 4000)
            return
        try:
            if sys.platform.startswith("linux"):
                subprocess.Popen(["xdg-open", outdir])
            elif sys.platform == "darwin":
                subprocess.Popen(["open", outdir])
            elif sys.platform.startswith("win"):
                os.startfile(outdir)  # type: ignore
        except Exception as e:
            self.status.showMessage(f"No se pudo abrir: {e}", 4000)

    def _log(self, mensaje, tipo="normal"):
        cursor = self.txt_log.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        fmt = QTextCharFormat()
        fmt.setForeground(self.COLORES.get(tipo, self.COLORES["normal"]))
        cursor.insertText(mensaje + "\n", fmt)
        if self._auto_scroll:
            self.txt_log.setTextCursor(cursor)
            self.txt_log.ensureCursorVisible()

    def _obtener_outdir(self):
        base = self.txt_ruta_base.text().strip() or os.getcwd()
        carpeta = self.txt_nombre_carpeta.text().strip() or "nmap_resultados"
        return os.path.join(base, carpeta)

    def _leer_targets(self):
        return [l.strip() for l in self.txt_targets.toPlainText().splitlines() if l.strip()]

    def _validar_targets(self):
        targets = self._leer_targets()
        invalidos = [t for t in targets if not validar_target(t)[0]]
        total = len(targets)
        bad = len(invalidos)
        color = "#5cff9d" if bad == 0 and total > 0 else ("#ff6b6b" if bad else "#7fb8d8")
        self.lbl_targets_info.setStyleSheet(f"color: {color}; font-size: 11px;")
        if bad:
            self.lbl_targets_info.setText(f"{total} objetivos · {bad} inválidos: {', '.join(invalidos[:3])}{'…' if bad>3 else ''}")
        else:
            self.lbl_targets_info.setText(f"{total} objetivos · todos válidos")
        self._actualizar_preview()

    def _actualizar_preview(self, *_):
        targets = self._leer_targets()
        target = targets[0] if targets else "<TARGET>"
        try:
            net = ipaddress.ip_network(target, strict=False)
            target_str = str(net)
            xml = archivo_XML(net, self._obtener_outdir())
        except Exception:
            target_str = target
            xml = os.path.join(self._obtener_outdir(), "scan_<target>.xml")
        cmd = construir_comando_nmap(
            self.cmb_interfaz.currentText().strip() or "<iface>",
            xml, target_str,
            self.chk_puertos.isChecked(), self.chk_syn.isChecked(),
            self.chk_open.isChecked(), self.chk_verbose.isChecked(),
            self.chk_ndns.isChecked(),
            self.txt_extra.text().strip() or None,
        )
        self.txt_preview.setPlainText(" ".join(shlex.quote(p) for p in cmd))

    def _agregar_fila_tabla(self, target, exito, mensaje):
        row = self.tbl.rowCount()
        self.tbl.insertRow(row)
        self.tbl.setItem(row, 0, QTableWidgetItem(target))
        if exito is True:
            estado, color = "✔ OK", QColor("#5cff9d")
        elif exito is False:
            estado, color = "✘ FALLO", QColor("#ff6b6b")
        else:
            estado, color = "⚠ DRY-RUN", QColor("#ffd166")
        item = QTableWidgetItem(estado)
        item.setForeground(color)
        font = item.font(); font.setBold(True); item.setFont(font)
        self.tbl.setItem(row, 1, item)
        self.tbl.setItem(row, 2, QTableWidgetItem(mensaje))

    # ------------------ Ciclo de escaneo ------------------

    def _iniciar_escaneo(self):
        targets = self._leer_targets()
        if not targets:
            QMessageBox.warning(self, "Sin objetivos", "Debés especificar al menos una red o IP.")
            return

        invalidos = [t for t in targets if not validar_target(t)[0]]
        if invalidos:
            QMessageBox.critical(self, "Targets inválidos",
                                 "Los siguientes targets no son IP/CIDR válidos:\n\n  · " +
                                 "\n  · ".join(invalidos))
            return

        outdir = self._obtener_outdir()
        try:
            os.makedirs(outdir, exist_ok=True)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"No se puede crear el directorio de salida:\n{e}")
            return

        interfaz = self.cmb_interfaz.currentText().strip()
        if not interfaz:
            QMessageBox.warning(self, "Interfaz", "Debés especificar una interfaz de red.")
            return

        syn = self.chk_syn.isChecked()
        dry_run = self.chk_dryrun.isChecked()

        if syn and not dry_run and hasattr(os, "geteuid") and os.geteuid() != 0:
            r = QMessageBox.warning(
                self, "Permisos insuficientes",
                "El escaneo SYN (-sS) necesita privilegios de root.\n"
                "Probablemente fallará.\n\n¿Continuar igualmente?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if r != QMessageBox.StandardButton.Yes:
                return

        # limpiar tabla
        self.tbl.setRowCount(0)

        self.thread = EscaneoThread(
            targets, interfaz, outdir,
            self.spin_timeout.value(), self.spin_workers.value(), dry_run,
            self.chk_puertos.isChecked(), syn,
            self.chk_open.isChecked(), self.chk_verbose.isChecked(),
            self.chk_ndns.isChecked(),
            self.txt_extra.text().strip() or None,
        )
        self.thread.log_signal.connect(self._log)
        self.thread.progreso_signal.connect(self._actualizar_progreso)
        self.thread.resultado_signal.connect(self._mostrar_resultado)
        self.thread.finalizado_signal.connect(self._escaneo_finalizado)

        self.btn_iniciar.setEnabled(False)
        self.btn_detener.setEnabled(True)
        self.lbl_estado.setText("🔄  Iniciando…")
        self._log("═" * 60, "info")
        self._log(f"▶  ESCÁNER INICIADO  ·  {len(targets)} objetivos  ·  {self.spin_workers.value()} hilos",
                  "success")
        self._log("═" * 60, "info")
        self.thread.start()

    def _actualizar_progreso(self, actual, total):
        if total > 0:
            self.lbl_estado.setText(f"📡  Escaneando  {actual}/{total}")

    def _mostrar_resultado(self, target, exito, mensaje):
        if exito is True:
            self._log(f"  ✔  {target}  →  {mensaje}", "success")
        elif exito is False:
            self._log(f"  ✘  {target}  →  {mensaje}", "error")
        else:
            self._log(f"  ⚠  {target}  →  DRY-RUN", "dry")
        self._agregar_fila_tabla(target, exito, mensaje)

    def _escaneo_finalizado(self, resumen):
        self.btn_iniciar.setEnabled(True)
        self.btn_detener.setEnabled(False)
        self.lbl_estado.setText(
            f"✔  Finalizado  ·  OK {resumen['ok']} · Fallo {resumen['fallo']} · Dry {resumen['dry']}"
        )
        self._log("🏁  ESCÁNER TERMINADO", "success")
        self.status.showMessage(f"Proceso completado · XML en {resumen['outdir']}", 8000)

    def _detener_escaneo(self):
        if self.thread and self.thread.isRunning():
            self._log("⚠  DETENIENDO ESCÁNER  (matando procesos nmap activos)…", "error")
            self.thread.stop()
            self.btn_detener.setEnabled(False)
            self.lbl_estado.setText("🛑  Deteniendo…")

    def closeEvent(self, event):
        if self.thread and self.thread.isRunning():
            r = QMessageBox.question(
                self, "Salir",
                "Hay un escaneo en curso. ¿Detenerlo y salir?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if r != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
            self.thread.stop()
            self.thread.wait(3000)
        event.accept()


# --------------------------- main ------------------------------------------

def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setApplicationName("Nmap Segmentation Tester")
    ventana = VentanaPrincipal()
    ventana.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
