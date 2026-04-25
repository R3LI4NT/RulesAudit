import re
import json
import os
import ipaddress
from collections import defaultdict, Counter
from datetime import datetime
import pandas as pd
from .utils import convertir_bytes


class FirewallRuleAnalyzer:

    FORMATOS = {
        'estandar': {
            'nombre': 'Formato Estandar (12 columnas)',
            'mapeo': {
                'policy': 0,
                'source': 1,
                'dest': 2,
                'schedule': 3,
                'service': 4,
                'action': 5,
                'ip_pool': 6,
                'nat': 7,
                'type': 8,
                'security_profiles': 9,
                'log': 10,
                'bytes': 11
            },
            'aliases': {
                'source': ['source', 'origen', 'src', 'from'],
                'dest': ['dest', 'destination', 'destino', 'dst', 'to'],
                'service': ['service', 'services', 'servicio', 'port', 'puerto'],
                'action': ['action', 'accion', 'disposition']
            }
        },
        'especifico': {
            'nombre': 'Formato Especifico (14 columnas)',
            'mapeo': {
                'numero': 0,
                'type': 1,
                'hits': 2,
                'first_hits': 3,
                'last_hits': 4,
                'name': 5,
                'source': 6,
                'destination': 7,
                'vpn': 8,
                'services': 9,
                'action': 10,
                'track': 11,
                'install_on': 12,
                'uid': 13
            },
            'aliases': {
                'source': ['source', 'origen', 'src', 'from'],
                'dest': ['dest', 'destination', 'destino', 'dst', 'to'],
                'service': ['service', 'services', 'servicio', 'services & applications'],
                'action': ['action', 'accion'],
                'log': ['log', 'track', 'logging']
            }
        },
        'checkpoint': {
            'nombre': 'Formato CheckPoint',
            'mapeo': {
                'number': 0,
                'name': 1,
                'source': 2,
                'destination': 3,
                'service': 4,
                'action': 5,
                'track': 6,
                'install_on': 7,
                'comments': 8,
                'uid': 9
            },
            'aliases': {
                'source': ['source', 'src'],
                'dest': ['destination', 'dst'],
                'service': ['service', 'services'],
                'log': ['track']
            }
        },
        'palo_alto': {
            'nombre': 'Formato Palo Alto (15+ columnas)',
            'mapeo': {
                'name': 0,
                'tags': 1,
                'type': 2,
                'source_zone': 3,
                'source': 4,
                'source_user': 5,
                'dest_zone': 6,
                'destination': 7,
                'application': 8,
                'service': 9,
                'action': 10,
                'profile': 11,
                'options': 12,
                'rule_usage': 13,
                'modified': 14
            },
            'aliases': {
                'source': ['source', 'src'],
                'dest': ['destination', 'dst'],
                'service': ['service', 'services', 'application'],
                'security_profiles': ['profile', 'profile setting']
            }
        }
    }

    ACCIONES_ACEPTAR = {'accept', 'allow', 'permit', 'pass', 'enable'}
    ACCIONES_DENEGAR = {'deny', 'drop', 'reject', 'block', 'disable'}
    VALORES_CUALQUIERA = {'any', 'all', 'cualquiera', '*', '0.0.0.0/0', '0.0.0.0', '::/0'}

    def __init__(self, df, vulns_file=None, formato=None):
        self.df = df
        self.headers = [str(c) for c in df.columns.tolist()]
        self.vulnerabilidades = []
        self.estadisticas = defaultdict(int)
        self.reglas_por_interface = defaultdict(list)
        self.indice_por_regla = {}
        self.config = self._cargar_configuracion(vulns_file)
        self.formato = self._detectar_formato(formato)
        self.idx_map = self.FORMATOS[self.formato]['mapeo']
        self._contador_evidencia = 0

    def _detectar_formato(self, formato_especificado=None):
        if formato_especificado and formato_especificado in self.FORMATOS:
            return formato_especificado
        num_columnas = len(self.df.columns)
        cabeceras_lower = [str(c).lower() for c in self.df.columns]
        if any('zone' in h for h in cabeceras_lower) and any('application' in h for h in cabeceras_lower):
            return 'palo_alto'
        if num_columnas >= 14:
            return 'especifico'
        elif num_columnas >= 12:
            return 'estandar'
        elif num_columnas >= 9:
            return 'checkpoint'
        return 'estandar'

    def _cargar_configuracion(self, vulns_file=None):
        config = {}
        if vulns_file is None:
            posibles_rutas = [
                'vulns.json',
                os.path.join(os.path.dirname(__file__), 'vulns.json'),
                os.path.join(os.path.dirname(os.path.dirname(__file__)), 'vulns.json'),
            ]
            for ruta in posibles_rutas:
                if os.path.exists(ruta):
                    vulns_file = ruta
                    break
        if vulns_file and os.path.exists(vulns_file):
            try:
                with open(vulns_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            except Exception:
                config = {}
        return config

    def _obtener_valor(self, row, campo):
        for key, idx in self.idx_map.items():
            if campo == key or campo in key or key in campo:
                if len(row) > idx and pd.notna(row.iloc[idx]):
                    return str(row.iloc[idx]).strip()
        formato_info = self.FORMATOS[self.formato]
        if 'aliases' in formato_info:
            for key, aliases in formato_info['aliases'].items():
                if campo in aliases and key in self.idx_map:
                    idx = self.idx_map[key]
                    if len(row) > idx and pd.notna(row.iloc[idx]):
                        return str(row.iloc[idx]).strip()
        return ""

    def _obtener_numero_regla(self, row):
        if self.formato == 'especifico':
            return self._obtener_valor(row, 'numero') or self._obtener_valor(row, 'name')
        elif self.formato == 'estandar':
            return self._obtener_valor(row, 'policy')
        elif self.formato == 'palo_alto':
            return self._obtener_valor(row, 'name')
        return self._obtener_valor(row, 'number') or self._obtener_valor(row, 'name')

    def _construir_evidencia(self, row):
        evidencia = {}
        for idx, columna in enumerate(self.headers):
            if idx < len(row):
                valor = row.iloc[idx]
                if pd.isna(valor):
                    evidencia[columna] = ""
                else:
                    evidencia[columna] = str(valor).strip()
            else:
                evidencia[columna] = ""
        return evidencia

    def _es_cualquiera(self, valor):
        if not valor:
            return True
        valor_limpio = valor.lower().strip()
        return valor_limpio in self.VALORES_CUALQUIERA or valor_limpio in ('', 'nan', 'none')

    def _es_accion_aceptar(self, valor):
        if not valor:
            return False
        return valor.lower().strip() in self.ACCIONES_ACEPTAR

    def _es_accion_denegar(self, valor):
        if not valor:
            return False
        return valor.lower().strip() in self.ACCIONES_DENEGAR

    def _es_red_privada(self, valor):
        if not valor:
            return False
        patrones_privados = [
            r'\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            r'\b192\.168\.\d{1,3}\.\d{1,3}\b',
            r'\b172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}\b',
            r'\bfc00:',
            r'\bfd[0-9a-f]{2}:'
        ]
        return any(re.search(p, valor, re.IGNORECASE) for p in patrones_privados)

    def _extraer_ips(self, valor):
        ips = []
        patron = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)'
        for coincidencia in re.findall(patron, valor):
            try:
                if '/' in coincidencia:
                    red = ipaddress.ip_network(coincidencia, strict=False)
                    ips.append(red)
                else:
                    ips.append(ipaddress.ip_address(coincidencia))
            except Exception:
                continue
        return ips

    def _separar_por_interface(self):
        seccion_actual = "General"
        for idx, row in self.df.iterrows():
            if pd.notna(row.iloc[0]) and isinstance(row.iloc[0], str):
                if ',' in row.iloc[0] and len(self.df.columns) > 1 and pd.isna(row.iloc[1]):
                    seccion_actual = row.iloc[0]
                    continue
            self.reglas_por_interface[seccion_actual].append(row)

    def analizar(self):
        self._separar_por_interface()
        self._analizar_patrones_avanzados()
        self._analizar_servicios_peligrosos()
        self._analizar_puertos_criticos()
        self._analizar_redes_expuestas()
        self._analizar_sobreposicion_reglas()
        self._analizar_reglas_duplicadas()
        self._analizar_shadows_rules()
        self._analizar_logging_faltante()
        self._analizar_perfiles_seguridad()
        self._analizar_reglas_permisivas()
        self._analizar_nat_sin_restriccion()
        self._analizar_egreso_sin_control()
        self._analizar_management_expuesto()
        if self.formato == 'especifico':
            self._analizar_especifico()
        self._verificar_compliance()
        self.vulnerabilidades = self._deduplicar_vulnerabilidades(self.vulnerabilidades)
        return self.vulnerabilidades

    def _analizar_patrones_avanzados(self):
        if 'patrones_avanzados' not in self.config:
            return
        for patron in self.config['patrones_avanzados']:
            self._aplicar_patron(patron)

    def _aplicar_patron(self, patron):
        for seccion, reglas in self.reglas_por_interface.items():
            for row in reglas:
                if self._coincide_patron(row, patron.get('condiciones', [])):
                    self._agregar_vulnerabilidad(
                        vuln_id=patron.get('id', ''),
                        tipo=patron.get('tipo', 'RIESGO'),
                        severidad=patron.get('severidad', 'MEDIA'),
                        seccion=seccion,
                        row=row,
                        descripcion=patron.get('descripcion', 'Vulnerabilidad detectada'),
                        recomendacion=patron.get('recomendacion', 'Revisar configuracion'),
                        categoria=patron.get('categoria', 'exposicion'),
                        cvss=patron.get('cvss', 5.0),
                        referencias=patron.get('referencias', [])
                    )
                    self.estadisticas[f"patron_{patron.get('nombre', 'desconocido')}"] += 1

    def _coincide_patron(self, row, condiciones):
        if not condiciones:
            return False
        for cond in condiciones:
            campo = cond.get('campo', '')
            patron_str = cond.get('patron', '')
            tipo = cond.get('tipo', 'exacto')
            negado = cond.get('negado', False)
            if '|' in campo:
                campos = campo.split('|')
                coincide = False
                for c in campos:
                    valor = self._obtener_valor(row, c)
                    if self._verificar_condicion(valor, patron_str, tipo, cond):
                        coincide = True
                        break
                if negado:
                    coincide = not coincide
                if not coincide:
                    return False
                continue
            valor = self._obtener_valor(row, campo)
            resultado = self._verificar_condicion(valor, patron_str, tipo, cond)
            if negado:
                resultado = not resultado
            if not resultado:
                return False
        return True

    def _verificar_condicion(self, valor, patron, tipo, condicion):
        if not valor and tipo != 'regex':
            return False
        valor_lower = valor.lower() if valor else ""
        if tipo == 'exacto':
            return valor == patron
        elif tipo == 'contiene':
            return patron.lower() in valor_lower if patron else False
        elif tipo == 'regex':
            try:
                return bool(re.search(patron, valor, re.IGNORECASE))
            except Exception:
                return False
        elif tipo == 'cidr':
            max_cidr = condicion.get('max_cidr', 32)
            for coincidencia in re.findall(r'/(\d{1,2})', valor):
                try:
                    if int(coincidencia) < max_cidr:
                        return True
                except Exception:
                    continue
            return False
        elif tipo == 'bytes' and 'min_valor' in condicion:
            try:
                bytes_num = convertir_bytes(valor)
                min_valor = condicion.get('min_valor', 0)
                unidad = condicion.get('unidad', 'GB')
                if unidad == 'GB':
                    min_bytes = min_valor * 1024**3
                elif unidad == 'MB':
                    min_bytes = min_valor * 1024**2
                elif unidad == 'KB':
                    min_bytes = min_valor * 1024
                else:
                    min_bytes = min_valor
                return bytes_num > min_bytes
            except Exception:
                return False
        return False

    def _analizar_servicios_peligrosos(self):
        if 'servicios_peligrosos' not in self.config:
            return
        servicios = self.config['servicios_peligrosos']
        for seccion, reglas in self.reglas_por_interface.items():
            for row in reglas:
                servicio = self._obtener_valor(row, 'service')
                action = self._obtener_valor(row, 'action')
                if not self._es_accion_aceptar(action):
                    continue
                for svc in servicios:
                    patron = svc.get('patron', '')
                    if patron and re.search(patron, servicio, re.IGNORECASE):
                        self._agregar_vulnerabilidad(
                            vuln_id=svc.get('id', ''),
                            tipo=svc.get('tipo', 'RIESGO'),
                            severidad=svc.get('severidad', 'MEDIA'),
                            seccion=seccion,
                            row=row,
                            descripcion=f"Servicio {svc.get('nombre', 'desconocido')} detectado: {svc.get('descripcion', '')}",
                            recomendacion=svc.get('recomendacion', 'Usar version segura'),
                            categoria=svc.get('categoria', 'cifrado'),
                            cvss=svc.get('cvss', 5.0),
                            referencias=svc.get('referencias', [])
                        )
                        self.estadisticas['servicios_riesgosos'] += 1

    def _analizar_puertos_criticos(self):
        if 'puertos_criticos' not in self.config:
            return
        grupos = self.config['puertos_criticos']
        for seccion, reglas in self.reglas_por_interface.items():
            for row in reglas:
                servicio = self._obtener_valor(row, 'service')
                source = self._obtener_valor(row, 'source')
                action = self._obtener_valor(row, 'action')
                if not self._es_accion_aceptar(action):
                    continue
                if not self._es_cualquiera(source) and self._es_red_privada(source):
                    continue
                for grupo_nombre, grupo_info in grupos.items():
                    if isinstance(grupo_info, dict) and 'puertos' in grupo_info:
                        for puerto, nombre_svc in grupo_info['puertos'].items():
                            if re.search(rf'\b{puerto}\b', servicio) or re.search(rf'\b{nombre_svc}\b', servicio, re.IGNORECASE):
                                self._agregar_vulnerabilidad(
                                    vuln_id=f"PORT-{puerto}",
                                    tipo='RIESGO',
                                    severidad=grupo_info.get('severidad', 'ALTA'),
                                    seccion=seccion,
                                    row=row,
                                    descripcion=f"Puerto critico {puerto} ({nombre_svc}) expuesto desde origen no confiable - {grupo_info.get('descripcion', '')}",
                                    recomendacion=f"Restringir acceso al puerto {puerto} ({nombre_svc}) a IPs especificas o mover detras de VPN/Bastion",
                                    categoria=grupo_info.get('categoria', 'exposicion'),
                                    cvss=grupo_info.get('cvss', 7.0)
                                )
                                self.estadisticas[f'puerto_critico_{grupo_nombre}'] += 1
                                break

    def _analizar_redes_expuestas(self):
        for seccion, reglas in self.reglas_por_interface.items():
            for row in reglas:
                source = self._obtener_valor(row, 'source')
                dest = self._obtener_valor(row, 'dest')
                action = self._obtener_valor(row, 'action')
                if not self._es_accion_aceptar(action):
                    continue
                for nombre_campo, texto in [('origen', source), ('destino', dest)]:
                    if not texto:
                        continue
                    mascaras = re.findall(r'/(\d{1,2})', texto)
                    for mascara in mascaras:
                        try:
                            mask_int = int(mascara)
                            if mask_int < 8:
                                severidad, cvss = 'ALTA', 7.5
                            elif mask_int < 16:
                                severidad, cvss = 'MEDIA', 6.0
                            elif mask_int < 24:
                                severidad, cvss = 'BAJA', 4.0
                            else:
                                continue
                            self._agregar_vulnerabilidad(
                                vuln_id='NET-001',
                                tipo='RIESGO',
                                severidad=severidad,
                                seccion=seccion,
                                row=row,
                                descripcion=f'Red demasiado amplia expuesta en {nombre_campo} (/{mascara})',
                                recomendacion='Segmentar en redes mas pequenas. Ideal /24 o mas especifico',
                                categoria='segmentacion',
                                cvss=cvss
                            )
                            self.estadisticas['redes_amplias'] += 1
                        except Exception:
                            continue

    def _analizar_sobreposicion_reglas(self):
        if 'reglas_shadow' not in self.config:
            return
        config_shadow = self.config['reglas_shadow']
        min_coincidencias = config_shadow.get('min_coincidencias', 2)
        campos = config_shadow.get('campos_comparar', ['source', 'dest', 'service'])
        for seccion, reglas in self.reglas_por_interface.items():
            if len(reglas) < 2:
                continue
            for i in range(len(reglas)):
                for j in range(i + 1, len(reglas)):
                    regla1 = reglas[i]
                    regla2 = reglas[j]
                    action1 = self._obtener_valor(regla1, 'action')
                    action2 = self._obtener_valor(regla2, 'action')
                    if self._es_accion_denegar(action1) and self._es_accion_aceptar(action2):
                        if self._reglas_similares(regla1, regla2, campos, min_coincidencias):
                            self._agregar_vulnerabilidad(
                                vuln_id='SHADOW-001',
                                tipo=config_shadow.get('tipo', 'RIESGO'),
                                severidad=config_shadow.get('severidad', 'MEDIA'),
                                seccion=seccion,
                                row=regla2,
                                descripcion=f"Shadow rule: regla ACCEPT ({self._obtener_numero_regla(regla2)}) ocultada por DENY previa ({self._obtener_numero_regla(regla1)})",
                                recomendacion=config_shadow.get('recomendacion', 'Revisar orden de reglas'),
                                categoria=config_shadow.get('categoria', 'higiene'),
                                cvss=config_shadow.get('cvss', 5.0)
                            )

    def _reglas_similares(self, regla1, regla2, campos, min_coincidencias):
        coincidencias = 0
        for campo in campos:
            val1 = self._obtener_valor(regla1, campo).lower()
            val2 = self._obtener_valor(regla2, campo).lower()
            if val1 and val1 == val2:
                coincidencias += 1
            elif val1 and val2 and (val1 in val2 or val2 in val1):
                coincidencias += 1
        return coincidencias >= min_coincidencias

    def _analizar_reglas_duplicadas(self):
        if 'reglas_duplicadas' not in self.config:
            return
        config_dup = self.config['reglas_duplicadas']
        campos_clave = config_dup.get('campos_clave', ['source', 'dest', 'service', 'action'])
        for seccion, reglas in self.reglas_por_interface.items():
            reglas_vistas = {}
            for row in reglas:
                clave = self._crear_clave_regla(row, campos_clave)
                if not any(clave):
                    continue
                if clave in reglas_vistas:
                    self._agregar_vulnerabilidad(
                        vuln_id='DUP-001',
                        tipo=config_dup.get('tipo', 'HIGIENE'),
                        severidad=config_dup.get('severidad', 'BAJA'),
                        seccion=seccion,
                        row=row,
                        descripcion=f"Regla duplicada (equivalente a la regla {reglas_vistas[clave]})",
                        recomendacion=config_dup.get('recomendacion', 'Consolidar reglas duplicadas'),
                        categoria=config_dup.get('categoria', 'higiene'),
                        cvss=config_dup.get('cvss', 2.5)
                    )
                else:
                    reglas_vistas[clave] = self._obtener_numero_regla(row)

    def _crear_clave_regla(self, row, campos_clave):
        componentes = []
        for campo in campos_clave:
            valor = self._obtener_valor(row, campo).lower()
            componentes.append(valor)
        return tuple(componentes)

    def _analizar_shadows_rules(self):
        for seccion, reglas in self.reglas_por_interface.items():
            destinos_deny = set()
            for row in reglas:
                destino = self._obtener_valor(row, 'dest').lower()
                action = self._obtener_valor(row, 'action')
                if self._es_accion_denegar(action) and destino and not self._es_cualquiera(destino):
                    destinos_deny.add(destino)
                if self._es_accion_aceptar(action) and destino in destinos_deny:
                    self._agregar_vulnerabilidad(
                        vuln_id='SHADOW-002',
                        tipo='RIESGO',
                        severidad='MEDIA',
                        seccion=seccion,
                        row=row,
                        descripcion=f'Regla ACCEPT para destino {destino} pero existe DENY previo hacia el mismo',
                        recomendacion='Revisar orden de reglas. Esta regla probablemente nunca se aplica',
                        categoria='higiene',
                        cvss=5.0
                    )

    def _analizar_logging_faltante(self):
        for seccion, reglas in self.reglas_por_interface.items():
            for row in reglas:
                action = self._obtener_valor(row, 'action')
                log = self._obtener_valor(row, 'log') or self._obtener_valor(row, 'track')
                source = self._obtener_valor(row, 'source')
                dest = self._obtener_valor(row, 'dest')
                if self._es_accion_aceptar(action):
                    log_lower = log.lower().strip() if log else ""
                    sin_log = log_lower in ('', 'no', 'none', 'disable', 'off', 'nan')
                    flujo_sensible = self._es_cualquiera(source) or self._es_cualquiera(dest)
                    if sin_log and flujo_sensible:
                        self._agregar_vulnerabilidad(
                            vuln_id='LOG-001',
                            tipo='RIESGO',
                            severidad='MEDIA',
                            seccion=seccion,
                            row=row,
                            descripcion='Regla ACCEPT con origen/destino amplio y sin logging habilitado',
                            recomendacion='Habilitar logging para poder auditar este flujo',
                            categoria='observabilidad',
                            cvss=5.3
                        )

    def _analizar_perfiles_seguridad(self):
        for seccion, reglas in self.reglas_por_interface.items():
            for row in reglas:
                action = self._obtener_valor(row, 'action')
                perfiles = self._obtener_valor(row, 'security_profiles')
                dest = self._obtener_valor(row, 'dest')
                if self._es_accion_aceptar(action):
                    perfiles_lower = perfiles.lower().strip() if perfiles else ""
                    sin_perfiles = perfiles_lower in ('', 'no-inspection', 'none', 'no', 'disable', 'nan')
                    if sin_perfiles and (self._es_cualquiera(dest) or 'internet' in dest.lower()):
                        self._agregar_vulnerabilidad(
                            vuln_id='PROF-001',
                            tipo='RIESGO',
                            severidad='MEDIA',
                            seccion=seccion,
                            row=row,
                            descripcion='Regla ACCEPT sin perfiles UTM hacia destino amplio o Internet',
                            recomendacion='Aplicar IPS, AV, Application Control y Web Filter cuando el destino lo amerite',
                            categoria='observabilidad',
                            cvss=5.8
                        )

    def _analizar_reglas_permisivas(self):
        for seccion, reglas in self.reglas_por_interface.items():
            for row in reglas:
                source = self._obtener_valor(row, 'source')
                dest = self._obtener_valor(row, 'dest')
                service = self._obtener_valor(row, 'service')
                action = self._obtener_valor(row, 'action')
                if not self._es_accion_aceptar(action):
                    continue
                score = 0
                if self._es_cualquiera(source):
                    score += 1
                if self._es_cualquiera(dest):
                    score += 1
                if self._es_cualquiera(service):
                    score += 1
                if score >= 2:
                    if score == 3:
                        sev, cvss = 'CRÍTICA', 9.8
                        desc = 'Regla permite ANY origen, ANY destino y ANY servicio. Bypasea completamente el firewall'
                    else:
                        sev, cvss = 'ALTA', 8.1
                        desc = f'Regla permisiva: {score} campos abiertos a ANY (source/dest/service)'
                    self._agregar_vulnerabilidad(
                        vuln_id='PERM-001',
                        tipo='RIESGO',
                        severidad=sev,
                        seccion=seccion,
                        row=row,
                        descripcion=desc,
                        recomendacion='Restringir origen, destino y servicio al minimo necesario',
                        categoria='exposicion',
                        cvss=cvss
                    )

    def _analizar_nat_sin_restriccion(self):
        for seccion, reglas in self.reglas_por_interface.items():
            for row in reglas:
                nat = self._obtener_valor(row, 'nat')
                source = self._obtener_valor(row, 'source')
                dest = self._obtener_valor(row, 'dest')
                action = self._obtener_valor(row, 'action')
                if nat and nat.lower().strip() in ('enable', 'yes', 'on', 'true'):
                    if self._es_accion_aceptar(action):
                        if self._es_cualquiera(source) or self._es_cualquiera(dest):
                            self._agregar_vulnerabilidad(
                                vuln_id='NAT-001',
                                tipo='RIESGO',
                                severidad='MEDIA',
                                seccion=seccion,
                                row=row,
                                descripcion='NAT activo con origen o destino amplio (any). Puede ocultar origen real de trafico',
                                recomendacion='Restringir el flujo NAT a origen y destino especificos',
                                categoria='segmentacion',
                                cvss=5.5
                            )

    def _analizar_egreso_sin_control(self):
        for seccion, reglas in self.reglas_por_interface.items():
            for row in reglas:
                source = self._obtener_valor(row, 'source')
                dest = self._obtener_valor(row, 'dest')
                service = self._obtener_valor(row, 'service')
                action = self._obtener_valor(row, 'action')
                if not self._es_accion_aceptar(action):
                    continue
                if self._es_red_privada(source) and self._es_cualquiera(dest) and self._es_cualquiera(service):
                    self._agregar_vulnerabilidad(
                        vuln_id='EGR-001',
                        tipo='RIESGO',
                        severidad='ALTA',
                        seccion=seccion,
                        row=row,
                        descripcion='Egreso sin control: permite trafico desde red interna hacia cualquier destino y servicio. Riesgo de exfiltracion y C2',
                        recomendacion='Implementar proxy de salida con categorizacion. Restringir servicios permitidos en egreso a HTTP/HTTPS/DNS',
                        categoria='egreso',
                        cvss=7.5
                    )

    def _analizar_management_expuesto(self):
        puertos_gestion = {
            '22': 'SSH',
            '23': 'Telnet',
            '3389': 'RDP',
            '5900': 'VNC',
            '161': 'SNMP',
            '623': 'IPMI',
            '10000': 'Webmin',
            '2375': 'Docker API',
            '10250': 'Kubelet'
        }
        for seccion, reglas in self.reglas_por_interface.items():
            for row in reglas:
                source = self._obtener_valor(row, 'source')
                service = self._obtener_valor(row, 'service')
                action = self._obtener_valor(row, 'action')
                if not self._es_accion_aceptar(action):
                    continue
                if not self._es_cualquiera(source) and self._es_red_privada(source):
                    continue
                for puerto, nombre in puertos_gestion.items():
                    if re.search(rf'\b{puerto}\b', service) or re.search(rf'\b{nombre}\b', service, re.IGNORECASE):
                        severidad = 'CRÍTICA' if puerto in ('23', '3389') else 'ALTA'
                        cvss = 9.8 if puerto in ('23', '3389') else 8.5
                        self._agregar_vulnerabilidad(
                            vuln_id=f'MGMT-{puerto}',
                            tipo='RIESGO',
                            severidad=severidad,
                            seccion=seccion,
                            row=row,
                            descripcion=f'Puerto de gestion {nombre} ({puerto}) expuesto desde red no confiable',
                            recomendacion=f'Mover {nombre} detras de VPN o Bastion. Aplicar MFA. Restringir por IP de administracion',
                            categoria='gestion',
                            cvss=cvss
                        )
                        break

    def _analizar_especifico(self):
        for seccion, reglas in self.reglas_por_interface.items():
            for row in reglas:
                type_val = self._obtener_valor(row, 'type')
                if '[Disabled]' in type_val or 'disabled' in type_val.lower():
                    self._agregar_vulnerabilidad(
                        vuln_id='INEF-001',
                        tipo='HIGIENE',
                        severidad='BAJA',
                        seccion=seccion,
                        row=row,
                        descripcion='Regla deshabilitada permanece en el ruleset',
                        recomendacion='Eliminar reglas deshabilitadas tras validar que no son necesarias',
                        categoria='higiene',
                        cvss=1.5
                    )
                hits_val = self._obtener_valor(row, 'hits')
                if 'zero' in hits_val.lower() or hits_val == '0':
                    self._agregar_vulnerabilidad(
                        vuln_id='INEF-002',
                        tipo='HIGIENE',
                        severidad='MEDIA',
                        seccion=seccion,
                        row=row,
                        descripcion='Regla sin uso detectado (Zero hits)',
                        recomendacion='Validar necesidad con el owner. Si no hay justificacion, deshabilitar y eliminar',
                        categoria='higiene',
                        cvss=4.0
                    )

    def _verificar_compliance(self):
        if 'compliance_checks' not in self.config:
            return
        ids_detectados = {v.get('ID', '') for v in self.vulnerabilidades}
        patrones_detectados = set()
        for vuln in self.vulnerabilidades:
            vid = vuln.get('ID', '')
            if vid.startswith('ADV-'):
                for patron_cfg in self.config.get('patrones_avanzados', []):
                    if patron_cfg.get('id', '') == vid:
                        patrones_detectados.add(patron_cfg.get('nombre', ''))
        hallazgos_compliance = []
        for marco, info in self.config['compliance_checks'].items():
            incumplimientos = []
            for control in info.get('controles', []):
                for patron in control.get('patrones_check', []):
                    if patron in patrones_detectados:
                        incumplimientos.append(control.get('id', ''))
                        break
            if incumplimientos:
                hallazgos_compliance.append({
                    'marco': marco,
                    'descripcion': info.get('descripcion', ''),
                    'controles_incumplidos': list(set(incumplimientos))
                })
        self.compliance_results = hallazgos_compliance

    def _deduplicar_vulnerabilidades(self, vulns):
        vistos = set()
        unicos = []
        for v in vulns:
            clave = (v.get('ID', ''), v.get('Seccion', ''), v.get('Regla', ''), v.get('Descripcion', ''))
            if clave not in vistos:
                vistos.add(clave)
                unicos.append(v)
        return unicos

    def _agregar_vulnerabilidad(self, vuln_id, tipo, severidad, seccion, row, descripcion, recomendacion, categoria='exposicion', cvss=5.0, referencias=None):
        self._contador_evidencia += 1
        regla_num = self._obtener_numero_regla(row)
        evidencia = self._construir_evidencia(row) if row is not None else {}
        self.vulnerabilidades.append({
            'ID': vuln_id,
            'Tipo': tipo,
            'Severidad': severidad,
            'Categoria': categoria,
            'CVSS': round(cvss, 1),
            'Sección': seccion if seccion else 'General',
            'Regla': regla_num if regla_num and regla_num != 'nan' else f"Row-{self._contador_evidencia}",
            'Descripción': descripcion,
            'Recomendación': recomendacion,
            'Referencias': referencias or [],
            'Evidencia': evidencia
        })

    def obtener_estadisticas(self):
        return dict(self.estadisticas)

    def obtener_compliance(self):
        return getattr(self, 'compliance_results', [])

    def obtener_resumen(self):
        total_reglas = sum(len(r) for r in self.reglas_por_interface.values())
        secciones = list(self.reglas_por_interface.keys())
        por_severidad = Counter(v['Severidad'] for v in self.vulnerabilidades)
        por_categoria = Counter(v.get('Categoria', 'otros') for v in self.vulnerabilidades)
        reglas_afectadas = {v.get('Regla', '') for v in self.vulnerabilidades}
        cvss_total = sum(v.get('CVSS', 0) for v in self.vulnerabilidades)
        cvss_prom = cvss_total / len(self.vulnerabilidades) if self.vulnerabilidades else 0
        return {
            'formato_detectado': self.FORMATOS[self.formato]['nombre'],
            'total_reglas': total_reglas,
            'total_secciones': len(secciones),
            'secciones': secciones,
            'total_vulnerabilidades': len(self.vulnerabilidades),
            'reglas_afectadas': len(reglas_afectadas),
            'por_severidad': dict(por_severidad),
            'por_categoria': dict(por_categoria),
            'cvss_promedio': round(cvss_prom, 2),
            'cvss_maximo': max((v.get('CVSS', 0) for v in self.vulnerabilidades), default=0),
            'headers_archivo': self.headers,
            'fecha_analisis': datetime.now().isoformat()
        }
