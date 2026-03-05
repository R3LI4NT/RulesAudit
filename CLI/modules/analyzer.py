import re
import json
import os
from collections import defaultdict
from .utils import convertir_bytes
import pandas as pd


class FirewallRuleAnalyzer:
    #formatos soportados con sus mapeos
    FORMATOS = {
        'estandar': {
            'nombre': 'Formato Estándar (12 columnas)',
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
                'source': ['source', 'origen', 'src'],
                'dest': ['dest', 'destination', 'destino', 'dst'],
                'service': ['service', 'services', 'servicio'],
                'action': ['action', 'accion']
            }
        },
        'especifico': {
            'nombre': 'Formato Específico (14 columnas)',
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
                'source': ['source', 'origen', 'src'],
                'dest': ['dest', 'destination', 'destino', 'dst'],
                'service': ['service', 'services', 'servicio', 'services & applications'],
                'action': ['action', 'accion']
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
                'service': ['service', 'services']
            }
        }
    }
    
    def __init__(self, df, vulns_file=None, formato=None):
        self.df = df
        self.vulnerabilidades = []
        self.estadisticas = defaultdict(int)
        self.reglas_por_interface = defaultdict(list)
        self.config = self._cargar_configuracion(vulns_file)
        self.formato = self._detectar_formato(formato)
        self.idx_map = self.FORMATOS[self.formato]['mapeo']
        
        print(f"   [+] Usando formato: {self.FORMATOS[self.formato]['nombre']}")
        
    def _detectar_formato(self, formato_especificado=None):
        if formato_especificado and formato_especificado in self.FORMATOS:
            return formato_especificado
        
        num_columnas = len(self.df.columns)
        
        if num_columnas >= 14:
            return 'especifico'
        elif num_columnas >= 12:
            return 'estandar'
        else:
            print(f"   [!] Número de columnas {num_columnas} no reconocido, usando formato estándar")
            return 'estandar'
    
    def _cargar_configuracion(self, vulns_file=None):
        config = {}
        
        if vulns_file is None:
            posibles_rutas = [
                'vulns.json',
                os.path.join(os.path.dirname(__file__), 'vulns.json'),
                os.path.join(os.path.dirname(os.path.dirname(__file__)), 'vulns.json'),
                os.path.join(os.path.expanduser('~'), '.rulesaudit', 'vulns.json')
            ]
            
            for ruta in posibles_rutas:
                if os.path.exists(ruta):
                    vulns_file = ruta
                    break
        
        if vulns_file and os.path.exists(vulns_file):
            try:
                with open(vulns_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                print(f"   [+] Configuración cargada: {vulns_file}")
            except Exception as e:
                print(f"   [!] Error cargando {vulns_file}: {e}")
                config = self._get_configuracion_default()
        else:
            print("   [!] No se encontró vulns.json, usando configuración por defecto")
            config = self._get_configuracion_default()
        
        return config
    
    def _get_configuracion_default(self):
        return {
            "severidades": {
                "CRÍTICA": {"nivel": 5, "color": "#8B0000", "icono": "💀"},
                "ALTA": {"nivel": 4, "color": "#FF0000", "icono": "🔴"},
                "MEDIA": {"nivel": 3, "color": "#FFA500", "icono": "🟠"},
                "BAJA": {"nivel": 2, "color": "#00FF00", "icono": "🟢"},
                "INFORMATIVA": {"nivel": 1, "color": "#0088FF", "icono": "🔵"}
            },
            "servicios_peligrosos": [
                {
                    "nombre": "Telnet",
                    "patron": "telnet",
                    "descripcion": "Protocolo sin cifrar",
                    "recomendacion": "Usar SSH",
                    "tipo": "RIESGO",
                    "severidad": "MEDIA"
                },
                {
                    "nombre": "FTP",
                    "patron": "ftp",
                    "descripcion": "Protocolo sin cifrar",
                    "recomendacion": "Usar SFTP/FTPS",
                    "tipo": "RIESGO",
                    "severidad": "ALTA"
                },
                {
                    "nombre": "HTTP",
                    "patron": "http(?!s)",
                    "descripcion": "Tráfico web sin cifrar",
                    "recomendacion": "Usar HTTPS",
                    "tipo": "RIESGO",
                    "severidad": "MEDIA"
                }
            ],
            "patrones_avanzados": [
                {
                    "nombre": "cualquier_origen",
                    "descripcion": "Regla que permite cualquier origen",
                    "recomendacion": "Restringir el origen a IPs específicas",
                    "tipo": "RIESGO",
                    "severidad": "ALTA",
                    "condiciones": [
                        {
                            "campo": "source",
                            "patron": "^(any|all|0.0.0.0/0)$",
                            "tipo": "regex",
                            "negado": False
                        }
                    ]
                }
            ]
        }
    
    def _obtener_valor(self, row, campo):
        # Buscar el campo en el mapeo
        for key, idx in self.idx_map.items():
            if campo in key or key in campo:
                if len(row) > idx and pd.notna(row.iloc[idx]):
                    return str(row.iloc[idx])
        
        # Si no se encuentra, buscar por alias
        formato_info = self.FORMATOS[self.formato]
        if 'aliases' in formato_info:
            for key, aliases in formato_info['aliases'].items():
                if campo in aliases and key in self.idx_map:
                    idx = self.idx_map[key]
                    if len(row) > idx and pd.notna(row.iloc[idx]):
                        return str(row.iloc[idx])
        
        return ""
    
    def _obtener_numero_regla(self, row):
        if self.formato == 'especifico':
            return self._obtener_valor(row, 'numero')
        elif self.formato == 'estandar':
            return self._obtener_valor(row, 'policy')
        else:
            return self._obtener_valor(row, 'number') or self._obtener_valor(row, 'name')
    
    def analizar(self):
        self._separar_por_interface()
        self._analizar_patrones_avanzados()
        self._analizar_servicios_peligrosos()
        self._analizar_redes_expuestas()
        self._analizar_sobreposicion_reglas()
        self._analizar_reglas_duplicadas()
        self._analizar_shadows_rules()
        
        if self.formato == 'especifico':
            self._analizar_especifico()
        
        return self.vulnerabilidades
    
    def _analizar_especifico(self):
        for seccion, reglas in self.reglas_por_interface.items():
            for row in reglas:
                # Analizar reglas deshabilitadas
                type_val = self._obtener_valor(row, 'type')
                if '[Disabled]' in type_val:
                    self._agregar_vulnerabilidad(
                        tipo='INEFICIENCIA',
                        severidad='BAJA',
                        seccion=seccion,
                        regla=self._obtener_numero_regla(row),
                        descripcion='Regla deshabilitada',
                        recomendacion='Eliminar reglas deshabilitadas para mantener configuración limpia'
                    )
                
                # Analizar reglas con cero hits
                hits_val = self._obtener_valor(row, 'hits')
                if 'Zero' in hits_val:
                    self._agregar_vulnerabilidad(
                        tipo='INEFICIENCIA',
                        severidad='MEDIA',
                        seccion=seccion,
                        regla=self._obtener_numero_regla(row),
                        descripcion='Regla sin uso (0 hits)',
                        recomendacion='Revisar necesidad de la regla'
                    )
    
    def _separar_por_interface(self):
        seccion_actual = "General"
        
        for idx, row in self.df.iterrows():
            if pd.notna(row.iloc[0]) and isinstance(row.iloc[0], str):
                if ',' in row.iloc[0] and len(self.df.columns) > 1 and pd.isna(row.iloc[1]):
                    seccion_actual = row.iloc[0]
                    continue
            
            self.reglas_por_interface[seccion_actual].append(row)
    
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
                        tipo=patron.get('tipo', 'RIESGO'),
                        severidad=patron.get('severidad', 'MEDIA'),
                        seccion=seccion,
                        regla=self._obtener_numero_regla(row),
                        descripcion=patron.get('descripcion', 'Vulnerabilidad detectada'),
                        recomendacion=patron.get('recomendacion', 'Revisar configuración')
                    )
                    
                    key = f"patron_{patron.get('nombre', 'desconocido')}"
                    self.estadisticas[key] += 1
    
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
                if not coincide and not negado:
                    return False
                elif coincide and negado:
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
        valor_lower = valor.lower()
        patron_lower = patron.lower() if isinstance(patron, str) else patron
        
        if tipo == 'exacto':
            return valor == patron
        
        elif tipo == 'contiene':
            return patron_lower in valor_lower
        
        elif tipo == 'regex':
            try:
                return bool(re.search(patron, valor, re.IGNORECASE))
            except:
                return False
        
        elif tipo == 'cidr':
            match = re.search(r'/(\d+)', valor)
            if match:
                mascara = int(match.group(1))
                max_cidr = condicion.get('max_cidr', 32)
                return mascara < max_cidr
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
            except:
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
                
                if action.upper() == 'ACCEPT':
                    for svc in servicios:
                        patron = svc.get('patron', '').lower()
                        if patron and patron in servicio.lower():
                            self._agregar_vulnerabilidad(
                                tipo=svc.get('tipo', 'RIESGO'),
                                severidad=svc.get('severidad', 'MEDIA'),
                                seccion=seccion,
                                regla=self._obtener_numero_regla(row),
                                descripcion=f"Servicio {svc.get('nombre', patron.upper())} permitido: {svc.get('descripcion', '')}",
                                recomendacion=svc.get('recomendacion', 'Usar versión segura')
                            )
                            self.estadisticas['servicios_riesgosos'] += 1
    
    def _analizar_redes_expuestas(self):
        for seccion, reglas in self.reglas_por_interface.items():
            for row in reglas:
                source = self._obtener_valor(row, 'source')
                dest = self._obtener_valor(row, 'dest')
                action = self._obtener_valor(row, 'action')
                
                if action.upper() == 'ACCEPT':
                    for texto in [source, dest]:
                        if re.search(r'/\d{1,2}', texto):
                            mascaras = re.findall(r'/(\d{1,2})', texto)
                            for mascara in mascaras:
                                if int(mascara) < 24:
                                    self._agregar_vulnerabilidad(
                                        tipo='RIESGO',
                                        severidad='MEDIA',
                                        seccion=seccion,
                                        regla=self._obtener_numero_regla(row),
                                        descripcion=f'Red demasiado amplia expuesta (/{mascara})',
                                        recomendacion='Segmentar en redes más pequeñas (ideal /24 o más específicas)'
                                    )
                                    self.estadisticas['redes_amplias'] += 1
    
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
                for j in range(i+1, len(reglas)):
                    regla1 = reglas[i]
                    regla2 = reglas[j]
                    
                    action1 = self._obtener_valor(regla1, 'action')
                    action2 = self._obtener_valor(regla2, 'action')
                    
                    if action1 == 'DENY' and action2 == 'ACCEPT':
                        if self._reglas_similares(regla1, regla2, campos, min_coincidencias):
                            self._agregar_vulnerabilidad(
                                tipo=config_shadow.get('tipo', 'RIESGO'),
                                severidad=config_shadow.get('severidad', 'MEDIA'),
                                seccion=seccion,
                                regla=f"{self._obtener_numero_regla(regla1)} vs {self._obtener_numero_regla(regla2)}",
                                descripcion=config_shadow.get('descripcion', 'Posible shadow rule'),
                                recomendacion=config_shadow.get('recomendacion', 'Revisar orden de reglas')
                            )
    
    def _reglas_similares(self, regla1, regla2, campos, min_coincidencias):
        coincidencias = 0
        for campo in campos:
            val1 = self._obtener_valor(regla1, campo)
            val2 = self._obtener_valor(regla2, campo)
            if val1 == val2:
                coincidencias += 1
        
        return coincidencias >= min_coincidencias
    
    def _analizar_reglas_duplicadas(self):
        if 'reglas_duplicadas' not in self.config:
            return
        
        config_dup = self.config['reglas_duplicadas']
        campos_clave = config_dup.get('campos_clave', ['source', 'dest', 'service', 'action'])
        
        reglas_vistas = {}
        
        for seccion, reglas in self.reglas_por_interface.items():
            for idx, row in enumerate(reglas):
                clave = self._crear_clave_regla(row, campos_clave)
                
                if clave in reglas_vistas:
                    self._agregar_vulnerabilidad(
                        tipo=config_dup.get('tipo', 'ADVERTENCIA'),
                        severidad=config_dup.get('severidad', 'BAJA'),
                        seccion=seccion,
                        regla=self._obtener_numero_regla(row),
                        descripcion=config_dup.get('descripcion', 'Regla duplicada'),
                        recomendacion=config_dup.get('recomendacion', 'Eliminar reglas duplicadas')
                    )
                else:
                    reglas_vistas[clave] = True
    
    def _crear_clave_regla(self, row, campos_clave):
        componentes = []
        for campo in campos_clave:
            valor = self._obtener_valor(row, campo)
            componentes.append(valor)
        return tuple(componentes)
    
    def _analizar_shadows_rules(self):
        for seccion, reglas in self.reglas_por_interface.items():
            destinos_deny = set()
            
            for row in reglas:
                destino = self._obtener_valor(row, 'dest')
                action = self._obtener_valor(row, 'action')
                
                if action == 'DENY' and destino not in ['all', 'any', '']:
                    destinos_deny.add(destino)
                
                if action == 'ACCEPT' and destino in destinos_deny:
                    self._agregar_vulnerabilidad(
                        tipo='RIESGO',
                        severidad='MEDIA',
                        seccion=seccion,
                        regla=self._obtener_numero_regla(row),
                        descripcion=f'Regla ACCEPT para destino {destino} pero existe DENY previo',
                        recomendacion='Revisar orden de reglas - posiblemente esta regla nunca se aplica'
                    )
    
    def _agregar_vulnerabilidad(self, tipo, severidad, seccion, regla, descripcion, recomendacion):
        self.vulnerabilidades.append({
            'Tipo': tipo,
            'Severidad': severidad,
            'Sección': seccion,
            'Regla': regla if regla and regla != 'nan' else 'N/A',
            'Descripción': descripcion,
            'Recomendación': recomendacion
        })
    
    def obtener_estadisticas(self):
        return dict(self.estadisticas)