#Módulo para análisis de vulnerabilidades en reglas de firewall usando el motor vulns.json

import re
import json
import os
from collections import defaultdict
from .utils import convertir_bytes
import pandas as pd


class FirewallRuleAnalyzer:
    
    def __init__(self, df, vulns_file=None):
        self.df = df
        self.vulnerabilidades = []
        self.estadisticas = defaultdict(int)
        self.reglas_por_interface = defaultdict(list)
        self.config = self._cargar_configuracion(vulns_file)
        
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
                }
            ]
        }
        
    def analizar(self):
        self._separar_por_interface()
        self._analizar_patrones_avanzados()
        self._analizar_servicios_peligrosos()
        self._analizar_redes_expuestas()
        self._analizar_sobreposicion_reglas()
        self._analizar_reglas_duplicadas()
        self._analizar_shadows_rules()
        return self.vulnerabilidades
    
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
                        regla=row.iloc[0],
                        descripcion=patron.get('descripcion', 'Vulnerabilidad detectada'),
                        recomendacion=patron.get('recomendacion', 'Revisar configuración')
                    )
                    
                    key = f"patron_{patron.get('nombre', 'desconocido')}"
                    self.estadisticas[key] += 1
    
    def _coincide_patron(self, row, condiciones):
        if not condiciones:
            return False
        
        idx_map = {
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
        }
        
        for cond in condiciones:
            campo = cond.get('campo', '')
            patron_str = cond.get('patron', '')
            tipo = cond.get('tipo', 'exacto')
            negado = cond.get('negado', False)
            
            if '|' in campo:
                campos = campo.split('|')
                coincide = False
                for c in campos:
                    if c in idx_map:
                        valor = str(row.iloc[idx_map[c]]) if len(row) > idx_map[c] and pd.notna(row.iloc[idx_map[c]]) else ""
                        if self._verificar_condicion(valor, patron_str, tipo, cond):
                            coincide = True
                            break
                if not coincide and not negado:
                    return False
                elif coincide and negado:
                    return False
                continue
            
            if campo not in idx_map:
                continue
                
            valor = str(row.iloc[idx_map[campo]]) if len(row) > idx_map[campo] and pd.notna(row.iloc[idx_map[campo]]) else ""
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
                if len(row) < 5:
                    continue
                    
                servicio = str(row.iloc[4]) if pd.notna(row.iloc[4]) else ""
                action = str(row.iloc[5]) if pd.notna(row.iloc[5]) else ""
                
                if action.upper() == 'ACCEPT':
                    for svc in servicios:
                        patron = svc.get('patron', '').lower()
                        if patron and patron in servicio.lower():
                            self._agregar_vulnerabilidad(
                                tipo=svc.get('tipo', 'RIESGO'),
                                severidad=svc.get('severidad', 'MEDIA'),
                                seccion=seccion,
                                regla=row.iloc[0],
                                descripcion=f"Servicio {svc.get('nombre', patron.upper())} permitido: {svc.get('descripcion', '')}",
                                recomendacion=svc.get('recomendacion', 'Usar versión segura')
                            )
                            self.estadisticas['servicios_riesgosos'] += 1
    
    def _analizar_redes_expuestas(self):
        for seccion, reglas in self.reglas_por_interface.items():
            for row in reglas:
                if len(row) < 2:
                    continue
                    
                source = str(row.iloc[1]) if pd.notna(row.iloc[1]) else ""
                dest = str(row.iloc[2]) if pd.notna(row.iloc[2]) else ""
                action = str(row.iloc[5]) if pd.notna(row.iloc[5]) else ""
                
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
                                        regla=row.iloc[0],
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
                    
                    if len(regla1) < 6 or len(regla2) < 6:
                        continue
                    
                    if regla1.iloc[5] == 'DENY' and regla2.iloc[5] == 'ACCEPT':
                        if self._reglas_similares(regla1, regla2, campos, min_coincidencias):
                            self._agregar_vulnerabilidad(
                                tipo=config_shadow.get('tipo', 'RIESGO'),
                                severidad=config_shadow.get('severidad', 'MEDIA'),
                                seccion=seccion,
                                regla=f"{regla1.iloc[0]} vs {regla2.iloc[0]}",
                                descripcion=config_shadow.get('descripcion', 'Posible shadow rule'),
                                recomendacion=config_shadow.get('recomendacion', 'Revisar orden de reglas')
                            )
    
    def _reglas_similares(self, regla1, regla2, campos, min_coincidencias):
        idx_map = {
            'source': 1,
            'dest': 2,
            'service': 4,
            'action': 5
        }
        
        coincidencias = 0
        for campo in campos:
            if campo in idx_map:
                idx = idx_map[campo]
                val1 = str(regla1.iloc[idx]) if len(regla1) > idx and pd.notna(regla1.iloc[idx]) else ""
                val2 = str(regla2.iloc[idx]) if len(regla2) > idx and pd.notna(regla2.iloc[idx]) else ""
                if val1 == val2:
                    coincidencias += 1
        
        return coincidencias >= min_coincidencias
    
    def _analizar_reglas_duplicadas(self):
        if 'reglas_duplicadas' not in self.config:
            return
        
        config_dup = self.config['reglas_duplicadas']
        campos_clave = config_dup.get('campos_clave', ['source', 'dest', 'service', 'action'])
        
        reglas_vistas = {}
        idx_map = {
            'source': 1,
            'dest': 2,
            'service': 4,
            'action': 5
        }
        
        for seccion, reglas in self.reglas_por_interface.items():
            for idx, row in enumerate(reglas):
                if len(row) < 6:
                    continue
                    
                clave = self._crear_clave_regla(row, campos_clave, idx_map)
                
                if clave in reglas_vistas:
                    self._agregar_vulnerabilidad(
                        tipo=config_dup.get('tipo', 'ADVERTENCIA'),
                        severidad=config_dup.get('severidad', 'BAJA'),
                        seccion=seccion,
                        regla=row.iloc[0],
                        descripcion=config_dup.get('descripcion', 'Regla duplicada'),
                        recomendacion=config_dup.get('recomendacion', 'Eliminar reglas duplicadas')
                    )
                else:
                    reglas_vistas[clave] = True
    
    def _crear_clave_regla(self, row, campos_clave, idx_map):
        componentes = []
        for campo in campos_clave:
            if campo in idx_map:
                idx = idx_map[campo]
                valor = str(row.iloc[idx]) if len(row) > idx and pd.notna(row.iloc[idx]) else ""
                componentes.append(valor)
        return tuple(componentes)
    
    def _analizar_shadows_rules(self):
        for seccion, reglas in self.reglas_por_interface.items():
            destinos_deny = set()
            
            for row in reglas:
                if len(row) < 6:
                    continue
                    
                destino = str(row.iloc[2]) if pd.notna(row.iloc[2]) else ""
                action = str(row.iloc[5]) if pd.notna(row.iloc[5]) else ""
                
                if action == 'DENY' and destino not in ['all', 'any', '']:
                    destinos_deny.add(destino)
                
                if action == 'ACCEPT' and destino in destinos_deny:
                    self._agregar_vulnerabilidad(
                        tipo='RIESGO',
                        severidad='MEDIA',
                        seccion=seccion,
                        regla=row.iloc[0],
                        descripcion=f'Regla ACCEPT para destino {destino} pero existe DENY previo',
                        recomendacion='Revisar orden de reglas - posiblemente esta regla nunca se aplica'
                    )
    
    def _agregar_vulnerabilidad(self, tipo, severidad, seccion, regla, descripcion, recomendacion):
        self.vulnerabilidades.append({
            'Tipo': tipo,
            'Severidad': severidad,
            'Sección': seccion,
            'Regla': regla if pd.notna(regla) else 'N/A',
            'Descripción': descripcion,
            'Recomendación': recomendacion
        })