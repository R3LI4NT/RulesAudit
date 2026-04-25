import os
import json
from datetime import datetime


class GestorHistorial:

    def __init__(self, ruta_historial):
        self.ruta = ruta_historial
        os.makedirs(self.ruta, exist_ok=True)
        self.indice_path = os.path.join(self.ruta, 'indice.json')
        self._cargar_indice()

    def _cargar_indice(self):
        if os.path.exists(self.indice_path):
            try:
                with open(self.indice_path, 'r', encoding='utf-8') as f:
                    self.indice = json.load(f)
            except Exception:
                self.indice = []
        else:
            self.indice = []

    def _guardar_indice(self):
        with open(self.indice_path, 'w', encoding='utf-8') as f:
            json.dump(self.indice, f, ensure_ascii=False, indent=2)

    def registrar_analisis(self, cliente, archivo_original, vulnerabilidades, resumen, score):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        entrada_id = f"{cliente}_{timestamp}"
        detalle_path = os.path.join(self.ruta, f"{entrada_id}.json")
        detalle = {
            'id': entrada_id,
            'cliente': cliente,
            'archivo_original': archivo_original,
            'fecha': datetime.now().isoformat(),
            'vulnerabilidades': vulnerabilidades,
            'resumen': resumen,
            'score': score
        }
        with open(detalle_path, 'w', encoding='utf-8') as f:
            json.dump(detalle, f, ensure_ascii=False, indent=2, default=str)
        entrada_indice = {
            'id': entrada_id,
            'cliente': cliente,
            'archivo_original': archivo_original,
            'fecha': datetime.now().isoformat(),
            'total_vulnerabilidades': len(vulnerabilidades),
            'score': score.get('score', 0),
            'nivel': score.get('nivel', 'BAJO'),
            'grado': score.get('grado', 'A'),
            'total_reglas': resumen.get('total_reglas', 0)
        }
        self.indice.insert(0, entrada_indice)
        self._guardar_indice()
        return entrada_id

    def listar_historial(self, cliente=None, limite=50):
        if cliente:
            resultados = [e for e in self.indice if e['cliente'].lower() == cliente.lower()]
        else:
            resultados = self.indice
        return resultados[:limite]

    def obtener_analisis(self, entrada_id):
        detalle_path = os.path.join(self.ruta, f"{entrada_id}.json")
        if not os.path.exists(detalle_path):
            return None
        try:
            with open(detalle_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return None

    def comparar_analisis(self, id_anterior, id_actual):
        anterior = self.obtener_analisis(id_anterior)
        actual = self.obtener_analisis(id_actual)
        if not anterior or not actual:
            return None
        vulns_anterior = anterior.get('vulnerabilidades', [])
        vulns_actual = actual.get('vulnerabilidades', [])
        claves_anterior = {self._clave_vuln(v) for v in vulns_anterior}
        claves_actual = {self._clave_vuln(v) for v in vulns_actual}
        nuevas = claves_actual - claves_anterior
        resueltas = claves_anterior - claves_actual
        persistentes = claves_anterior & claves_actual
        vulns_nuevas = [v for v in vulns_actual if self._clave_vuln(v) in nuevas]
        vulns_resueltas = [v for v in vulns_anterior if self._clave_vuln(v) in resueltas]
        vulns_persistentes = [v for v in vulns_actual if self._clave_vuln(v) in persistentes]
        return {
            'anterior': {
                'id': id_anterior,
                'fecha': anterior.get('fecha'),
                'score': anterior.get('score', {}).get('score', 0),
                'total': len(vulns_anterior)
            },
            'actual': {
                'id': id_actual,
                'fecha': actual.get('fecha'),
                'score': actual.get('score', {}).get('score', 0),
                'total': len(vulns_actual)
            },
            'nuevas': vulns_nuevas,
            'resueltas': vulns_resueltas,
            'persistentes': vulns_persistentes,
            'delta_score': round(actual.get('score', {}).get('score', 0) - anterior.get('score', {}).get('score', 0), 1),
            'delta_total': len(vulns_actual) - len(vulns_anterior)
        }

    def _clave_vuln(self, v):
        return (
            v.get('ID', ''),
            v.get('Regla', ''),
            v.get('Sección', ''),
            v.get('Descripción', '')[:80]
        )

    def eliminar_analisis(self, entrada_id):
        detalle_path = os.path.join(self.ruta, f"{entrada_id}.json")
        if os.path.exists(detalle_path):
            os.remove(detalle_path)
        self.indice = [e for e in self.indice if e['id'] != entrada_id]
        self._guardar_indice()
        return True

    def limpiar_historial(self):
        for archivo in os.listdir(self.ruta):
            if archivo.endswith('.json') and archivo != 'indice.json':
                try:
                    os.remove(os.path.join(self.ruta, archivo))
                except Exception:
                    pass
        self.indice = []
        self._guardar_indice()

    def estadisticas_cliente(self, cliente):
        historial = self.listar_historial(cliente)
        if not historial:
            return None
        scores = [h['score'] for h in historial]
        totales = [h['total_vulnerabilidades'] for h in historial]
        return {
            'cliente': cliente,
            'total_analisis': len(historial),
            'primer_analisis': historial[-1]['fecha'],
            'ultimo_analisis': historial[0]['fecha'],
            'score_actual': historial[0]['score'],
            'score_promedio': round(sum(scores) / len(scores), 2),
            'score_minimo': min(scores),
            'score_maximo': max(scores),
            'tendencia': self._calcular_tendencia(scores),
            'vulnerabilidades_actuales': historial[0]['total_vulnerabilidades'],
            'vulnerabilidades_promedio': round(sum(totales) / len(totales), 1)
        }

    def _calcular_tendencia(self, scores):
        if len(scores) < 2:
            return 'estable'
        reciente = scores[0]
        anterior = scores[-1] if len(scores) > 3 else scores[-1]
        diff = reciente - anterior
        if diff > 5:
            return 'empeora'
        elif diff < -5:
            return 'mejora'
        return 'estable'
