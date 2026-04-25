from collections import Counter


class PuntuadorRiesgo:

    PESOS_SEVERIDAD = {
        'CRÍTICA': 10.0,
        'ALTA': 7.5,
        'MEDIA': 5.0,
        'BAJA': 2.5,
        'INFORMATIVA': 0.5
    }

    NIVELES_RIESGO = [
        (90, 'CRÍTICO', '#8B0000', 'Riesgo inaceptable. Remediacion inmediata requerida'),
        (70, 'ALTO', '#FF4500', 'Riesgo alto. Plan de remediacion en 30 dias'),
        (40, 'MEDIO', '#FFA500', 'Riesgo moderado. Plan de remediacion en 90 dias'),
        (15, 'BAJO', '#9ACD32', 'Riesgo bajo. Mejora continua'),
        (0, 'MUY BAJO', '#00FF00', 'Configuracion aceptable. Mantener hardening')
    ]

    def __init__(self, vulnerabilidades, total_reglas=0):
        self.vulnerabilidades = vulnerabilidades
        self.total_reglas = max(total_reglas, 1)

    def calcular_score_global(self):
        if not self.vulnerabilidades:
            return {
                'score': 0,
                'nivel': 'MUY BAJO',
                'color': '#00FF00',
                'descripcion': 'Sin vulnerabilidades detectadas',
                'grado': 'A+'
            }
        puntos = 0
        for v in self.vulnerabilidades:
            peso = self.PESOS_SEVERIDAD.get(v.get('Severidad', 'BAJA'), 1.0)
            cvss = v.get('CVSS', 5.0)
            puntos += (peso * 0.6 + cvss * 0.4)
        densidad = len(self.vulnerabilidades) / self.total_reglas
        factor_densidad = min(1.5, 1 + densidad)
        score_base = puntos * factor_densidad
        max_puntos = self.total_reglas * 10
        score_normalizado = min(100, (score_base / max_puntos) * 100) if max_puntos > 0 else 0
        score_final = round(score_normalizado, 1)
        for umbral, nivel, color, desc in self.NIVELES_RIESGO:
            if score_final >= umbral:
                grado = self._calcular_grado(score_final)
                return {
                    'score': score_final,
                    'nivel': nivel,
                    'color': color,
                    'descripcion': desc,
                    'grado': grado
                }
        return {'score': 0, 'nivel': 'MUY BAJO', 'color': '#00FF00', 'descripcion': '', 'grado': 'A+'}

    def _calcular_grado(self, score):
        if score < 10:
            return 'A+'
        elif score < 25:
            return 'A'
        elif score < 40:
            return 'B'
        elif score < 55:
            return 'C'
        elif score < 70:
            return 'D'
        elif score < 85:
            return 'E'
        return 'F'

    def calcular_score_por_categoria(self):
        por_categoria = {}
        categorias = Counter(v.get('Categoria', 'otros') for v in self.vulnerabilidades)
        for categoria, cantidad in categorias.items():
            vulns_cat = [v for v in self.vulnerabilidades if v.get('Categoria') == categoria]
            cvss_prom = sum(v.get('CVSS', 0) for v in vulns_cat) / len(vulns_cat) if vulns_cat else 0
            por_categoria[categoria] = {
                'cantidad': cantidad,
                'cvss_promedio': round(cvss_prom, 2),
                'cvss_maximo': max((v.get('CVSS', 0) for v in vulns_cat), default=0)
            }
        return por_categoria

    def top_vulnerabilidades(self, n=10):
        ordenadas = sorted(
            self.vulnerabilidades,
            key=lambda x: (self.PESOS_SEVERIDAD.get(x.get('Severidad', 'BAJA'), 0), x.get('CVSS', 0)),
            reverse=True
        )
        return ordenadas[:n]

    def indicadores_clave(self):
        severidades = Counter(v.get('Severidad', 'BAJA') for v in self.vulnerabilidades)
        reglas_afectadas = {v.get('Regla', '') for v in self.vulnerabilidades}
        criticas_altas = severidades.get('CRÍTICA', 0) + severidades.get('ALTA', 0)
        return {
            'total_vulnerabilidades': len(self.vulnerabilidades),
            'total_reglas': self.total_reglas,
            'reglas_afectadas': len(reglas_afectadas),
            'porcentaje_reglas_afectadas': round((len(reglas_afectadas) / self.total_reglas) * 100, 1) if self.total_reglas > 0 else 0,
            'criticas_altas': criticas_altas,
            'ratio_criticas': round(criticas_altas / len(self.vulnerabilidades) * 100, 1) if self.vulnerabilidades else 0,
            'distribucion': dict(severidades)
        }
