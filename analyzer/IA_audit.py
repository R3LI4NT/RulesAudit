import pandas as pd
from google import genai
import json
import time
from tkinter import filedialog
from datetime import datetime

# ==============================
# CONFIGURACIÓN
# ==============================

API_KEY = ""

client = genai.Client(api_key=API_KEY)

# ==============================
# Seleccionar archivo
# ==============================

input("Presiona ENTER para seleccionar el Excel consolidado...")

file_path = filedialog.askopenfilename(filetypes=[("Excel files", "*.xlsx")])

if not file_path:
    print("No se seleccionó archivo.")
    exit()

df = pd.read_excel(file_path)

print(f"\n[+] Analizando {len(df)} reglas...\n")

resultados = []

# ==============================
# ANÁLISIS
# ==============================

for i, row in df.iterrows():
    print(f"[+] Analizando regla {i+1}...")

    regla_texto = f"""
Policy: {row.get('Policy')}
Source: {row.get('Source')}
Destination: {row.get('Destination')}
Service: {row.get('Service')}
Action: {row.get('Action')}
NAT: {row.get('NAT')}
Log: {row.get('Log')}
"""

    prompt = f"""
Analiza la siguiente regla de firewall y determina si existe alguna vulnerabilidad.

Responde únicamente en JSON válido con esta estructura EXACTA:

{{
  "vulnerabilidad": "Sí/No",
  "descripcion": "",
  "evidencia": "",
  "criticidad": "Crítica/Alta/Media/Baja/Informativa",
  "recomendacion": ""
}}

Regla:
{regla_texto}
"""

    try:
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
            config={
                "response_mime_type": "application/json"
            }
        )

        if not response.text:
            raise Exception("Respuesta vacía del modelo")

        texto = response.text.strip()

        if texto.startswith("```"):
            texto = texto.replace("```json", "").replace("```", "").strip()

        data = json.loads(texto)

    except Exception as e:
        data = {
            "vulnerabilidad": "Error",
            "descripcion": str(e),
            "evidencia": "",
            "criticidad": "",
            "recomendacion": ""
        }

    resultados.append(data)

    time.sleep(0.5)  

# GUARDAR RESULTADO
resultado_df = pd.DataFrame(resultados)
df_final = pd.concat([df, resultado_df], axis=1)

output_file = f"Analisis_Vulnerabilidades_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
df_final.to_excel(output_file, index=False)

print(f"\n[+] Análisis terminado. Archivo generado: {output_file}")