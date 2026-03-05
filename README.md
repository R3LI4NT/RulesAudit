<p align="center">
  <img width="500" height="180" src="https://github.com/user-attachments/assets/cb7586ce-7fed-45a9-aec8-e1507047c6d4" alt="RulesAudit" Logo" />
</p>

<p align="center">
   <a href="https://dotnet.microsoft.com/">
    <img src="https://img.shields.io/badge/Python-Tool-00DD00.svg">
  </a>
    <img src="https://img.shields.io/badge/Release-2.0-00DD00.svg">
  </a>
    <img src="https://img.shields.io/badge/Public-%F0%9F%97%9D%EF%B8%8F-00DD00.svg">
  </a>
</p>

<h1 align="center"></h1>

### Acerca de RulesAudit

RulesAudit es una herramienta desarrollada en Python para analizar configuraciones inseguras en reglas de Firewalls. 

Cuenta con un motor propio de vulnerabilidades basado en el archivo `vulns.json`, completamente personalizable, que permite clasificar los hallazgos en distintos niveles de severidad según su tipo: **Crítica, Alta, Media, Baja e Informativa**.

<img width="1572" height="882" alt="1" src="https://github.com/user-attachments/assets/ee65d2ae-5b7e-4d3c-86ea-37e50b082dd3" />

El archivo `mapeo\csv_to_excel` permite convertir una o varias reglas CSV a un formato más legible (Excel).

<img width="1333" height="653" alt="mapeo-2" src="https://github.com/user-attachments/assets/0bb6ce8c-01ef-4a0d-b7b9-93adaf1ecbb7" />

Utiliza <a href="https://pandas.pydata.org/">Pandas</a> para estructurar los datos del Excel en diferentes headers según su tipo: **Policy, Source, Destination, Schedule, Service, Action, IP Pool, NAT, Type, Security Profiles, Log, Bytes, Extra_13**.

<img width="1755" height="774" alt="3" src="https://github.com/user-attachments/assets/1f97a5a3-8671-4b7f-b124-85f9ba7b2c38" />

En caso de que las reglas exportadas del cliente tenga diferentes formatos, pueden modificar los archivos `csv_to_excel` y `analyzer.py` para especificarle los headers.

<img width="722" height="214" alt="formatos-2" src="https://github.com/user-attachments/assets/a5cae1ef-b775-480a-bb3b-18986521aa83" />

<img width="1096" height="887" alt="formatos" src="https://github.com/user-attachments/assets/eda0112b-9ad7-456c-97d5-c6570ee21489" />

<h1 align="center"></h1>

### MODO CLI

Luego de mapear los resultados, el módulo `analyzer\audit.py` se encarga de tomar las reglas y analizarlas en busca de configuración insegura basandose en el motor `vulns.json`.

<img width="1726" height="942" alt="audit-1" src="https://github.com/user-attachments/assets/82aa2a2e-ce70-4f08-86c8-98c6d169318e" />

<img width="1165" height="421" alt="audit-2" src="https://github.com/user-attachments/assets/f19440c1-a3b7-4580-a3d8-3256c6716535" />

Los resultados se guardan en un `excel` y un `html` interactivo para su posterior análisis:

<img width="1641" height="811" alt="excel" src="https://github.com/user-attachments/assets/74bcbd55-3c2d-427c-a6b8-2cc10d391586" />

El reportador HTML permite exportar un CSV si usted así lo requiere.

<img width="1919" height="954" alt="7" src="https://github.com/user-attachments/assets/1d638ec5-6fb8-4e76-8e1b-0f77946f4a32" />

<img width="1919" height="947" alt="html" src="https://github.com/user-attachments/assets/b2cae175-77a2-4bb2-9164-cd33d9121c77" />

<img width="1917" height="945" alt="reporte" src="https://github.com/user-attachments/assets/2f666bad-f109-49d6-b43d-893a71867bd4" />

<h1 align="center"></h1>

### MODO WEB

RulesAudit cuenta con una aplicación web desarrollada con el framework <a href="https://flask.palletsprojects.com/en/stable/">Flask</a> diseñada para auditar y analizar las reglas de firewall de manera eficiente y profesional.

| Componente | Tecnología |
|------------|------------|
| **Backend** | Flask (Python) |
| **Frontend** | HTML5, CSS3, JavaScript |
| **Estilos** | Google Fonts, Font Awesome |
| **Procesamiento** | Pandas (análisis de Excel) |
| **Templates** | Jinja2 |
| **Sesiones** | Flask-Login |

Instalar dependencias antes de iniciar la aplicación:
```python3
pip3 install -r requirements.txt
```
Dirección donde corre: `http://127.0.0.1:5000/admin/login`

**Credenciales por defecto:**
| Usuario| Contraseña |
|------------|------------|
| **admin** | rulesaudit |

<img width="1919" height="1034" alt="web-1" src="https://github.com/user-attachments/assets/0da40ff6-ec80-4e29-9f38-293532acb163" />

<img width="1919" height="1034" alt="web-2" src="https://github.com/user-attachments/assets/1943dc71-d9a6-412e-95c0-0056b70b5ec4" />

<img width="1919" height="1033" alt="web-3" src="https://github.com/user-attachments/assets/5df78376-3b8d-4c41-a330-2a9d91de3be0" />

<img width="1070" height="318" alt="web-4" src="https://github.com/user-attachments/assets/f596812c-c0e2-4c67-8e83-9ec9213a27f4" />

<h1 align="center"></h1>

### TEST DE SEGMENTACIÓN

Se desarrollo una aplicación de GUI `segmentación/segm_analyzer.py` con Tkinter para analizar las conexiones de origen y destino por segmento. Esto permite verificar que conexiones deben ser aceptadas (seguras) y cuáles no (inseguras).

Contiene tres modos de verificación:

**[MODO-1]:** Desde redes `CDE` **->** redes `CNTO`

**[MODO-2]:** Desde redes `CNTO` **->** redes `CDE`

**[MODO-3]:** Desde redes `NO-PCI` **->** redes `CNTO/CDE`

<img width="1919" height="1031" alt="segm1" src="https://github.com/user-attachments/assets/02f66360-a66a-4388-950a-5aa120dd538b" />

Para que los archivos de texto puedan ser cargados, los segmentos deben estar estructurados de la siguiente manera:
```CDE_ejemplo.txt
192.168.123.
192.168.180.
```

Evitar agregar `.0/24` al final ya que retorna error de mapeo.

Permite exportar el resultado en formato HTML interactivo.

<img width="1919" height="952" alt="segm" src="https://github.com/user-attachments/assets/29b1a52e-96a0-445b-b873-9489c1a84613" />

<img width="1919" height="948" alt="segm" src="https://github.com/user-attachments/assets/d32b2681-bb95-4140-9ced-d13efdec6a50" />

<img width="1919" height="943" alt="segm" src="https://github.com/user-attachments/assets/7c354c74-bf81-4ff3-9e8d-dd60d7ded1ec" />

➤ <a href="https://github.com/R3LI4NT/RulesAudit/releases">Descargar ejecutable</a>

<h1 align="center"></h1>

### Consideraciones a tener en cuenta

El motor construido se basa en la lógica del Analista, usted debe analizar si las configuraciones inseguras encontradas son válidas y si corresponden a la severidad clasificada. Siéntase libre de optimizar y ampliar el archivo `vulns.json` para mejorar la precisión en la detección y clasificación de vulnerabilidades.

<h1 align="center"></h1>

¿Te gustaría contribuir con la herramienta? Envíame un correo:

<img src="https://img.shields.io/badge/r3li4nt.contact@keemail.me-D14836?style=for-the-badge&logo=gmail&logoColor=white" />

<h1 align="center"></h1>

#### Developer: ~R3LI4NT~
