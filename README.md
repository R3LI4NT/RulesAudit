<p align="center">
  <img width="500" height="170" src="https://github.com/user-attachments/assets/f5ad76a4-cc46-4064-bd1b-46664973584a" alt="RulesAudit" Logo" />
</p>

<p align="center">
   <a href="https://dotnet.microsoft.com/">
    <img src="https://img.shields.io/badge/Python-Tool-00DD00.svg">
  </a>
    <img src="https://img.shields.io/badge/Release-1.0-00DD00.svg">
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

<img width="1048" height="505" alt="2" src="https://github.com/user-attachments/assets/b7a69892-7c60-4b0d-a950-acc728624e48" />

Utiliza <a href="https://pandas.pydata.org/">Pandas</a> para estructurar los datos del Excel en diferentes headers según su tipo: **Policy, Source, Destination, Schedule, Service, Action, IP Pool, NAT, Type, Security Profiles, Log, Bytes, Extra_13**.

<img width="1755" height="774" alt="3" src="https://github.com/user-attachments/assets/1f97a5a3-8671-4b7f-b124-85f9ba7b2c38" />

<h1 align="center"></h1>

Luego de mapear los resultados, el módulo `analyzer\audit.py` se encarga de tomar las reglas y analizarlas en busca de configuración insegura basandose en el motor `vulns.json`.

<img width="1170" height="945" alt="4" src="https://github.com/user-attachments/assets/47bd726d-a6dc-4574-b15c-9e7eaf52336b" />

<img width="1035" height="570" alt="5" src="https://github.com/user-attachments/assets/ff8beff3-0ed5-430c-b7bb-fddb39f3641d" />

Los resultados se guardan en un `excel` y un `html` interactivo para su posterior análisis:

<img width="1641" height="811" alt="excel" src="https://github.com/user-attachments/assets/74bcbd55-3c2d-427c-a6b8-2cc10d391586" />

El reportador HTML permite exportar un CSV si usted así lo requiere.

<img width="1919" height="954" alt="7" src="https://github.com/user-attachments/assets/1d638ec5-6fb8-4e76-8e1b-0f77946f4a32" />

<img width="1919" height="947" alt="html" src="https://github.com/user-attachments/assets/b2cae175-77a2-4bb2-9164-cd33d9121c77" />

<img width="1919" height="938" alt="9" src="https://github.com/user-attachments/assets/f15327a3-7037-4215-a073-766b317b9f5a" />

<h1 align="center"></h1>

### Consideraciones a tener en cuenta

El motor construido se basa en la lógica del Analista, usted debe analizar si las configuraciones inseguras encontradas son válidas y si corresponden a la severidad clasificada. Siéntase libre de optimizar y ampliar el archivo `vulns.json` para mejorar la precisión en la detección y clasificación de vulnerabilidades.

El script `IA_audit.py` corresponde a un analizador de reglas pero utilizando la IA de Gemini que aún se encuentra en fase de pruebas.

<h1 align="center"></h1>

Correo de contacto:

<img src="https://img.shields.io/badge/r3li4nt.contact@keemail.me-D14836?style=for-the-badge&logo=gmail&logoColor=white" />

<h1 align="center"></h1>

#### Developer: ~R3LI4NT~
