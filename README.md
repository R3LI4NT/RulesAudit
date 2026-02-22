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

<img width="1641" height="811" alt="6" src="https://github.com/user-attachments/assets/22f5b36d-edcc-42d9-9beb-231334b1f830" />

<img width="1919" height="954" alt="7" src="https://github.com/user-attachments/assets/1d638ec5-6fb8-4e76-8e1b-0f77946f4a32" />

<img width="1919" height="947" alt="8" src="https://github.com/user-attachments/assets/f13a401b-be27-4438-ad41-92d507476e72" />

<img width="1919" height="938" alt="9" src="https://github.com/user-attachments/assets/f15327a3-7037-4215-a073-766b317b9f5a" />
