<p align="center">
  <img width="500" height="170" src="https://github.com/user-attachments/assets/8034df25-2098-4831-bc4b-e8f049745e64" alt="RulesAudit" Logo" />
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

Cuenta con un motor propio de vulnerabilidades basado en el archivo `vulns.json`, completamente personalizable, que permite clasificar los hallazgos en distintos niveles de severidad según su tipo: Crítica, Alta, Media, Baja e Informativa.

<img width="1572" height="882" alt="1" src="https://github.com/user-attachments/assets/ee65d2ae-5b7e-4d3c-86ea-37e50b082dd3" />

El archivo `mapeo\csv_to_excel` permite convertir una o varias reglas CSV a un formato más legible (Excel).

<img width="1048" height="505" alt="2" src="https://github.com/user-attachments/assets/b7a69892-7c60-4b0d-a950-acc728624e48" />

Utiliza Pandas para estructurar los datos del Excel en diferentes headers según su tipo: Policy, Source, Destination, Schedule, Service, Action, IP Pool, NAT, Type, Security Profiles, Log, Bytes, Extra_13.

<img width="1755" height="774" alt="3" src="https://github.com/user-attachments/assets/1f97a5a3-8671-4b7f-b124-85f9ba7b2c38" />


