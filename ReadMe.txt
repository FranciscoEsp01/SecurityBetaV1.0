=======================================================================
         DASHBOARD DE MONITOREO DE RED Y CIBERSEGURIDAD
=======================================================================

DESCRIPCIÓN:
------------
Esta pagina es una herramienta de monitoreo de ciberseguridad que
registra los logs de los paquetes capturados por el monitor de red
TShark. Esta pagina se puede acceder desde cualquier navegador web
que tenga acceso a la interfaz de red en la que se ejecuta TShark. 

COMO FUNCIONA:
--------------
La pagina se ejecuta en segundo plano y registra los logs de los
paquetes capturados por TShark.

REQUISITOS:
-----------
* Python 3.x instalado.
* TShark (Motor de Wireshark): Indispensable para capturar paquetes.
* Librerías de Python:
  - streamlit
  - pandas
  - pyshark
  - plotly
  - auth_key (URLhaus) (se consigue en el siguiente link = https://auth.abuse.ch/user/me)

INSTALACION:
------------
Ejecute los siguientes comandos en terminal para instalar los módulos necesarios:

1. python3 -m pip install streamlit plotly pyshark pandas
2. brew install wireshark (para macOS) o apt-get install wireshark (para Linux)
3. recordar entrar desde la terminal a la carpeta donde este guardado el proyecto
         ejemplo: cd Documets securitybeta

USO:
----
 En la terminal ejecutar los siguientes comandos:

1. sudo tshark -i en0 -c 5
2. streamlit run securityBeta.py
3. (en caso de que no funcione el comando anterior) sudo python3 -m streamlit run securityBeta.py

 Esto abrirá la pagina en tu navegador web.

 Para acceder a la interfaz de red, cambia el nombre de la interfaz de red
 en la función start_capture() de la página.

esta se puede encontrar con los siguientes comandos:

1. networksetup -listallhardwareports
2. ifconfig | grep "inet " | grep -v 127.0.0.1
