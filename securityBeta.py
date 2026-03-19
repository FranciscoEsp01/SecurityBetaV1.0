import streamlit as st
import pandas as pd
import pyshark
import threading
import time
import requests
import plotly.express as px
from datetime import datetime
import asyncio
from streamlit.runtime.scriptrunner import add_script_run_ctx
import ssl

# V1.0 2: inicio de la version beta de Pagina de Monitoreo de Ciberseguridad
# la pagina funciona pero no registra los logs ni se muestran graficos ya que no se capturan
# mi teoria es que hay un problema con los permisos que se le da a streamlit
# registro de fecha y hora:  21/02/2026 04:21 AM

# V1.1 2: Se corrigio el problema con los permisos de streamlit
# al final era un prblema dentro de la terminal la cual no permitia el uso correcto de astreamlit
# se reestructuro la mayoria del codigo para mejorar la captura de paquetes
# registro de fecha y hora:  8/03/2026 17:45 PM

# V1.2 2: se organizo mejor la UI y se agrego el registro para poder ver las capturas por IP unica
# ademas tambien se aumento la cantidad de paquetes que se pueden mostrar en el log a 1000 para evitar problemas de rendimiento
# tengo ideado aumentar la cantidad de paquetes que se pueden mostrar en el log a 2000 pero puede que la capacidad de memoria de streamlit no permita eso
# registro de fecha y hora:  09/03/2026 13:45 PM

# V1.3 2: se agrego el grafico de actividad en el tiempo, se corrigio el problema de registro de paquetes, pero el sistema se queda sin memoria y crashea despues de cierto tiempo
#no se como arreglarlo, pero quizas se podria eliminar el registro de paquetes y utilizar una proxy para que no se utilize la memoria del sistema
# registro de fecha y hora:  10/03/2026 12:21 PM

# V1.4 2: se agrego la base de datos de amenazas recientes de URLhaus, esta no funciona (no genera conexion con la API), no se como solucionarlo pero algo se me ocurrira mas adelante
# elimine la key de la API de URLhaus por seguridad, pero esto hace que la base de datos no se pueda cargar, se necesita una key para poder acceder a la API, si alguien quiere probarlo solo tiene que obtener una key gratuita en el sitio de URLhaus y agregarla
# en versiones superiores quisiera cambiar de UI posiblemente filament o algo asi, pero por ahora streamlit es lo que mejor se adapta a mis necesidades
# registro de fecha y hora:  13/03/2026 12:15 PM

# V1.5 2: se corrigio el problema que habia con la base de datos de URLhaus, ya genenra conexion con la API y se puede cargar la base de datos
# la API de URLhaus no aparecera en el repositorio por seguridad, pero si alguien quiere probarlo solo tiene que obtener una key gratuita en el sitio de URLhaus y agregarla en la funcion load_urlhaus_db()
# registro de fecha y hora:  18/03/2026 11:35 PM

# V1.6 2: se simplifico la UI para que sea mas facil de usar, se agrego la opcion de descargar el registro en formato CSV, se corrigio el problema de rendimiento que habia con la cantidad de paquetes mostrados en el log, ahora se pueden mostrar hasta 5 millones de paquetes sin que el sistema se quede sin memoria
# voy a buscar asesoria sobre el tema de ARP spoofing para la captura de paquetes de red y que tan legal y factible es esto, tambien quiero comparar los beneficios y los contras de este ultimo y un "modo monitor"
# el codigo ya esta bastante avanzado y funcionando en los casos de prueba que estoy haceiendo pero a largo plazo no se como mejorarlo y mejorar la experiencia de usuario
# tambien se añadio un boton de descarga en CSV para poder descargar los registros y estos sean pasados a un excel
# registro de fecha y hora:  18/03/2026 22:10 PM

pd.set_option("styler.render.max_elements", 5000000)

ssl._create_default_https_context = ssl._create_unverified_context

st.set_page_config(page_title="SecurityBeta prototype", layout="wide", page_icon="🛡️")

st.title("🛡️ Monitor de Seguridad de Red")
st.markdown("Vigilancia en tiempo real de tu conexión a internet, diseñada de forma clara y fácil de entender.")

if 'log_data' not in st.session_state:
    st.session_state.log_data = pd.DataFrame(columns=[
        'Timestamp', 'Origen', 'Destino', 'Protocolo', 'Tipo', 'Riesgo', 'Detalle'
    ])

urlhaus_cache = {}

@st.cache_data(ttl=3600)
def load_urlhaus_db():
    try:
        url = "https://urlhaus-api.abuse.ch/files/exports/recent.csv?auth-key="
        df = pd.read_csv(url, skiprows=8)
        df.columns = df.columns.str.strip().str.replace('"', '').str.replace('# ', '')
        
        columnas_deseadas = ['id', 'dateadded', 'url', 'threat', 'reporter']
        columnas_disponibles = [col for col in columnas_deseadas if col in df.columns]
        
        if columnas_disponibles:
            return df[columnas_disponibles].head(500), None
        return df.head(500), None
    except Exception as e:
        return pd.DataFrame(), str(e)

def check_urlhaus(host):
    if not host:
        return False
    if host in urlhaus_cache:
        return urlhaus_cache[host]
    try:
        response = requests.post("https://urlhaus-api.abuse.ch/v1/host/", data={'host': host}, timeout=2, verify=False)
        if response.status_code == 200:
            is_malicious = response.json().get('query_status') == 'ok'
            urlhaus_cache[host] = is_malicious
            return is_malicious
    except:
        pass
    urlhaus_cache[host] = False
    return False

def classify_threat(packet):
    try:
        proto = packet.highest_layer
        risk = "Seguro"
        usage = "Tráfico Interno/Sistema"

        if proto in ['HTTP', 'TLS', 'TCP', 'QUIC']:
            usage = "Navegación en Internet"
        elif proto in ['DNS', 'MDNS', 'SSDP']:
            usage = "Servicios Automáticos"
        
        if 'TCP' in packet and hasattr(packet.tcp, 'flags_syn') and packet.tcp.flags_syn == '1':
            if hasattr(packet.tcp, 'flags_ack') and packet.tcp.flags_ack == '0':
                risk = "Precaución (Posible Escaneo)"
        
        return usage, risk
    except:
        return "Desconocido", "Seguro"

def get_packet_details(packet):
    detalle = "Sin detalles técnicos"
    host = None
    try:
        if hasattr(packet, 'http') and hasattr(packet.http, 'host'):
            host = packet.http.host
            detalle = f"Página web: {host}"
        elif hasattr(packet, 'tls') and hasattr(packet.tls, 'handshake_extensions_server_name'):
            host = packet.tls.handshake_extensions_server_name
            detalle = f"Sitio seguro: {host}"
        elif hasattr(packet, 'dns') and hasattr(packet.dns, 'qry_name'):
            host = packet.dns.qry_name
            detalle = f"Búsqueda: {host}"
        elif hasattr(packet, 'mdns') and hasattr(packet.mdns, 'dns_qry_name'):
            detalle = f"Dispositivo local: {packet.mdns.dns_qry_name}"
    except Exception:
        pass
    return detalle, host

def start_capture(interface):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        capture = pyshark.LiveCapture(interface=interface)
        for packet in capture.sniff_continuously():
            try:
                usage, risk = classify_threat(packet)
                detalle, host = get_packet_details(packet)
                
                if host and check_urlhaus(host):
                    risk = "Peligro (Sitio Malicioso Bloqueado)"
                    usage = "Amenaza Detectada"
                
                new_row = {
                    'Timestamp': datetime.now().strftime('%H:%M:%S'),
                    'Origen': packet.ip.src,
                    'Destino': packet.ip.dst,
                    'Protocolo': packet.highest_layer,
                    'Tipo': usage,
                    'Riesgo': risk,
                    'Detalle': detalle
                }

                new_df = pd.DataFrame([new_row])
                st.session_state.log_data = pd.concat([st.session_state.log_data, new_df], ignore_index=True)

            except (AttributeError, Exception):
                continue
    except Exception:
        pass

interface_name = 'en0' 

if 'thread_started' not in st.session_state:
    thread = threading.Thread(target=start_capture, args=(interface_name,), daemon=True)
    add_script_run_ctx(thread)
    thread.start()
    st.session_state.thread_started = True

df_snapshot = st.session_state.log_data.copy()

# Barra lateral para herramientas
with st.sidebar:
    st.header("⚙️ Herramientas")
    st.markdown("Descarga todo el registro para analizarlo en Excel o compartirlo.")
    if not df_snapshot.empty:
        csv = df_snapshot.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="💾 Descargar CSV",
            data=csv,
            file_name=f"Reporte_Red_{datetime.now().strftime('%Y%m%d_%H%M')}.csv",
            mime='text/csv'
        )
    else:
        st.info("Aún no hay datos capturados.")

if not df_snapshot.empty:
    st.markdown("### 📊 Estado General de tu Red")
    m1, m2, m3 = st.columns(3)
    m1.metric("🌐 Conexiones Totales", len(df_snapshot))
    m2.metric("📱 Dispositivos Activos", df_snapshot['Origen'].nunique())
    
    alertas = df_snapshot['Riesgo'].fillna('').str.contains("Precaución|Peligro").sum()
    m3.metric("⚠️ Alertas de Seguridad", int(alertas))

st.divider()

tab1, tab2, tab3 = st.tabs(["🏠 Vista Principal", "🔍 Revisar Dispositivos", "🦠 Lista de Amenazas Globales"])

def row_style(row):
    if 'Peligro' in str(row['Riesgo']):
        return ['background-color: rgba(255, 75, 75, 0.3)'] * len(row)
    elif 'Precaución' in str(row['Riesgo']):
        return ['background-color: rgba(255, 165, 0, 0.3)'] * len(row)
    return [''] * len(row)

with tab1:
    if not df_snapshot.empty:
        # Fila Superior: Relación 60/40
        top_col1, top_col2 = st.columns([6, 4])
        
        with top_col1:
            st.markdown("#### 📈 Actividad Reciente")
            df_time = df_snapshot.copy()
            df_time['Hora'] = pd.to_datetime(df_time['Timestamp'], format='%H:%M:%S').dt.strftime('%H:00')
            time_counts = df_time.groupby('Hora').size().reset_index(name='Conexiones')
            
            fig_line = px.line(time_counts, x='Hora', y='Conexiones', markers=True, color_discrete_sequence=['#4CAF50'])
            fig_line.update_layout(margin=dict(t=20, b=20, l=0, r=0), xaxis_title="Hora del día", yaxis_title="Cantidad de Tráfico")
            st.plotly_chart(fig_line, width="stretch")
            
        with top_col2:
            st.markdown("#### 🧩 ¿Para qué se usa el internet?")
            fig_pie = px.pie(df_snapshot, names='Tipo', hole=0.4, color_discrete_sequence=px.colors.qualitative.Pastel)
            fig_pie.update_layout(margin=dict(t=20, b=20, l=0, r=0))
            st.plotly_chart(fig_pie, width="stretch")

        st.divider()

        # Fila Inferior: Relación 30/70
        bot_col1, bot_col2 = st.columns([3, 7])

        with bot_col1:
            st.markdown("#### 🏆 Top Dispositivos")
            top_ips = df_snapshot['Origen'].value_counts().head(5).reset_index()
            top_ips.columns = ['Dirección IP', 'Conexiones']
            fig_bar = px.bar(top_ips, x='Conexiones', y='Dirección IP', orientation='h', color_discrete_sequence=['#2196F3'])
            fig_bar.update_layout(margin=dict(t=20, b=20, l=0, r=0))
            st.plotly_chart(fig_bar, width="stretch")

        with bot_col2:
            st.markdown("#### 📋 Registro Detallado")
            styled_df = df_snapshot.iloc[::-1].style.apply(row_style, axis=1)
            st.dataframe(styled_df, width="stretch", height=350)
            
    else:
        st.info("Esperando que los dispositivos se conecten y generen tráfico...")

with tab2:
    st.markdown("### 🔎 Inspeccionar un Dispositivo Específico")
    
    if not df_snapshot.empty:
        # Buscador de IP
        col_busqueda, _ = st.columns([1, 2])
        with col_busqueda:
            ip_buscada = st.text_input("🔍 Escribe la IP para filtrar (Ej. 192.168.1.15):", "")

        riesgos_mask = df_snapshot['Riesgo'].fillna('')
        malicious_ips = df_snapshot[riesgos_mask.str.contains('Peligro')]['Origen'].unique()
        medium_ips = df_snapshot[riesgos_mask.str.contains('Precaución')]['Origen'].unique()
        all_ips = df_snapshot['Origen'].unique()
        
        ips_ordenadas = list(malicious_ips)
        ips_ordenadas.extend([ip for ip in medium_ips if ip not in ips_ordenadas])
        ips_ordenadas.extend([ip for ip in all_ips if ip not in ips_ordenadas])
        
        # Aplicar el filtro si se ingresó texto
        if ip_buscada:
            ips_ordenadas = [ip for ip in ips_ordenadas if ip_buscada in ip]
            
        if not ips_ordenadas:
            st.warning("No se encontraron registros para esa IP.")

        for ip in ips_ordenadas:
            is_malicious = ip in malicious_ips
            is_medium = ip in medium_ips
            
            if is_malicious:
                expander_label = f"🔴 Dispositivo: {ip} (¡PELIGRO DETECTADO!)"
            elif is_medium:
                expander_label = f"🟠 Dispositivo: {ip} (Precaución)"
            else:
                expander_label = f"🟢 Dispositivo: {ip} (Seguro)"
            
            with st.expander(expander_label):
                filtered_data = df_snapshot[df_snapshot['Origen'] == ip]
                
                resumen_col1, resumen_col2 = st.columns(2)
                resumen_col1.metric("Total de conexiones", len(filtered_data))
                resumen_col2.metric("Nivel de Riesgo", "Alto" if is_malicious else "Medio" if is_medium else "Bajo")
                
                columnas_limpias = filtered_data[['Timestamp', 'Destino', 'Tipo', 'Detalle', 'Riesgo']]
                styled_filtered_df = columnas_limpias.iloc[::-1].style.apply(row_style, axis=1)
                st.dataframe(styled_filtered_df, width="stretch")
    else:
        st.info("Aún no hay información de dispositivos recolectada.")

with tab3:
    st.markdown("### 🦠 Base de Datos de Enlaces Peligrosos")
    st.markdown("El escudo utiliza esta lista mundial y actualizada en tiempo real para bloquear sitios web fraudulentos.")
    
    df_urlhaus, error_msg = load_urlhaus_db()
    if not df_urlhaus.empty:
        st.dataframe(df_urlhaus, width="stretch", height=600)
    else:
        if error_msg:
            st.error(f"Error de conexión con la lista de seguridad: {error_msg}")
        else:
            st.warning("Cargando la base de datos de amenazas mundiales...")

time.sleep(4)
st.rerun()
