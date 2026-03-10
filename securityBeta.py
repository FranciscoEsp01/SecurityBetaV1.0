import streamlit as st
import pandas as pd
import pyshark
import threading
import time
import plotly.express as px
from datetime import datetime
import asyncio
from streamlit.runtime.scriptrunner import add_script_run_ctx

# V1.0 : inicio de la version beta de Pagina de Monitoreo de Ciberseguridad
# la pagina funciona pero no registra los logs ni se muestran graficos ya que no se capturan
# mi teoria es que hay un problema con los permisos que se le da a streamlit
# registro de fecha y hora:  21/02/2026 04:21 AM

# V1.1 : Se corrigio el problema con los permisos de streamlit
# al final era un prblema dentro de la terminal la cual no permitia el uso correcto de astreamlit
# se reestructuro la mayoria del codigo para mejorar la captura de paquetes
# registro de fecha y hora:  8/03/2026 17:45 PM

# V1.2 : se organizo mejor la UI y se agrego el registro para poder ver las capturas por IP unica
# ademas tambien se aumento la cantidad de paquetes que se pueden mostrar en el log a 1000 para evitar problemas de rendimiento
# tengo ideado aumentar la cantidad de paquetes que se pueden mostrar en el log a 2000 pero puede que la capacidad de memoria de streamlit no permita eso
# registro de fecha y hora:  09/03/2026 13:45 PM

# V1.3 : se agrego el grafico de actividad en el tiempo, se corrigio el problema de registro de paquetes, pero el sistema se queda sin memoria y crashea despues de cierto tiempo
#no se como arreglarlo, pero quizas se podria eliminar el registro de paquetes y utilizar una proxy para que no se utilize la memoria del sistema
# registro de fecha y hora:  10/03/2026 12:21 PM

# V1.4 : se agrefo detalle a los protoocolos de red para tener una mejor informacion de los paquetes recopilados en el log, ademas facilita la visualizacion de los datos y el filtrado de los paquetes en posibles ataques
# registro de fecha y hora:  10/03/2026 15:30 PM

st.set_page_config(page_title="securityBeta Prototype", layout="wide", page_icon="🛡️")
st.title(" Monitor de Ciberseguridad en Tiempo Real")

if 'log_data' not in st.session_state:
    st.session_state.log_data = pd.DataFrame(columns=[
        'Timestamp', 'Origen', 'Destino', 'Protocolo', 'Tipo', 'Riesgo', 'Detalle'
    ])

def classify_threat(packet):
    try:
        proto = packet.highest_layer
        risk = "Bajo"
        usage = "Sistema/Basura"

        if proto in ['HTTP', 'TLS', 'TCP', 'QUIC']:
            usage = "Navegación Web"
        elif proto in ['DNS', 'MDNS', 'SSDP']:
            usage = "Servicios de Red"
        
        if 'TCP' in packet and hasattr(packet.tcp, 'flags_syn') and packet.tcp.flags_syn == '1':
            if hasattr(packet.tcp, 'flags_ack') and packet.tcp.flags_ack == '0':
                risk = "Medio (SYN Scan?)"
        
        return usage, risk
    except:
        return "Desconocido", "Bajo"

def get_packet_details(packet):
    detalle = "Sin detalles"
    try:
        if hasattr(packet, 'http') and hasattr(packet.http, 'host'):
            detalle = f"Sitio Web: {packet.http.host}"
        elif hasattr(packet, 'tls') and hasattr(packet.tls, 'handshake_extensions_server_name'):
            detalle = f"Sitio (HTTPS): {packet.tls.handshake_extensions_server_name}"
        elif hasattr(packet, 'dns') and hasattr(packet.dns, 'qry_name'):
            detalle = f"Consulta DNS: {packet.dns.qry_name}"
        elif hasattr(packet, 'mdns') and hasattr(packet.mdns, 'dns_qry_name'):
            detalle = f"Descubrimiento: {packet.mdns.dns_qry_name}"
    except Exception:
        pass
    return detalle

def start_capture(interface):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        capture = pyshark.LiveCapture(interface=interface)
        for packet in capture.sniff_continuously():
            try:
                usage, risk = classify_threat(packet)
                detalle = get_packet_details(packet)
                
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

if not st.session_state.log_data.empty:
    m1, m2, m3 = st.columns(3)
    m1.metric("Paquetes Capturados", len(st.session_state.log_data))
    m2.metric("IPs Únicas", st.session_state.log_data['Origen'].nunique())
    m3.metric("Alertas de Riesgo", len(st.session_state.log_data[st.session_state.log_data['Riesgo'] != "Bajo"]))

st.divider()

tab1, tab2 = st.tabs(["🌐 Dashboard General", "🔍 Análisis por IP Única"])

with tab1:
    if not st.session_state.log_data.empty:
        st.subheader("📈 Actividad en el Tiempo (por Hora)")
        df_time = st.session_state.log_data.copy()
        df_time['Hora'] = pd.to_datetime(df_time['Timestamp'], format='%H:%M:%S').dt.strftime('%H:00')
        time_counts = df_time.groupby('Hora').size().reset_index(name='Acciones')
        
        fig_line = px.line(time_counts, x='Hora', y='Acciones', markers=True, color_discrete_sequence=['#FF00FF'])
        fig_line.update_layout(margin=dict(t=20, b=20, l=0, r=0), xaxis_title="Hora", yaxis_title="Cantidad de Acciones")
        st.plotly_chart(fig_line, width="stretch")
        
    st.divider()

    col_charts, col_table = st.columns([1, 2])
    
    with col_charts:
        st.subheader("📊 Gráficos de Tráfico")
        if not st.session_state.log_data.empty:
            fig_pie = px.pie(st.session_state.log_data, names='Tipo', hole=0.3)
            fig_pie.update_layout(margin=dict(t=0, b=0, l=0, r=0))
            st.plotly_chart(fig_pie, width="stretch")
            
            top_ips = st.session_state.log_data['Origen'].value_counts().head(5).reset_index()
            top_ips.columns = ['IP', 'Paquetes']
            fig_bar = px.bar(top_ips, x='Paquetes', y='IP', orientation='h')
            fig_bar.update_layout(margin=dict(t=0, b=0, l=0, r=0))
            st.plotly_chart(fig_bar, width="stretch")

    with col_table:
        st.subheader(" Registro Completo")
        st.dataframe(
            st.session_state.log_data.iloc[::-1], 
            width="stretch",
            height=500
        )

with tab2:
    st.subheader(" Rastreo de Actividad por IP")
    if not st.session_state.log_data.empty:
        unique_ips = st.session_state.log_data['Origen'].unique()
        for ip in unique_ips:
            with st.expander(f"📍 Acciones de la IP: {ip}"):
                filtered_data = st.session_state.log_data[st.session_state.log_data['Origen'] == ip]
                st.dataframe(
                    filtered_data.iloc[::-1],
                    width="stretch"
                )
    else:
        st.info("Esperando captura de paquetes...")

time.sleep(4)
st.rerun()
