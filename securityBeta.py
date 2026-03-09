import streamlit as st
import pandas as pd
import pyshark
import threading
import time
import plotly.express as px
from datetime import datetime
import asyncio
from streamlit.runtime.scriptrunner import add_script_run_ctx

# V1.0 2: inicio de la version beta de Pagina de Monitoreo de Ciberseguridad
# la pagina funciona pero no registra los logs ni se muestran graficos ya que no se capturan
# mi teoria es que hay un problema con los permisos que se le da a streamlit
# registro de fecha y hora:  21/02/2026 04:21 AM

# V1.1 2: Se corrigio el problema con los permisos de streamlit
# al final era un prblema dentro de la terminal la cual no permitia el uso correcto de streamlit
# se reestructuro la mayoria del codigo para mejorar la captura de paquetes
# registro de fecha y hora:  8/03/2026 17:45 PM

st.set_page_config(page_title="SecurityBeta Prototype", layout="wide")
st.title(" Monitor de Ciberseguridad en Tiempo Real")

if 'log_data' not in st.session_state:
    st.session_state.log_data = pd.DataFrame(columns=[
        'Timestamp', 'Origen', 'Destino', 'Protocolo', 'Tipo', 'Riesgo'
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

def start_capture(interface):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        capture = pyshark.LiveCapture(interface=interface)
        for packet in capture.sniff_continuously():
            try:
                usage, risk = classify_threat(packet)
                
                new_row = {
                    'Timestamp': datetime.now().strftime('%H:%M:%S'),
                    'Origen': packet.ip.src,
                    'Destino': packet.ip.dst,
                    'Protocolo': packet.highest_layer,
                    'Tipo': usage,
                    'Riesgo': risk
                }

                new_df = pd.DataFrame([new_row])
                st.session_state.log_data = pd.concat([st.session_state.log_data, new_df], ignore_index=True)

                if len(st.session_state.log_data) > 100:
                    st.session_state.log_data = st.session_state.log_data.tail(100)
            except (AttributeError, Exception):
                continue
    except Exception as e:
        print(f"Error en captura: {e}")

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

col_table, col_charts = st.columns([2, 1])

with col_table:
    st.subheader(" Registro de Logs")
    st.dataframe(
        st.session_state.log_data.iloc[::-1], 
        width="stretch",
        height=450
    )

with col_charts:
    st.subheader("📊 Análisis")
    if not st.session_state.log_data.empty:
        fig_pie = px.pie(st.session_state.log_data, names='Tipo', hole=0.3)
        st.plotly_chart(fig_pie, width="stretch")
        top_ips = st.session_state.log_data['Origen'].value_counts().head(5)
        st.bar_chart(top_ips)
time.sleep(2)
st.rerun()
