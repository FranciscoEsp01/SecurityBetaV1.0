import streamlit as st
import pandas as pd
import pyshark
import threading
import time
import plotly.express as px
from datetime import datetime
import os

# V1.0 2: inicio de la version beta de Pagina de Monitoreo de Ciberseguridad
# la pagina funciona pero no registra los logs ni se muestran graficos ya que no se capturan
# mi teoria es que hay un problema con los permisos que se le da a streamlit
# registro de fecha y hora:  21/02/2025 04:21 AM

st.set_page_config(page_title="SecurityBeta", layout="wide")
st.title("🛡️ Monitor de Ciberseguridad en Tiempo Real")

if 'log_data' not in st.session_state:
    st.session_state.log_data = pd.DataFrame(columns=[
        'Timestamp', 'Origen', 'Destino', 'Protocolo', 'Tipo', 'Riesgo'
    ])

def classify_threat(packet):
    """Clasifica el uso y detecta posibles amenazas."""
    try:
        proto = packet.highest_layer
        risk = "Bajo"
        usage = "Sistema/Basura"
        if proto in ['HTTP', 'TLS', 'TCP', 'QUIC']:
            usage = "Navegación Web"
        elif proto in ['DNS', 'MDNS', 'SSDP']:
            usage = "Servicios de Red"
        if 'TCP' in packet:
            if hasattr(packet.tcp, 'flags_syn') and packet.tcp.flags_syn == '1':
                if hasattr(packet.tcp, 'flags_ack') and packet.tcp.ack == '0':
                    risk = "Medio (SYN Scan?)"
        
        return usage, risk
    except:
        return "Desconocido", "Bajo"

def start_capture(interface):
    """Ejecuta la captura de TShark en segundo plano."""
    try:
        capture = pyshark.LiveCapture(interface=interface)
        for packet in capture.sniff_continuous():
            try:
                timestamp = datetime.now().strftime('%H:%M:%S')
                src = packet.ip.src
                dst = packet.ip.dst
                proto = packet.highest_layer
                
                usage, risk = classify_threat(packet)

                new_row = {
                    'Timestamp': timestamp,
                    'Origen': src,
                    'Destino': dst,
                    'Protocolo': proto,
                    'Tipo': usage,
                    'Riesgo': risk
                }
                new_df = pd.DataFrame([new_row])
                st.session_state.log_data = pd.concat([st.session_state.log_data, new_df], ignore_index=True)
                if len(st.session_state.log_data) > 100:
                    st.session_state.log_data = st.session_state.log_data.tail(100)
            except AttributeError:
                continue
    except Exception as e:
        st.error(f"Error en la captura: {e}")
interface_name = 'bridge0' 
if 'thread_started' not in st.session_state:
    thread = threading.Thread(target=start_capture, args=(interface_name,), daemon=True)
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
    st.subheader("📋 Registro de Logs (Tiempo Real)")

    st.dataframe(
        st.session_state.log_data.sort_index(ascending=False), 
        use_container_width=True,
        height=400
    )

with col_charts:
    st.subheader("📊 Análisis de Tráfico")
    if not st.session_state.log_data.empty:
        # Grafico 1 Clasificacion de uso
        fig_pie = px.pie(st.session_state.log_data, names='Tipo', title="Uso de Red", hole=0.3)
        st.plotly_chart(fig_pie, use_container_width=True)
        
        # Grafico 2 IPs mas activas
        fig_bar = px.bar(
            st.session_state.log_data['Origen'].value_counts().head(5), 
            orientation='h', 
            title="Top 5 IPs Origen",
            labels={'value': 'Paquetes', 'index': 'IP'}
        )
        st.plotly_chart(fig_bar, use_container_width=True)
time.sleep(1.5)
st.rerun()