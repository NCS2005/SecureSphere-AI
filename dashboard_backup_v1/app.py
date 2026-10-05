import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
import sys
from pathlib import Path
from datetime import datetime

# Add the parent directory to sys.path so we can import the gateway package
sys.path.append(str(Path(__file__).resolve().parent.parent))

from gateway.database import get_recent_logs, get_aggregate_stats
from gateway.config import settings

# Page Configuration
st.set_page_config(
    page_title="SecureSphere-AI Control Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Premium Styling
st.markdown("""
<style>
    .main-title {
        font-size: 2.8rem;
        font-weight: 800;
        background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.1rem;
    }
    .sub-title {
        font-size: 1.1rem;
        color: #666;
        margin-bottom: 2rem;
    }
    .metric-card {
        background-color: #f8f9fa;
        border-left: 5px solid #1e3c72;
        padding: 1.5rem;
        border-radius: 8px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.05);
    }
    .section-header {
        font-size: 1.6rem;
        font-weight: 700;
        color: #1e3c72;
        border-bottom: 2px solid #eee;
        padding-bottom: 0.5rem;
        margin-top: 1.5rem;
        margin-bottom: 1rem;
    }
    .stButton>button {
        background-color: #1e3c72;
        color: white;
        border-radius: 6px;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

# Sidebar Configuration
st.sidebar.image("https://img.icons8.com/color/96/shield.png", width=70)
st.sidebar.markdown("### SecureSphere-AI Admin")
st.sidebar.markdown("Intelligent LLM Security Proxy")
st.sidebar.markdown("---")
st.sidebar.info(f"**Gateway URL**: http://localhost:8000\n\n"
                f"**Local Model**: {settings.LOCAL_LLM_MODEL}\n\n"
                f"**Cloud Mode**: {'Mock (Offline)' if settings.MOCK_CLOUD else 'Active Cloud (Gemini/OpenAI)'}")

# Main Layout
st.markdown('<div class="main-title">SecureSphere-AI</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-title">Private LLM Deployment & Intelligent AI Guardrail Gateway Dashboard</div>', unsafe_allow_html=True)

# Tabs
tab_chat, tab_dashboard, tab_playground, tab_settings = st.tabs(["💬 Secure Chatbot", "📊 Analytics Dashboard", "🛡️ Gateway Playground", "⚙️ System Configuration"])

with tab_chat:
    st.markdown('<div class="section-header">💬 Secure Corporate Chatbot</div>', unsafe_allow_html=True)
    st.write("Ask questions freely. Sensitive data is automatically cleaned and routed behind the scenes.")
    
    # Store chat history in session state
    if "messages" not in st.session_state:
        st.session_state.messages = []

    # Display chat history
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.write(message["content"])

    # React to user input
    if user_input := st.chat_input("Message SecureSphere..."):
        # Display user message in chat message container
        with st.chat_message("user"):
            st.write(user_input)
        # Add user message to chat history
        st.session_state.messages.append({"role": "user", "content": user_input})
        
        # Call the gateway API
        url = "http://localhost:8000/generate"
        headers = {"X-API-Key": "securesphere_test_key_dev"}
        payload = {
            "prompt": user_input,
            "user_id": "chatbot_user"
        }
        
        with st.chat_message("assistant"):
            message_placeholder = st.empty()
            try:
                response = requests.post(url, json=payload, headers=headers, timeout=60.0)
                if response.status_code == 200:
                    data = response.json()
                    final_reply = data.get("final_response", "")
                    
                    # Highlight security actions quietly in a banner if blocked/masked
                    status_flag = data.get("status", "ALLOW")
                    if status_flag == "BLOCK":
                        st.error("⚠️ Policy Enforcement: Request Blocked.")
                    elif status_flag == "MASK":
                        st.info("🔒 SecureSphere: Response sanitized to protect outbound data leaks.")
                        
                    message_placeholder.write(final_reply)
                    st.session_state.messages.append({"role": "assistant", "content": final_reply})
                else:
                    message_placeholder.error(f"Error calling Gateway: Code {response.status_code}")
            except Exception as e:
                message_placeholder.error(f"Could not connect to gateway server: {str(e)}")

with tab_dashboard:
    # Refresh metrics
    stats = get_aggregate_stats()
    
    # 1. Key Metrics Cards Row
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        st.metric(label="Total Requests", value=stats["total_requests"])
    with col2:
        st.metric(label="Detections (PII)", value=stats["pii_detections"])
    with col3:
        st.metric(label="Blocked Requests", value=stats["blocked_requests"], delta_color="inverse")
    with col4:
        st.metric(label="Model Split (Local / Cloud)", value=f"{stats['local_count']} / {stats['cloud_count']}")
    with col5:
        st.metric(label="Avg Latency (ms)", value=f"{stats['avg_latency']}ms")

    st.markdown("---")

    # Fetch logs for charts
    logs = get_recent_logs(500)
    
    if len(logs) > 0:
        df = pd.DataFrame(logs)
        # Parse timestamp
        df['datetime'] = pd.to_datetime(df['timestamp'])
        
        # 2. Charts Row
        col_left, col_right = st.columns([2, 1])
        
        with col_left:
            st.markdown('<div class="section-header">Traffic & Request Status Over Time</div>', unsafe_allow_html=True)
            # Group by 1-minute intervals or similar depending on size
            df_grouped = df.groupby([df['datetime'].dt.strftime('%m-%d %H:%M'), 'status']).size().reset_index(name='count')
            fig_traffic = px.bar(
                df_grouped, 
                x='datetime', 
                y='count', 
                color='status',
                color_discrete_map={'ALLOW': '#2ecc71', 'BLOCK': '#e74c3c', 'MASK': '#f1c40f'},
                title="Request Throughput",
                labels={'datetime': 'Timestamp', 'count': 'Number of Requests'}
            )
            fig_traffic.update_layout(height=350, margin=dict(l=20, r=20, t=40, b=20))
            st.plotly_chart(fig_traffic, use_container_width=True)
            
        with col_right:
            st.markdown('<div class="section-header">LLM Model Split</div>', unsafe_allow_html=True)
            # Route / Model split pie chart
            df_models = df['model_used'].value_counts().reset_index()
            df_models.columns = ['model', 'count']
            fig_models = px.pie(
                df_models, 
                values='count', 
                names='model',
                color_discrete_sequence=px.colors.qualitative.Pastel,
                title="Model Load Distribution"
            )
            fig_models.update_layout(height=350, margin=dict(l=20, r=20, t=40, b=20))
            st.plotly_chart(fig_models, use_container_width=True)
            
        # 3. Latency & PII Type Row
        col_l2, col_r2 = st.columns([1, 1])
        
        with col_l2:
            st.markdown('<div class="section-header">Latency Distribution (ms)</div>', unsafe_allow_html=True)
            fig_latency = px.histogram(
                df, 
                x="latency_ms", 
                nbins=20,
                color="status",
                color_discrete_map={'ALLOW': '#2ecc71', 'BLOCK': '#e74c3c', 'MASK': '#f1c40f'},
                title="Processing Latency Histogram"
            )
            fig_latency.update_layout(height=300, margin=dict(l=20, r=20, t=40, b=20))
            st.plotly_chart(fig_latency, use_container_width=True)
            
        with col_r2:
            st.markdown('<div class="section-header">Detected PII Entity Types</div>', unsafe_allow_html=True)
            # Aggregate PII types list
            pii_list = []
            for plist in df['pii_types']:
                if isinstance(plist, list):
                    pii_list.extend(plist)
                elif isinstance(plist, str) and plist:
                    pii_list.extend(plist.split(','))
            
            if pii_list:
                df_pii = pd.DataFrame(pii_list, columns=['PII Type']).value_counts().reset_index()
                df_pii.columns = ['PII Type', 'Frequency']
                fig_pii = px.bar(
                    df_pii, 
                    x='Frequency', 
                    y='PII Type', 
                    orientation='h',
                    color='PII Type',
                    title="Blocked/Masked Entity Frequency"
                )
                fig_pii.update_layout(height=300, margin=dict(l=20, r=20, t=40, b=20), showlegend=False)
                st.plotly_chart(fig_pii, use_container_width=True)
            else:
                st.info("No PII data has been detected yet.")
        
        # 4. Raw Audit Logs Data Table
        st.markdown('<div class="section-header">Recent Audit Logs (Real-time)</div>', unsafe_allow_html=True)
        # Select clean subset of columns for display
        df_display = df[[
            "timestamp", "user_id", "prompt", "response", 
            "model_used", "status", "toxicity_score", "latency_ms"
        ]].copy()
        
        df_display['timestamp'] = pd.to_datetime(df_display['timestamp']).dt.strftime('%Y-%m-%d %H:%M:%S')
        st.dataframe(df_display, use_container_width=True)
        
    else:
        st.warning("No audit logs found. Submit a request through the playground to populate stats!")

with tab_playground:
    st.markdown('<div class="section-header">Bilateral Inspection Playground</div>', unsafe_allow_html=True)
    st.markdown("Test SecureSphere-AI's real-time de-identification, routing, and toxicity engines.")
    
    # Input area
    user_prompt = st.text_area(
        label="Test Prompt", 
        value="My Aadhaar card is 3689 4210 5678 and my email is sam@example.com. Can you draft a request?",
        height=100
    )
    
    test_user_id = st.text_input("Simulated User ID", "playground_user_dev")
    
    # Send request button
    if st.button("Submit through Gateway"):
        with st.spinner("Processing request through security pipeline..."):
            # Call our gateway running locally
            url = "http://localhost:8000/generate"
            headers = {"X-API-Key": "securesphere_test_key_dev"}
            payload = {
                "prompt": user_prompt,
                "user_id": test_user_id
            }
            
            try:
                response = requests.post(url, json=payload, headers=headers, timeout=15.0)
                if response.status_code == 200:
                    data = response.json()
                    
                    status_val = data.get("status", "ALLOW")
                    
                    # Layout comparison
                    col_status, col_route, col_latency = st.columns(3)
                    with col_status:
                        if status_val == "ALLOW":
                            st.success("🟢 STATUS: ALLOWED")
                        elif status_val == "MASK":
                            st.warning("🟡 STATUS: MASKED / SANITIZED")
                        else:
                            st.error("🔴 STATUS: BLOCKED")
                    with col_route:
                        st.info(f"🧭 ROUTE: {data.get('model_used')}")
                    with col_latency:
                        st.metric("Latency", f"{data.get('latency_ms')} ms")
                    
                    # Columns for inputs
                    col_p1, col_p2 = st.columns(2)
                    with col_p1:
                        st.subheader("Original Input Prompt")
                        st.code(data.get("original_prompt"))
                    with col_p2:
                        st.subheader("Sanitized Prompt sent to Model")
                        st.code(data.get("sanitized_prompt"))
                        
                    st.markdown("---")
                    
                    # Metadata details
                    st.subheader("PII Detection & Safety Results")
                    col_m1, col_m2, col_m3 = st.columns(3)
                    with col_m1:
                        st.write("**PII Entities Detected:**")
                        st.write(data.get("pii_detected") or "None")
                    with col_m2:
                        st.write(f"**Has PII:** {data.get('has_pii')}")
                    with col_m3:
                        st.write(f"**Outbound Toxicity Score:** {data.get('toxicity_score')}")
                        
                    st.markdown("---")
                    
                    # Columns for outputs
                    col_o1, col_o2 = st.columns(2)
                    with col_o1:
                        st.subheader("Raw Output (from LLM)")
                        st.code(data.get("raw_response"))
                    with col_o2:
                        st.subheader("Final Output (returned to User)")
                        st.code(data.get("final_response"))
                        
                else:
                    st.error(f"Gateway returned error code {response.status_code}: {response.text}")
                    st.info("Make sure the FastAPI gateway server is running! Run: uvicorn gateway.main:app --reload")
            except Exception as e:
                st.error(f"Could not connect to Gateway: {str(e)}")
                st.info("Please start the FastAPI gateway server on port 8000.")

with tab_settings:
    st.markdown('<div class="section-header">Gateway Active Config & Rules</div>', unsafe_allow_html=True)
    st.write("These parameters are currently loaded into memory from the `.env` file:")
    
    st.json({
        "Gateway Port": settings.PORT,
        "Gateway Host": settings.HOST,
        "Is Cloud Model Mocked?": settings.MOCK_CLOUD,
        "Local LLM URL": settings.LOCAL_LLM_URL,
        "Local LLM Model": settings.LOCAL_LLM_MODEL,
        "Bypass PII Routing (Force Cloud)": settings.BYPASS_PII_ROUTING,
        "Enforce Toxicity Filters": settings.ENFORCE_TOXICITY,
        "Toxicity Score Threshold": settings.TOXICITY_THRESHOLD,
        "Write Raw PII to Database Logs": settings.LOG_RAW_PII
    })
    
    st.info("To modify these parameters, update the `.env` file in the project root directory and restart the FastAPI gateway server.")
