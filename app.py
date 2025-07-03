import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from agent import ThreatIntelligenceAgent
from constants import openai_api_key
from style import UI_STYLE
from indexmanager import IndexManager

# Set page configuration
st.set_page_config(
    page_title="ICS Security Advisories",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Custom CSS for better styling and fixed chat
st.markdown(UI_STYLE, unsafe_allow_html=True)

# Additional CSS to fix chat positioning
st.markdown("""
<style>
    /* Fix chat input positioning */
    .stChatInput {
        position: fixed !important;
        bottom: 0 !important;
        left: 0 !important;
        right: 0 !important;
        z-index: 999 !important;
        background: white !important;
        border-top: 1px solid #ddd !important;
        padding: 1rem !important;
    }
    
    /* Add padding to chat container to prevent overlap */
    .chat-container {
        padding-bottom: 100px !important;
        margin-bottom: 1rem !important;
    }
    
    /* Ensure chat messages are scrollable */
    .chat-messages {
        max-height: 60vh !important;
        overflow-y: auto !important;
        margin-bottom: 2rem !important;
    }
</style>
""", unsafe_allow_html=True)

def check_api_key():
    """Check if OpenAI API key is configured"""
    if not openai_api_key:
        st.error("⚠️ OpenAI API key not found! Please set OPENAI_API_KEY in your .env file")
        st.stop()

@st.cache_resource
def initialize_agent():
    """Initialize the threat intelligence agent (cached)"""
    with st.spinner("Initializing system..."):
        index_manager = IndexManager("ai-cti")
        index = index_manager.load_existing_index()
        return ThreatIntelligenceAgent(index, index_manager)

# Initialize session state variables
if "agent" not in st.session_state:
    st.session_state.agent = initialize_agent()
if "messages" not in st.session_state:
    st.session_state.messages = []
if "current_tab" not in st.session_state:
    st.session_state.current_tab = 0

def create_mitre_pie_chart(advisories):
    """Create pie chart for MITRE ATT&CK techniques"""
    all_techniques = []
    for adv in advisories:
        all_techniques.extend(adv.get('mitre_techniques', []))
    
    if all_techniques:
        technique_counts = Counter(all_techniques)
        techniques = list(technique_counts.keys())
        frequencies = list(technique_counts.values())
        
        fig = px.pie(
            values=frequencies,
            names=techniques,
            title='Distribution of MITRE ATT&CK Techniques in Security Advisories',
            labels={'names': 'MITRE Technique', 'values': 'Frequency'},
            height=500
        )
        
        fig.update_traces(
            textposition='inside',
            textinfo='percent+label',
            hovertemplate='<b>%{label}</b><br>Count: %{value}<br>Percentage: %{percent}<extra></extra>'
        )
        
        fig.update_layout(
            showlegend=True,
            legend=dict(
                orientation="v",
                yanchor="top",
                y=1,
                xanchor="left",
                x=1.01
            ),
            margin=dict(t=50, b=50, l=50, r=150)
        )
        
        return fig
    return None

def display_advisory_grid(agent, advisories):
    """Display advisories in a grid format"""
    if not advisories:
        st.warning("No advisories found.")
        return
    
    cols = st.columns(2)
    for i, advisory in enumerate(advisories):
        with cols[i % 2]:
            agent.display_advisory_card(advisory)

def display_overview_tab():
    """Display the Overview tab content"""
    st.header("📊 Security Overview Dashboard")
    
    try:
        advisories = st.session_state.agent.get_advisory_summary(limit=10)
        top_4_advisories = advisories[:4]
        
        if advisories:
            # Metrics row
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("📋 Total Advisories", len(advisories))
            
            with col2:
                all_techniques = []
                for adv in advisories:
                    all_techniques.extend(adv.get('mitre_techniques', []))
                unique_techniques = len(set(all_techniques))
                st.metric("🎯 MITRE Techniques", unique_techniques)
            
            with col3:
                try:
                    latest_date = max(pd.to_datetime(adv['published']).date() for adv in advisories)
                    st.metric("📅 Latest Advisory", latest_date.strftime("%Y-%m-%d"))
                except:
                    st.metric("📅 Latest Advisory", "Unknown")
            
            with col4:
                technique_counts = Counter(all_techniques)
                if technique_counts:
                    most_common = technique_counts.most_common(1)[0][0]
                    st.metric("🔥 Top Technique", most_common)
                else:
                    st.metric("🔥 Top Technique", "None")
            
            st.markdown("---")
            
            # MITRE ATT&CK Techniques Pie Chart
            st.subheader("🎯 MITRE ATT&CK Techniques Distribution")
            
            fig = create_mitre_pie_chart(advisories)
            if fig:
                st.plotly_chart(fig, use_container_width=True)
                
                # Additional insights
                col1, col2 = st.columns(2)
                
                with col1:
                    st.subheader("🔍 Top MITRE Techniques")
                    technique_counts = Counter(all_techniques)
                    if technique_counts:
                        for technique, count in technique_counts.most_common(5):
                            percentage = (count / len(all_techniques)) * 100
                            st.write(f"**{technique}**: {count} advisories ({percentage:.1f}%)")
                    else:
                        st.write("No MITRE techniques mapped yet.")
                
                with col2:
                    st.subheader("📊 Distribution Summary")
                    total_techniques = len(all_techniques)
                    unique_count = len(technique_counts)
                    
                    st.write(f"**Total technique instances**: {total_techniques}")
                    st.write(f"**Unique techniques**: {unique_count}")
                    
                    if unique_count > 0:
                        avg_per_technique = total_techniques / unique_count
                        st.write(f"**Average per technique**: {avg_per_technique:.1f}")
                        
                        if technique_counts:
                            most_frequent = technique_counts.most_common(1)[0]
                            st.write(f"**Most frequent**: {most_frequent[0]} ({most_frequent[1]} times)")
            else:
                st.info("No MITRE ATT&CK technique data available for analysis.")
            
            st.markdown("---")
            
            # Latest advisories grid
            st.subheader("🆕 Latest Security Advisories")
            display_advisory_grid(st.session_state.agent, top_4_advisories)
            
        else:
            st.warning("No advisories found. The system may need to fetch new data.")
            
    except Exception as e:
        st.error(f"Error loading overview: {str(e)}")

def display_chat_tab():
    """Display the AI Chat tab content with improved state management"""
    st.header("💬 AI Security Assistant")
    
    # Create a container for chat messages with fixed height
    chat_container = st.container()
    
    with chat_container:
        # Display existing messages
        if st.session_state.messages:
            for i, message in enumerate(st.session_state.messages):
                with st.chat_message(message["role"]):
                    st.markdown(message["content"])
    
    # Handle new messages with a form to prevent page refresh
    with st.form(key="chat_form", clear_on_submit=True):
        col1, col2 = st.columns([6, 1])
        with col1:
            user_input = st.text_input(
                "Ask about ICS security advisories, vulnerabilities, or threats...",
                key="user_input",
                label_visibility="collapsed"
            )
        with col2:
            submitted = st.form_submit_button("Send", use_container_width=True)
    
    # Process the message if submitted
    if submitted and user_input:
        # Add user message
        st.session_state.messages.append({"role": "user", "content": user_input})
        
        # Display user message
        with st.chat_message("user"):
            st.markdown(user_input)
        
        # Generate and display assistant response
        with st.chat_message("assistant"):
            with st.spinner("Thinking..."):
                try:
                    answer = st.session_state.agent.chat(user_input).response
                    st.markdown(answer)
                    st.session_state.messages.append({"role": "assistant", "content": answer})
                except Exception as e:
                    error_msg = f"Error processing query: {str(e)}"
                    st.error(error_msg)
                    st.session_state.messages.append({"role": "assistant", "content": error_msg})
        
        # Force rerun to show new messages
        st.rerun()
    
    # Clear chat button
    if st.session_state.messages:
        if st.button("🗑️ Clear Chat", key="clear_chat"):
            st.session_state.messages = []
            st.rerun()

def main():
    # Check API key
    check_api_key()
    
    # Header
    st.markdown("""
    <div class="main-header">
        <h1>🛡️ ICS Security Advisories</h1>
        <p>Latest Industrial Control Systems Security Intelligence</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Create tabs and handle selection
    tab_names = ["📊 Overview", "💬 AI Chat"]
    
    # Use selectbox instead of tabs for more stable state management
    selected_tab = st.selectbox(
        "Choose a section:",
        options=tab_names,
        index=st.session_state.get("current_tab", 0),
        key="tab_selector"
    )
    
    # Update session state
    st.session_state.current_tab = tab_names.index(selected_tab)
    
    # Display content based on selection
    if selected_tab == "📊 Overview":
        display_overview_tab()
    elif selected_tab == "💬 AI Chat":
        display_chat_tab()
    
    # Footer
    st.markdown("---")
    st.markdown("""
    <div style="text-align: center; color: #666; padding: 1rem; margin-top: 2rem;">
        <p>🛡️ ICS Security Advisory System | Data from CISA ICS Advisories</p>
        <p><small>Last updated: {}</small></p>
    </div>
    """.format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")), unsafe_allow_html=True)

if __name__ == "__main__":
    main()