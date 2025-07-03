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

# Custom CSS for better styling
st.markdown(UI_STYLE, unsafe_allow_html=True)

def check_api_key():
    """Check if OpenAI API key is configured"""
    if not openai_api_key:
        st.error("⚠️ OpenAI API key not found! Please set OPENAI_API_KEY in your .env file")
        st.stop()

@st.cache_resource
def initialize_agent():
    """Initialize the threat intelligence agent (cached)"""
    with st.spinner("Initializing system..."):
        index_manager = IndexManager()
        index = index_manager.load_existing_index()
        return ThreatIntelligenceAgent(index)

if "agent" not in st.session_state:
    st.session_state.agent = initialize_agent()
if "messages" not in st.session_state:
    st.session_state.messages = []

def create_mitre_time_series(advisories):
    """Create time series data for MITRE ATT&CK techniques"""
    if not advisories:
        return pd.DataFrame()
    
    # Prepare data for time series
    time_series_data = []
    
    for advisory in advisories:
        try:
            # Parse the published date
            published_date = pd.to_datetime(advisory['published']).date()
            mitre_techniques = advisory.get('mitre_techniques', [])
            
            # Add each technique as a separate row
            for technique in mitre_techniques:
                time_series_data.append({
                    'date': published_date,
                    'technique': technique,
                    'advisory_id': advisory['id']
                })
        except Exception as e:
            print(f"Error processing advisory {advisory.get('id', 'unknown')}: {e}")
            continue
    
    if not time_series_data:
        return pd.DataFrame()
    
    # Create DataFrame
    df = pd.DataFrame(time_series_data)
    
    # Group by date and technique, count occurrences
    df_grouped = df.groupby(['date', 'technique']).size().reset_index(name='count')
    
    return df_grouped

def display_advisory_grid(agent, advisories):
    """Display advisories in a grid format"""
    if not advisories:
        st.warning("No advisories found.")
        return
    
    # Create grid layout (2 columns)
    cols = st.columns(2)
    
    for i, advisory in enumerate(advisories):
        with cols[i % 2]:
            agent.display_advisory_card(advisory)

def display_overview_tab(agent):
    """Display the Overview tab content"""
    st.header("📊 Security Overview Dashboard")
    
    # Get advisories data
    try:
        advisories = agent.get_advisory_summary(limit=10)  # Get more for time series
        top_4_advisories = advisories[:4]  # Top 4 for grid display
        print(f"Gotten advisory summaries {advisories}")
        
        if advisories:
            # Metrics row
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("📋 Total Advisories", len(advisories))
            
            with col2:
                # Count unique MITRE techniques
                all_techniques = []
                for adv in advisories:
                    all_techniques.extend(adv.get('mitre_techniques', []))
                unique_techniques = len(set(all_techniques))
                st.metric("🎯 MITRE Techniques", unique_techniques)
            
            with col3:
                # Get latest advisory date
                try:
                    latest_date = max(pd.to_datetime(adv['published']).date() for adv in advisories)
                    st.metric("📅 Latest Advisory", latest_date.strftime("%Y-%m-%d"))
                except:
                    st.metric("📅 Latest Advisory", "Unknown")
            
            with col4:
                # Most common technique
                technique_counts = Counter(all_techniques)
                if technique_counts:
                    most_common = technique_counts.most_common(1)[0][0]
                    st.metric("🔥 Top Technique", most_common)
                else:
                    st.metric("🔥 Top Technique", "None")
            
            st.markdown("---")
            
            # Time series chart
            st.subheader("📈 MITRE ATT&CK Techniques Timeline")
            
            df_time_series = create_mitre_time_series(advisories)
            
            if not df_time_series.empty:
                # Create time series plot
                fig = px.line(
                    df_time_series, 
                    x='date', 
                    y='count',
                    color='technique',
                    title='MITRE ATT&CK Techniques Over Time',
                    labels={
                        'date': 'Publication Date',
                        'count': 'Number of Advisories',
                        'technique': 'MITRE Technique'
                    },
                    height=400
                )
                
                fig.update_layout(
                    xaxis_title="Publication Date",
                    yaxis_title="Number of Advisories",
                    legend_title="MITRE ATT&CK Techniques",
                    hovermode='x unified'
                )
                
                st.plotly_chart(fig, use_container_width=True)
                
                # Additional insights
                col1, col2 = st.columns(2)
                
                with col1:
                    st.subheader("🔍 Top MITRE Techniques")
                    technique_summary = df_time_series.groupby('technique')['count'].sum().sort_values(ascending=False)
                    
                    if not technique_summary.empty:
                        for technique, count in technique_summary.head(5).items():
                            st.write(f"**{technique}**: {count} advisories")
                    else:
                        st.write("No MITRE techniques mapped yet.")
                
                with col2:
                    st.subheader("📊 Recent Activity")
                    # Show activity in last 30 days
                    recent_date = df_time_series['date'].max() - timedelta(days=30)
                    recent_activity = df_time_series[df_time_series['date'] > recent_date]
                    
                    if not recent_activity.empty:
                        recent_count = recent_activity['count'].sum()
                        st.write(f"**Last 30 days**: {recent_count} technique mappings")
                        
                        # Most active technique recently
                        recent_top = recent_activity.groupby('technique')['count'].sum().idxmax()
                        st.write(f"**Most active**: {recent_top}")
                    else:
                        st.write("No recent activity in the last 30 days.")
            else:
                st.info("No MITRE ATT&CK technique data available for time series analysis.")
            
            st.markdown("---")
            
            # Latest advisories grid
            st.subheader("🆕 Latest Security Advisories")
            display_advisory_grid(agent, top_4_advisories)
            
        else:
            st.warning("No advisories found. The system may need to fetch new data.")
            if st.button("🔄 Refresh Data"):
                with st.spinner("Fetching latest advisories..."):
                    try:
                        agent.refresh_knowledge_base()
                        st.rerun()
                    except Exception as e:
                        st.error(f"Error refreshing data: {str(e)}")
                        
    except Exception as e:
        raise e

def display_chat_tab(agent):
    """Display the AI Chat tab content"""
    st.header("💬 AI Security Assistant")
    
    # Chat interface in a container
    with st.container():
        st.markdown('<div class="chat-container">', unsafe_allow_html=True)
        
        # Initialize chat history
        if "messages" not in st.session_state:
            st.session_state.messages = []
        
        # Display chat messages
        for message in st.session_state.messages:
            with st.chat_message(message["role"]):
                st.markdown(message["content"])
        
        # Chat input
        if prompt := st.chat_input("Ask about ICS security advisories, vulnerabilities, or threats..."):
            # Add user message to chat history
            st.session_state.messages.append({"role": "user", "content": prompt})
            with st.chat_message("user"):
                st.markdown(prompt)
            
            # Generate assistant response using RAG
            with st.chat_message("assistant"):
                with st.spinner("Thinking..."):
                    try:
                        response = st.session_state.agent.chat(prompt)
                        st.markdown(response)
                        # Add assistant response to chat history
                        st.session_state.messages.append({"role": "assistant", "content": response})
                    except Exception as e:
                        error_msg = f"Error processing query: {str(e)}"
                        st.error(error_msg)
                        st.session_state.messages.append({"role": "assistant", "content": error_msg})
        
        # Chat controls
        col1, col2 = st.columns([1, 4])
        with col1:
            if st.session_state.messages:
                if st.button("🗑️ Clear Chat"):
                    st.session_state.messages = []
                    st.rerun()
        
        st.markdown('</div>', unsafe_allow_html=True)

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
    
    # Initialize agent
    # agent = initialize_agent()
    
    # Create tabs
    tab1, tab2 = st.tabs(["📊 Overview", "💬 AI Chat"])
    
    with tab1:
        display_overview_tab(st.session_state.agent)
    
    with tab2:
        display_chat_tab(st.session_state.agent)
    
    # Footer with system controls
    st.markdown("---")
    
    
    # Footer
    st.markdown("""
    <div style="text-align: center; color: #666; padding: 1rem; margin-top: 2rem;">
        <p>🛡️ ICS Security Advisory System | Data from CISA ICS Advisories</p>
        <p><small>Last updated: {}</small></p>
    </div>
    """.format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")), unsafe_allow_html=True)

if __name__ == "__main__":
    main()