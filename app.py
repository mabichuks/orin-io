import streamlit as st
import pandas as pd
from datetime import datetime
from agent import ThreatIntelligenceAgent
from constants import openai_api_key

# Set page configuration
st.set_page_config(
    page_title="ICS Threat Intelligence System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        text-align: center;
        padding: 1rem 0;
        background: linear-gradient(90deg, #1f4e79, #2e7bb8);
        color: white;
        border-radius: 10px;
        margin-bottom: 2rem;
    }
    .advisory-card {
        border: 1px solid #ddd;
        border-radius: 8px;
        padding: 1rem;
        margin: 0.5rem 0;
        background-color: #f8f9fa;
    }
    .mitre-technique {
        background-color: #e3f2fd;
        padding: 0.2rem 0.5rem;
        border-radius: 4px;
        margin: 0.2rem;
        display: inline-block;
        font-size: 0.85rem;
    }
    .confidence-high { border-left: 4px solid #4caf50; }
    .confidence-medium { border-left: 4px solid #ff9800; }
    .confidence-low { border-left: 4px solid #f44336; }
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
    with st.spinner("Initializing threat intelligence system..."):
        return ThreatIntelligenceAgent()

def display_advisory_card(advisory):
    """Display an advisory as a card"""
    confidence_class = f"confidence-{advisory.get('confidence', 'medium').lower()}"
    
    with st.container():
        st.markdown(f'<div class="advisory-card {confidence_class}">', unsafe_allow_html=True)
        
        col1, col2 = st.columns([3, 1])
        
        with col1:
            st.markdown(f"**{advisory['title']}**")
            st.markdown(f"*{advisory['id']} | Published: {advisory['published'][:10]}*")
            st.write(advisory['summary'])
            
            # Display MITRE techniques
            if advisory.get('mitre_techniques'):
                st.markdown("**MITRE ATT&CK Techniques:**")
                techniques_html = ""
                for technique in advisory['mitre_techniques']:
                    techniques_html += f'<span class="mitre-technique">{technique}</span>'
                st.markdown(techniques_html, unsafe_allow_html=True)
        
        with col2:
            st.markdown(f"**Confidence:** {advisory.get('confidence', 'N/A').title()}")
            if advisory.get('link'):
                st.markdown(f"[View Advisory]({advisory['link']})")
        
        st.markdown('</div>', unsafe_allow_html=True)

def main():
    # Check API key
    check_api_key()
    
    # Header
    st.markdown("""
    <div class="main-header">
        <h1>🛡️ ICS Threat Intelligence System</h1>
        <p>AI-Powered Industrial Control Systems Security Advisory Analysis</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Initialize agent
    agent = initialize_agent()
    
    # Sidebar
    with st.sidebar:
        st.header("🔧 System Controls")
        
        # Cache status
        try:
            cache_info = agent.get_cache_info()
            st.subheader("📊 Cache Status")
            
            if cache_info['status'] == 'loaded':
                st.success(f"✅ Loaded: {cache_info['count']} advisories")
                st.info(f"Latest: {cache_info['latest_advisory_date']}")
            elif cache_info['status'] == 'empty':
                st.warning("⚠️ No data loaded")
            else:
                st.error(f"❌ Error: {cache_info.get('error', 'Unknown')}")
                
        except Exception as e:
            st.error(f"Error checking cache: {str(e)}")
        
        st.markdown("---")
        
        # Check for updates
        if st.button("🔍 Check for Updates"):
            with st.spinner("Checking for new advisories..."):
                try:
                    update_info = agent.check_for_updates()
                    
                    if update_info['has_updates']:
                        st.success(f"🆕 {update_info['new_count']} new advisories available!")
                        
                        # Show preview of new advisories
                        if update_info.get('new_advisories'):
                            st.write("**Preview of new advisories:**")
                            for adv in update_info['new_advisories']:
                                st.write(f"• {adv['id']}: {adv['title'][:50]}...")
                    else:
                        st.info("✅ Knowledge base is up to date")
                        
                except Exception as e:
                    st.error(f"Error checking updates: {str(e)}")
        
        # Refresh options
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("🔄 Smart Update", type="primary", help="Only processes new advisories"):
                with st.spinner("Updating with new advisories..."):
                    try:
                        result = agent.refresh_knowledge_base(force_rebuild=False)
                        st.success(result)
                        st.rerun()
                    except Exception as e:
                        st.error(f"Update error: {str(e)}")
        
        with col2:
            if st.button("🔨 Force Rebuild", help="Rebuilds entire knowledge base"):
                with st.spinner("Rebuilding entire knowledge base..."):
                    try:
                        result = agent.refresh_knowledge_base(force_rebuild=True)
                        st.success(result)
                        st.rerun()
                    except Exception as e:
                        st.error(f"Rebuild error: {str(e)}")
        
        st.markdown("---")
        
        # MITRE ATT&CK Statistics
        st.header("📊 MITRE ATT&CK Statistics")
        try:
            stats = agent.get_mitre_statistics()
            st.metric("Total Advisories", stats['total_advisories'])
            
            # Confidence distribution
            st.subheader("Confidence Distribution")
            for confidence, count in stats['confidence_distribution'].items():
                st.write(f"• {confidence.title()}: {count}")
            
            # Most common techniques
            st.subheader("Top Techniques")
            for technique, count in stats['most_common_techniques'][:3]:
                st.write(f"• {technique}: {count}")
                
        except Exception as e:
            st.error(f"Error loading statistics: {str(e)}")
    
    # Main content area
    tab1, tab2, tab3, tab4 = st.tabs(["📋 Advisory Dashboard", "💬 Chat Interface", "🔍 Search & Analysis", "📈 Threat Intelligence"])
    
    with tab1:
        st.header("Latest ICS Security Advisories")
        
        try:
            # Get top 4 advisories
            advisories = agent.get_advisory_summary(limit=4)
            
            if advisories:
                st.success(f"Displaying top {len(advisories)} advisories from CISA ICS feed")
                
                for advisory in advisories:
                    display_advisory_card(advisory)
            else:
                st.warning("No advisories found. Try refreshing the knowledge base.")
                
        except Exception as e:
            st.error(f"Error loading advisories: {str(e)}")
    
    with tab2:
        st.header("💬 Chat with Threat Intelligence")
        
        # Chat interface
        if "messages" not in st.session_state:
            st.session_state.messages = []
        
        # Display chat messages
        for message in st.session_state.messages:
            with st.chat_message(message["role"]):
                st.markdown(message["content"])
        
        # Chat input
        if prompt := st.chat_input("Ask about ICS security advisories, vulnerabilities, or threat intelligence..."):
            # Add user message to chat history
            st.session_state.messages.append({"role": "user", "content": prompt})
            with st.chat_message("user"):
                st.markdown(prompt)
            
            # Generate assistant response
            with st.chat_message("assistant"):
                with st.spinner("Analyzing threat intelligence..."):
                    try:
                        response = agent.query(prompt)
                        st.markdown(response)
                        # Add assistant response to chat history
                        st.session_state.messages.append({"role": "assistant", "content": response})
                    except Exception as e:
                        error_msg = f"Error processing query: {str(e)}"
                        st.error(error_msg)
                        st.session_state.messages.append({"role": "assistant", "content": error_msg})
        
        # Clear chat button
        if st.button("🗑️ Clear Chat History"):
            st.session_state.messages = []
            st.rerun()
    
    with tab3:
        st.header("🔍 Search & Analysis")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.subheader("Search Advisories")
            search_query = st.text_input(
                "Enter search query:",
                placeholder="e.g., Siemens vulnerabilities, SQL injection, remote code execution"
            )
            
            if st.button("🔍 Search") and search_query:
                with st.spinner("Searching advisories..."):
                    try:
                        response = agent.query(f"Search for: {search_query}")
                        st.markdown("### Search Results")
                        st.markdown(response)
                    except Exception as e:
                        st.error(f"Search error: {str(e)}")
        
        with col2:
            st.subheader("Filter by MITRE Technique")
            
            # Common MITRE techniques dropdown
            mitre_techniques = [
                "T0819 - Exploit Public-Facing Application",
                "T0815 - Denial of Service", 
                "T0818 - Engineering Workstation Compromise",
                "T0883 - Internet Accessible Device",
                "T0866 - Exploitation of Remote Services"
            ]
            
            selected_technique = st.selectbox(
                "Select MITRE ATT&CK Technique:",
                ["Select a technique..."] + mitre_techniques
            )
            
            if selected_technique and selected_technique != "Select a technique...":
                technique_id = selected_technique.split(" - ")[0]
                
                if st.button("🎯 Filter by Technique"):
                    with st.spinner("Filtering advisories..."):
                        try:
                            matching_advisories = agent.search_by_mitre_technique(technique_id)
                            
                            if matching_advisories:
                                st.markdown(f"### Advisories mapped to {technique_id}")
                                for advisory in matching_advisories:
                                    with st.expander(f"{advisory['id']} - {advisory['title']}"):
                                        st.write(advisory['summary'])
                                        st.markdown(f"**Confidence:** {advisory['confidence']}")
                                        if advisory.get('link'):
                                            st.markdown(f"[View Full Advisory]({advisory['link']})")
                            else:
                                st.info(f"No advisories found for technique {technique_id}")
                                
                        except Exception as e:
                            st.error(f"Filter error: {str(e)}")
    
    with tab4:
        st.header("📈 Comprehensive Threat Intelligence")
        
        col1, col2 = st.columns([3, 1])
        
        with col1:
            if st.button("📊 Generate Threat Intelligence Report", type="primary"):
                with st.spinner("Generating comprehensive threat intelligence report..."):
                    try:
                        report = agent.get_threat_intelligence_summary()
                        st.markdown("### Threat Intelligence Report")
                        st.markdown(report)
                    except Exception as e:
                        st.error(f"Error generating report: {str(e)}")
        
        with col2:
            st.subheader("Quick Actions")
            
            if st.button("🔥 Critical Vulnerabilities"):
                with st.spinner("Analyzing critical vulnerabilities..."):
                    try:
                        response = agent.query("What are the most critical vulnerabilities in the latest advisories? Focus on those with high severity or potential for remote code execution.")
                        st.markdown("### Critical Vulnerabilities")
                        st.markdown(response)
                    except Exception as e:
                        st.error(f"Error: {str(e)}")
            
            if st.button("🎯 Attack Patterns"):
                with st.spinner("Analyzing attack patterns..."):
                    try:
                        response = agent.query("What are the common attack patterns and MITRE ATT&CK techniques seen in recent ICS advisories?")
                        st.markdown("### Attack Patterns Analysis")
                        st.markdown(response)
                    except Exception as e:
                        st.error(f"Error: {str(e)}")
            
            if st.button("🛡️ Defense Recommendations"):
                with st.spinner("Generating defense recommendations..."):
                    try:
                        response = agent.query("Based on the latest ICS security advisories, what are the key security recommendations and mitigation strategies?")
                        st.markdown("### Defense Recommendations")
                        st.markdown(response)
                    except Exception as e:
                        st.error(f"Error: {str(e)}")
        
        # Additional metrics and visualizations
        st.markdown("---")
        st.subheader("📊 Advisory Metrics")
        
        try:
            advisories = agent.get_advisories_data()
            
            if advisories:
                # Create metrics dataframe
                df_data = []
                for advisory in advisories:
                    mitre_mapping = advisory.get('mitre_mapping', {})
                    df_data.append({
                        'Advisory ID': advisory['id'],
                        'Title': advisory['title'][:50] + '...' if len(advisory['title']) > 50 else advisory['title'],
                        'Published': advisory['published'][:10],
                        'MITRE Techniques': len(mitre_mapping.get('mapped_techniques', [])),
                        'Confidence': mitre_mapping.get('confidence', 'N/A').title()
                    })
                
                df = pd.DataFrame(df_data)
                st.dataframe(df, use_container_width=True)
                
                # Summary metrics
                col1, col2, col3, col4 = st.columns(4)
                
                with col1:
                    st.metric("Total Advisories", len(advisories))
                
                with col2:
                    high_confidence = sum(1 for a in advisories 
                                        if a.get('mitre_mapping', {}).get('confidence') == 'high')
                    st.metric("High Confidence Mappings", high_confidence)
                
                with col3:
                    total_techniques = sum(len(a.get('mitre_mapping', {}).get('mapped_techniques', [])) 
                                         for a in advisories)
                    st.metric("Total MITRE Mappings", total_techniques)
                
                with col4:
                    avg_techniques = total_techniques / len(advisories) if advisories else 0
                    st.metric("Avg Techniques per Advisory", f"{avg_techniques:.1f}")
                    
        except Exception as e:
            st.error(f"Error loading metrics: {str(e)}")
    
    # Footer
    st.markdown("---")
    st.markdown("""
    <div style="text-align: center; color: #666; padding: 1rem;">
        <p>🛡️ ICS Threat Intelligence System | Powered by LlamaIndex & OpenAI | Data from CISA ICS Advisories</p>
        <p><small>Last updated: {}</small></p>
    </div>
    """.format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")), unsafe_allow_html=True)

if __name__ == "__main__":
    main()