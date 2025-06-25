import streamlit as st
from datetime import datetime
from agent import ThreatIntelligenceAgent
from constants import openai_api_key
from bs4 import BeautifulSoup
import re

# Set page configuration
st.set_page_config(
    page_title="ICS Security Advisories",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
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
        border-left: 4px solid #2e7bb8;
    }
    .advisory-title {
        font-weight: bold;
        font-size: 1.1rem;
        color: #1f4e79;
        margin-bottom: 0.5rem;
    }
    .advisory-meta {
        color: #666;
        font-size: 0.9rem;
        margin-bottom: 0.5rem;
    }
    .advisory-summary {
        line-height: 1.5;
    }
    .mitre-technique {
        background-color: #e3f2fd;
        padding: 0.2rem 0.5rem;
        border-radius: 4px;
        margin: 0.2rem 0.2rem 0.2rem 0;
        display: inline-block;
        font-size: 0.85rem;
        color: #1565c0;
    }
    .confidence-badge {
        background-color: #4caf50;
        color: white;
        padding: 0.2rem 0.5rem;
        border-radius: 12px;
        font-size: 0.8rem;
        margin-left: 0.5rem;
    }
    .confidence-medium {
        background-color: #ff9800;
    }
    .confidence-low {
        background-color: #f44336;
    }
    .chat-container {
        background-color: #f8f9fa;
        border-radius: 10px;
        padding: 1rem;
        margin-top: 2rem;
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
        agent = ThreatIntelligenceAgent()
        # Store agent in session state for access in other functions
        st.session_state['agent'] = agent
        return agent

def clean_html_text(html_text: str, max_length: int = 300) -> str:
    """
    Clean HTML tags from text and truncate to specified length
    """
    if not html_text:
        return "No summary available"
    
    # Parse HTML and extract text with proper separator
    soup = BeautifulSoup(html_text, 'html.parser')
    
    # Add spaces around block elements to prevent word concatenation
    for tag in soup.find_all(['p', 'div', 'li', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'br']):
        tag.insert_before(' ')
        tag.insert_after(' ')
    
    # Extract clean text
    clean_text = soup.get_text(separator=' ', strip=True)
    
    # Clean up multiple spaces and newlines
    clean_text = re.sub(r'\s+', ' ', clean_text).strip()
    
    # Remove any remaining problematic characters that might cause formatting issues
    clean_text = re.sub(r'[^\w\s\-.,;:!?()\[\]{}"\'/]', '', clean_text)
    
    # Truncate if too long
    if len(clean_text) > max_length:
        clean_text = clean_text[:max_length] + "..."
    
    return clean_text

@st.cache_data
def generate_summary(advisory_id: str, full_content: str, _llm) -> str:
    """
    Use LLM to generate a concise summary of the advisory content
    Cached based on advisory_id to avoid expensive re-generation
    """
    try:
        summary_prompt = f"""
        Please provide a concise 2-3 sentence summary of this ICS security advisory. Focus on:
        - What the vulnerability is
        - What systems are affected
        - The potential impact
        
        Advisory content:
        {full_content[:2000]}  # Limit content to avoid token limits
        
        Provide only the summary, no additional text:
        """
        
        response = _llm.complete(summary_prompt)
        return response.text.strip()
    except Exception as e:
        # Fallback to cleaned HTML if LLM fails
        return clean_html_text(full_content, max_length=200)

def display_advisory_card(advisory):
    """Display an advisory as a card with MITRE ATT&CK mapping"""
    # Check if we have a cached summary first, otherwise generate one
    advisory_id = advisory.get('id', 'unknown')
    
    # Try to get cached summary from advisory data first
    if 'llm_summary' in advisory and advisory['llm_summary']:
        clean_summary = advisory['llm_summary']
    else:
        # Generate LLM summary (cached by advisory ID)
        agent = st.session_state.get('agent')
        if agent and agent.llm:
            clean_summary = generate_summary(advisory_id, advisory.get('summary', ''), agent.llm)
        else:
            # Fallback to cleaned HTML
            clean_summary = clean_html_text(advisory.get('summary', ''), max_length=400)
    
    # Clean and escape the title to prevent formatting issues
    clean_title = clean_html_text(advisory.get('title', 'No Title'), max_length=100)
    
    # Get MITRE techniques (removed confidence)
    mitre_techniques = advisory.get('mitre_techniques', [])
    
    # Create MITRE techniques HTML (without confidence)
    mitre_html = ""
    if mitre_techniques:
        mitre_html = "<div style='margin: 0.5rem 0;'><strong>MITRE ATT&CK:</strong><br>"
        for technique in mitre_techniques:
            mitre_html += f'<span class="mitre-technique">{technique}</span>'
        mitre_html += "</div>"
    
    with st.container():
        st.markdown(f"""
        <div class="advisory-card">
            <div class="advisory-title">{clean_title}</div>
            <div class="advisory-meta">
                {advisory['id']} | Published: {advisory['published'][:10]}
            </div>
            <div class="advisory-summary">{clean_summary}</div>
            {mitre_html}
            <div style="margin-top: 0.5rem;">
                <a href="{advisory['link']}" target="_blank">View Full Advisory →</a>
            </div>
        </div>
        """, unsafe_allow_html=True)

def rag_query(agent, query: str) -> str:
    """
    Perform RAG query: retrieve top 4 relevant documents and refine with LLM
    """
    try:
        # Use the agent's index manager to get the query engine
        query_engine = agent.index_manager.get_query_engine()
        response = query_engine.query(query)
        return str(response)
    except Exception as e:
        return f"Error processing query: {str(e)}"

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
    agent = initialize_agent()
    
    # Main content
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.header("📋 Latest Security Advisories")
        
        try:
            # Get top 4 advisories
            advisories = agent.get_advisory_summary(limit=4)
            
            if advisories:
                st.success(f"Showing {len(advisories)} most recent advisories")
                
                for advisory in advisories:
                    display_advisory_card(advisory)
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
            st.error(f"Error loading advisories: {str(e)}")
    
    with col2:
        st.header("💬 Ask About Security Advisories")
        
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
                    with st.spinner("Searching advisories..."):
                        try:
                            response = rag_query(agent, prompt)
                            st.markdown(response)
                            # Add assistant response to chat history
                            st.session_state.messages.append({"role": "assistant", "content": response})
                        except Exception as e:
                            error_msg = f"Error processing query: {str(e)}"
                            st.error(error_msg)
                            st.session_state.messages.append({"role": "assistant", "content": error_msg})
            
            # Clear chat button
            if st.session_state.messages:
                if st.button("🗑️ Clear Chat"):
                    st.session_state.messages = []
                    st.rerun()
            
            st.markdown('</div>', unsafe_allow_html=True)
    
    # Footer with system info
    st.markdown("---")
    
    col1, col2, col3 = st.columns([1, 1, 1])
    
    with col1:
        try:
            cache_info = agent.get_cache_info()
            if cache_info['status'] == 'loaded':
                st.metric("📊 Advisories Loaded", cache_info['count'])
            else:
                st.metric("📊 Advisories Loaded", "0")
        except:
            st.metric("📊 Advisories Loaded", "Error")
    
    with col2:
        try:
            cache_info = agent.get_cache_info()
            if cache_info['status'] == 'loaded':
                st.metric("📅 Latest Advisory", cache_info.get('latest_advisory_date', 'Unknown'))
            else:
                st.metric("📅 Latest Advisory", "None")
        except:
            st.metric("📅 Latest Advisory", "Error")
    
    with col3:
        if st.button("🔄 Refresh System"):
            with st.spinner("Refreshing..."):
                try:
                    result = agent.refresh_knowledge_base()
                    st.success("System refreshed successfully!")
                    st.rerun()
                except Exception as e:
                    st.error(f"Refresh failed: {str(e)}")
    
    # Footer
    st.markdown("""
    <div style="text-align: center; color: #666; padding: 1rem; margin-top: 2rem;">
        <p>🛡️ ICS Security Advisory System | Data from CISA ICS Advisories</p>
        <p><small>Last updated: {}</small></p>
    </div>
    """.format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")), unsafe_allow_html=True)

if __name__ == "__main__":
    main()