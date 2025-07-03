from typing import List, Dict, Any
from llama_index.core.agent import ReActAgent
from llama_index.core.tools import QueryEngineTool, ToolMetadata
from tools import create_advisory_fetch_tool, create_mitre_mapping_tool
from constants import llm_model, ADVISORY_SUMMARY_PROMPT_TEMPLATE, THREAT_INTELLIGENCE_SUMMARY_PROMPT
from bs4 import BeautifulSoup
from indexmanager import IndexManager
from llama_index.core.prompts import PromptTemplate
from constants import ENHANCED_RAG_TEMPLATE
from llama_index.core.response_synthesizers import ResponseMode
import re
import streamlit as st

class ThreatIntelligenceAgent:
    def __init__(self, index, index_manager):
        """Initialize the Threat Intelligence Agent"""
        self.index_manager = index_manager
        self.llm = llm_model
        self.index = index
        self.agent = None
        self.setup_agent()
    
    def setup_agent(self):
        """Setup the ReAct agent with tools"""
        # Get query engine tool
        query_engine_tool = self.create_query_engine_tool()
        
        # Get function tools
        advisory_fetch_tool = create_advisory_fetch_tool()
        mitre_mapping_tool = create_mitre_mapping_tool()
        
        # Create tools list
        tools = [
            query_engine_tool
            # advisory_fetch_tool,
            # mitre_mapping_tool
        ]
        
        # Create ReAct agent
        self.agent = ReActAgent.from_tools(
            tools=tools,
            llm=self.llm,
            verbose=True,
            max_iterations=10
        )
    
    def create_query_engine_tool(self) -> QueryEngineTool:
        """Create a query engine tool from the vector index"""
        qa_prompt = PromptTemplate(ENHANCED_RAG_TEMPLATE)

        self.query_engine = self.index.as_query_engine(
            llm_model=self.llm, similarity_top_k=5, text_qa_template=qa_prompt, response_mode="compact"
        )        
        return QueryEngineTool.from_defaults(
            query_engine=self.query_engine,
            name="advisory_search",
            description="Search and query ICS security advisories from CISA. "
                           "Use this to find information about specific vulnerabilities, "
                           "security issues, MITRE ATT&CK mappings, or threat intelligence."
        )
    
    def chat(self, query: str):
        prompt = f"""
        {query}. Ensure your final response is well structured, well detailed and contains the CVE ID links, advisory links and any additional resources
        """
        return self.agent.chat(prompt)
    
    def query(self, question: str) -> str:
        """
        Query the agent with a question
        """
        try:
            response = self.agent.chat(question)
            return str(response)
        except Exception as e:
            return f"Error processing query: {str(e)}"
    
    def rag_query(self, query: str) -> str:
        """
        Perform RAG query: retrieve top 4 relevant documents and refine with LLM
        """
        try:
            # Use the agent's index manager to get the query engine
            query_engine = self.index_manager.get_query_engine()
            response = query_engine.query(query)
            return str(response)
        except Exception as e:
            return f"Error processing query: {str(e)}"
    
    def clean_html_text(self, html_text: str, max_length: int = 300) -> str:
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
    def generate_summary(_self, advisory_id: str, full_content: str) -> str:
        """
        Use LLM to generate a concise summary of the advisory content
        Cached based on advisory_id to avoid expensive re-generation
        """
        try:
            # Use the prompt template from constants
            summary_prompt = ADVISORY_SUMMARY_PROMPT_TEMPLATE.format(
                advisory_content=full_content[:2000]  # Limit content to avoid token limits
            )
            
            response = _self.llm.complete(summary_prompt)
            print(f"Generated Advisory for {advisory_id}: {response.text.strip()}")
            return response.text.strip()
        except Exception as e:
            # Fallback to cleaned HTML if LLM fails
            return _self.clean_html_text(full_content, max_length=200)

    def display_advisory_card(self, advisory):
        """Display an advisory as a card with MITRE ATT&CK mapping"""
        # Check if we have a cached summary first, otherwise generate one
        advisory_id = advisory.get('id', 'unknown')
        
        # Try to get cached summary from advisory data first
        if 'llm_summary' in advisory and advisory['llm_summary']:
            clean_summary = advisory['llm_summary']
        else:
            # Generate LLM summary (cached by advisory ID)
            if self.llm:
                clean_summary = self.generate_summary(advisory_id, advisory.get('summary', ''))
            else:
                # Fallback to cleaned HTML
                clean_summary = self.clean_html_text(advisory.get('summary', ''), max_length=400)
        
        # Clean and escape the title to prevent formatting issues
        clean_title = self.clean_html_text(advisory.get('title', 'No Title'), max_length=100)
        
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
    
    def get_advisory_summary(self, limit: int = 4) -> List[Dict[str, Any]]:
        """
        Get summary of top advisories
        """
        advisories = self.index_manager.get_advisories_data()
        
        # Return top advisories with summary info
        summary_advisories = []
        for advisory in advisories[:limit]:
            summary = {
                'id': advisory['id'],
                'title': advisory['title'],
                'summary': advisory['summary'],
                'published': advisory['published'],
                'link': advisory['link'],
                'mitre_techniques': advisory.get('mitre_mapping', {}).get('mapped_techniques', []),
                'confidence': advisory.get('mitre_mapping', {}).get('confidence', 'N/A')
            }
            print(f"Advisory Summary: {summary}")
            summary_advisories.append(summary)
        
        return summary_advisories
    
    
    
    def get_cache_info(self):
        """
        Get information about current cache state
        """
        return self.index_manager.get_cache_info()
    
    def get_mitre_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about MITRE ATT&CK technique mappings
        """
        advisories = self.index_manager.get_advisories_data()
        
        technique_counts = {}
        confidence_counts = {'high': 0, 'medium': 0, 'low': 0}
        
        for advisory in advisories:
            mitre_mapping = advisory.get('mitre_mapping', {})
            techniques = mitre_mapping.get('mapped_techniques', [])
            confidence = mitre_mapping.get('confidence', 'medium')
            
            # Count techniques
            for technique in techniques:
                technique_counts[technique] = technique_counts.get(technique, 0) + 1
            
            # Count confidence levels
            if confidence in confidence_counts:
                confidence_counts[confidence] += 1
        
        return {
            'total_advisories': len(advisories),
            'technique_distribution': technique_counts,
            'confidence_distribution': confidence_counts,
            'most_common_techniques': sorted(technique_counts.items(), 
                                           key=lambda x: x[1], reverse=True)[:5]
        }
    
    def search_by_mitre_technique(self, technique_id: str) -> List[Dict[str, Any]]:
        """
        Search advisories by MITRE ATT&CK technique ID
        """
        advisories = self.index_manager.get_advisories_data()
        matching_advisories = []
        
        for advisory in advisories:
            mitre_mapping = advisory.get('mitre_mapping', {})
            techniques = mitre_mapping.get('mapped_techniques', [])
            
            if technique_id in techniques:
                matching_advisories.append({
                    'id': advisory['id'],
                    'title': advisory['title'],
                    'summary': advisory['summary'],
                    'link': advisory['link'],
                    'confidence': mitre_mapping.get('confidence', 'N/A')
                })
        
        return matching_advisories
    
    def get_threat_intelligence_summary(self) -> str:
        """
        Generate a comprehensive threat intelligence summary
        """
        try:
            # Use the prompt template from constants
            return self.query(THREAT_INTELLIGENCE_SUMMARY_PROMPT)
        except Exception as e:
            return f"Error generating threat intelligence summary: {str(e)}"