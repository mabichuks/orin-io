from typing import List, Dict, Any
from llama_index.core.agent import ReActAgent
from llama_index.core.tools import QueryEngineTool, ToolMetadata
from tools import create_advisory_fetch_tool, create_mitre_mapping_tool
from indexmanager import IndexManager
from constants import llm_model

class ThreatIntelligenceAgent:
    def __init__(self):
        """Initialize the Threat Intelligence Agent"""
        self.llm = llm_model
        self.index_manager = IndexManager()
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
            query_engine_tool,
            advisory_fetch_tool,
            mitre_mapping_tool
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
        query_engine = self.index_manager.get_query_engine()
        
        return QueryEngineTool(
            query_engine=query_engine,
            metadata=ToolMetadata(
                name="advisory_search",
                description="Search and query ICS security advisories from CISA. "
                           "Use this to find information about specific vulnerabilities, "
                           "security issues, MITRE ATT&CK mappings, or threat intelligence."
            )
        )
    
    def query(self, question: str) -> str:
        """
        Query the agent with a question
        """
        try:
            response = self.agent.chat(question)
            return str(response)
        except Exception as e:
            return f"Error processing query: {str(e)}"
    
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
                'summary': advisory['summary'][:200] + '...' if len(advisory['summary']) > 200 else advisory['summary'],
                'published': advisory['published'],
                'link': advisory['link'],
                'mitre_techniques': advisory.get('mitre_mapping', {}).get('mapped_techniques', []),
                'confidence': advisory.get('mitre_mapping', {}).get('confidence', 'N/A')
            }
            summary_advisories.append(summary)
        
        return summary_advisories
    
    def refresh_knowledge_base(self, force_rebuild=False):
        """
        Refresh the knowledge base with latest advisories
        """
        result = self.index_manager.refresh_index(force_rebuild=force_rebuild)
        self.setup_agent()  # Recreate agent with updated index
        
        if force_rebuild:
            return "Knowledge base completely rebuilt successfully!"
        else:
            return "Knowledge base updated with latest advisories!"
    
    def check_for_updates(self):
        """
        Check if there are new advisories available
        """
        return self.index_manager.check_for_updates()
    
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
            summary_query = """
            Provide a comprehensive threat intelligence summary based on the latest ICS security advisories.
            Include:
            1. Overview of current threat landscape
            2. Most critical vulnerabilities
            3. Common attack patterns (MITRE ATT&CK techniques)
            4. Recommended security measures
            5. Key affected systems/vendors
            
            Format the response in a structured manner.
            """
            
            return self.query(summary_query)
        except Exception as e:
            return f"Error generating threat intelligence summary: {str(e)}"