import os
import json
from typing import List, Dict, Any
from llama_index.core import VectorStoreIndex, Document, StorageContext, load_index_from_storage
from llama_index.core import Settings
from llama_index.core.prompts import PromptTemplate
from tools import fetch_cisa_advisories, map_to_mitre_attack, create_mitre_embeddings
from constants import embed_model, llm_model, INDEX_PERSIST_PATH, ENHANCED_RAG_TEMPLATE

class IndexManager:
    def __init__(self):
        """Initialize the IndexManager with OpenAI models"""
        # Set up LlamaIndex settings
        Settings.llm = llm_model
        Settings.embed_model = embed_model
        
        self.llm = Settings.llm
        self.embed_model = Settings.embed_model
        self.index = None
        self.advisories_data = []
        
        # Load MITRE techniques from JSON file
        print("Loading MITRE ATT&CK techniques from file...")
        with open("assets/mitre-ics.json", "r", encoding="utf-8") as f:
            mitre_data = json.load(f)
        self.mitre_techniques = mitre_data
        
        # Initialize MITRE embeddings for enhanced mapping
        print("Initializing MITRE ATT&CK embeddings...")
        self.mitre_embeddings = create_mitre_embeddings(self.embed_model)
        print(f"Created embeddings for {len(self.mitre_embeddings)} MITRE techniques")
    
    def create_index(self) -> VectorStoreIndex:
        """
        Create a new vector store index with CISA advisories
        """
        print("Fetching CISA advisories...")
        advisories = fetch_cisa_advisories()
        
        print("Processing advisories and mapping to MITRE ATT&CK...")
        documents = []
        processed_advisories = []
        
        for advisory in advisories:
            # Map to MITRE ATT&CK techniques using enhanced two-stage approach
            mitre_mapping = map_to_mitre_attack(
                advisory['content'], 
                self.mitre_embeddings,
            )
            
            # Create enhanced content with MITRE mapping
            enhanced_content = f"""
            Title: {advisory['title']}
            Summary: {advisory['summary']}
            Published: {advisory['published']}
            Link: {advisory['link']}
            
            MITRE ATT&CK Mapping:
            Techniques: {', '.join(mitre_mapping.get('mapped_techniques', []))}
            Reasoning: {mitre_mapping.get('reasoning', 'N/A')}
            Confidence: {mitre_mapping.get('confidence', 'N/A')}
            
            Full Content: {advisory['content']}
            """
            
            # Create document with metadata
            doc = Document(
                text=enhanced_content,
                metadata={
                    'id': advisory['id'],
                    'title': advisory['title'],
                    'published': advisory['published'],
                    'link': advisory['link'],
                    'mitre_techniques': mitre_mapping.get('mapped_techniques', []),
                    'confidence': mitre_mapping.get('confidence', 'N/A')
                }
            )
            
            documents.append(doc)
            
            # Store processed advisory data
            advisory_data = advisory.copy()
            advisory_data['mitre_mapping'] = mitre_mapping
            processed_advisories.append(advisory_data)
        
        print("Creating vector store index...")
        self.index = VectorStoreIndex.from_documents(documents)
        self.advisories_data = processed_advisories
        
        # Persist the index
        self.persist_index()
        
    def check_for_updates(self) -> Dict[str, Any]:
        """
        Check if there are new advisories without processing them
        """
        try:
            # Get current advisories from RSS
            new_advisories = fetch_cisa_advisories()
            
            # Load existing processed data
            existing_advisories = self.get_advisories_data()
            existing_ids = {adv['id'] for adv in existing_advisories}
            
            # Find new advisories
            new_advisories_available = [
                adv for adv in new_advisories 
                if adv['id'] not in existing_ids
            ]
            
            return {
                'has_updates': len(new_advisories_available) > 0,
                'new_count': len(new_advisories_available),
                'total_current': len(existing_advisories),
                'new_advisories': new_advisories_available[:3] if new_advisories_available else []  # Preview of first 3
            }
            
        except Exception as e:
            return {
                'has_updates': False,
                'error': str(e),
                'new_count': 0,
                'total_current': len(self.get_advisories_data())
            }
    
    def get_cache_info(self) -> Dict[str, Any]:
        """
        Get information about the current cache/index state
        """
        try:
            advisories = self.get_advisories_data()
            
            if not advisories:
                return {'status': 'empty', 'count': 0}
            
            # Get latest advisory date
            latest_date = max(adv.get('published', '') for adv in advisories)
            
            return {
                'status': 'loaded',
                'count': len(advisories),
                'latest_advisory_date': latest_date[:10] if latest_date else 'Unknown',
                'index_exists': self.index is not None,
                'storage_path': INDEX_PERSIST_PATH
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e),
                'count': 0
            }
    
    def load_existing_index(self) -> VectorStoreIndex:
        """
        Load existing vector store index from storage
        """
        try:
            if os.path.exists(INDEX_PERSIST_PATH):
                print("Loading existing index...")
                storage_context = StorageContext.from_defaults(persist_dir=INDEX_PERSIST_PATH)
                self.index = load_index_from_storage(storage_context)
                
                # Load advisory data if available
                metadata_path = os.path.join(INDEX_PERSIST_PATH, "advisories_metadata.json")
                if os.path.exists(metadata_path):
                    with open(metadata_path, 'r') as f:
                        self.advisories_data = json.load(f)
                
                return self.index
            else:
                print("No existing index found. Creating new index...")
                return self.create_index()
        except Exception as e:
            print(f"Error loading index: {e}")
            print("Creating new index...")
            return self.create_index()
    
    def persist_index(self):
        """
        Persist the index to storage
        """
        if self.index:
            print("Persisting index to storage...")
            self.index.storage_context.persist(persist_dir=INDEX_PERSIST_PATH)
            
            # Save advisory metadata
            metadata_path = os.path.join(INDEX_PERSIST_PATH, "advisories_metadata.json")
            os.makedirs(INDEX_PERSIST_PATH, exist_ok=True)
            with open(metadata_path, 'w') as f:
                json.dump(self.advisories_data, f, indent=2)
    
    def get_index(self) -> VectorStoreIndex:
        """
        Get the vector store index (load if not already loaded)
        """
        if self.index is None:
            self.index = self.load_existing_index()
        return self.index
    
    def get_query_engine(self):
        """
        Get a query engine for the index with enhanced RAG template
        """
        index = self.get_index()
        
        # Create enhanced prompt template
        qa_prompt = PromptTemplate(ENHANCED_RAG_TEMPLATE)
        print(f"Using enhanced RAG template for query engine: {qa_prompt.template}...")  # Preview first 100 chars
        
        return index.as_query_engine(
            similarity_top_k=5,
            llm=self.llm,
            text_qa_template=qa_prompt,
            response_mode="compact"
        )
    
    def get_advisories_data(self) -> List[Dict[str, Any]]:
        """
        Get the processed advisories data
        """
        if not self.advisories_data:
            # Try to load from file
            metadata_path = os.path.join(INDEX_PERSIST_PATH, "advisories_metadata.json")
            if os.path.exists(metadata_path):
                with open(metadata_path, 'r') as f:
                    self.advisories_data = json.load(f)
            else:
                # Create new index if no data available
                self.create_index()
        
        return self.advisories_data
    
    def refresh_index(self, force_rebuild=False):
        """
        Refresh the index with new data (incremental update)
        """
        if force_rebuild:
            print("Force rebuilding entire index...")
            self.index = None
            self.advisories_data = []
            return self.create_index()
        
        print("Checking for new advisories...")
        
        # Get current advisories from RSS
        new_advisories = fetch_cisa_advisories()
        
        # Load existing processed data
        existing_advisories = self.get_advisories_data()
        existing_ids = {adv['id'] for adv in existing_advisories}
        
        # Find truly new advisories
        new_advisories_to_process = [
            adv for adv in new_advisories 
            if adv['id'] not in existing_ids
        ]
        
        if not new_advisories_to_process:
            print("No new advisories found. Index is up to date.")
            return self.get_index()
        
        print(f"Found {len(new_advisories_to_process)} new advisories to process...")
        
        # Process only new advisories
        new_documents = []
        new_processed_advisories = []
        
        for advisory in new_advisories_to_process:
            print(f"Processing new advisory: {advisory['id']}")
            
            # Map to MITRE ATT&CK techniques using enhanced two-stage approach
            mitre_mapping = map_to_mitre_attack(
                advisory['content'], 
                self.mitre_embeddings,
            )
            
            # Create enhanced content with MITRE mapping
            enhanced_content = f"""
            Title: {advisory['title']}
            Summary: {advisory['summary']}
            Published: {advisory['published']}
            Link: {advisory['link']}
            
            MITRE ATT&CK Mapping:
            Techniques: {', '.join(mitre_mapping.get('mapped_techniques', []))}
            Reasoning: {mitre_mapping.get('reasoning', 'N/A')}
            Confidence: {mitre_mapping.get('confidence', 'N/A')}
            
            Full Content: {advisory['content']}
            """
            
            # Create document with metadata
            doc = Document(
                text=enhanced_content,
                metadata={
                    'id': advisory['id'],
                    'title': advisory['title'],
                    'published': advisory['published'],
                    'link': advisory['link'],
                    'mitre_techniques': mitre_mapping.get('mapped_techniques', []),
                    'confidence': mitre_mapping.get('confidence', 'N/A')
                }
            )
            
            new_documents.append(doc)
            
            # Store processed advisory data
            advisory_data = advisory.copy()
            advisory_data['mitre_mapping'] = mitre_mapping
            new_processed_advisories.append(advisory_data)
        
        # Get existing index or create if doesn't exist
        if self.index is None:
            self.index = self.load_existing_index()
        
        # Add new documents to existing index
        print("Adding new documents to existing index...")
        for doc in new_documents:
            self.index.insert(doc)
        
        # Update advisories data
        self.advisories_data = existing_advisories + new_processed_advisories
        
        # Persist updated index and metadata
        self.persist_index()
        
        print(f"Successfully added {len(new_documents)} new advisories to index.")
        return self.index
    
    def search_advisories(self, query: str, top_k: int = 5):
        """
        Search advisories using the query engine
        """
        query_engine = self.get_query_engine()
        response = query_engine.query(query)
        return response