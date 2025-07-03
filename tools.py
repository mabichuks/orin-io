import feedparser
import requests
import json
from datetime import datetime
from typing import List, Dict, Any
from llama_index.core.tools import FunctionTool
from tiktoken import get_encoding
import numpy as np
from bs4 import BeautifulSoup

from constants import (
    CISA_ICS_RSS_URL, 
    MAX_ADVISORIES, 
    REFINED_MITRE_PROMPT_TEMPLATE, 
    embed_model, 
    llm_model
)

def create_mitre_embeddings(embed_model):
    """
    Create embeddings for all MITRE ATT&CK techniques
    """
    mitre_embeddings = {}
    with open("assets/mitre-ics.json", "r", encoding="utf-8") as f:
        mitre_data = json.load(f)

    for item in mitre_data:
        # Create searchable text combining name and description
        technique_text = f"{item['name']} {item['description']} {item['tactics']}"
        technique_id = item['Id']
        # Generate embedding
        embedding = embed_model.get_text_embedding(technique_text)
        mitre_embeddings[technique_id] = {
            'embedding': embedding,
            'text': technique_text,
            'details': item
        }
    print(f"Generated embedding for {technique_id} Embedding: {embedding[:5]}...")  
    
    return mitre_embeddings

def get_mean_embedding(text: str, chunk_size: int = 1000):
    encoding = get_encoding("cl100k_base")
    tokens = encoding.encode(text)

    chunks = [tokens[i:i + chunk_size] for i in range(0, len(tokens), chunk_size)]
    embeddings = []

    for chunk in chunks:
        chunk_text = encoding.decode(chunk)
        embedding_obj = embed_model.get_text_embedding(chunk_text)
        
        # Convert Embedding object to list of floats
        if hasattr(embedding_obj, 'embedding'):
            emb_list = embedding_obj.embedding
        else:
            emb_list = embedding_obj  # In case it's already a list

        embeddings.append(np.array(emb_list))

    # Average the vectors
    return np.mean(embeddings, axis=0)


def find_similar_mitre_techniques(advisory_content: str, mitre_embeddings: Dict, top_k: int = 5):
    """
    Find top-k most similar MITRE ATT&CK techniques using embedding similarity
    """    
    # Get averaged embedding for potentially long advisory content
    advisory_embedding = get_mean_embedding(advisory_content)
    advisory_emb = np.array(advisory_embedding)

    similarities = []

    for technique_id, data in mitre_embeddings.items():
        mitre_emb = np.array(data['embedding'])

        # Cosine similarity with safeguard against divide-by-zero
        cosine_sim = np.dot(mitre_emb, advisory_emb) / (
            np.linalg.norm(mitre_emb) * np.linalg.norm(advisory_emb) + 1e-8
        )

        similarities.append({
            'technique_id': technique_id,
            'similarity': float(cosine_sim),
            'details': data['details']
        })

    similarities.sort(key=lambda x: x['similarity'], reverse=True)
    return similarities[:top_k]


def map_to_mitre_attack(advisory_content: str, mitre_embeddings=None) -> Dict[str, Any]:
    """
    Enhanced MITRE ATT&CK mapping using two-stage approach:
    1. Embedding-based similarity filtering
    2. LLM-based refined analysis
    """
    try:
        # Stage 1: Use embeddings to find top candidate techniques (if available)
        candidate_techniques = None
        if mitre_embeddings:
            print("Stage 1: Finding similar MITRE techniques using embeddings...")
            candidates = find_similar_mitre_techniques(
                advisory_content, mitre_embeddings, top_k=5
            )
            
            # Prepare candidate techniques for LLM analysis
            candidate_techniques = {
                cand['technique_id']: cand['details'] 
                for cand in candidates
            }
            
            print(f"Top candidates: {list(candidate_techniques.keys())}")
        
        # Stage 2: Use LLM for refined mapping on filtered candidates
        print("Stage 2: LLM-based refined analysis...")

        with open("assets/mitre-ics.json", "r", encoding="utf-8") as f:
            mitre_data = json.load(f)
        
        # Use candidate techniques if available, otherwise full set
        techniques_to_analyze = candidate_techniques if candidate_techniques else mitre_data
        
        # Enhanced prompt for refined analysis using constant
        refined_prompt = REFINED_MITRE_PROMPT_TEMPLATE.format(
            advisory_content=advisory_content,
            techniques_to_analyze=json.dumps(techniques_to_analyze, indent=2)
        )
        print(f"Refined prompt: {refined_prompt}...")
        response = llm_model.complete(refined_prompt)
        print(f"LLM response: {response.text}...")

        mapping = json.loads(response.text)
        print(f"Final mapping: {mapping}...")
        return mapping
        
    except Exception as e:
        print(f"Error in map_to_mitre_attack: {e}")


def extract_vulnerability_overview(html_content: str) -> str:
    """
    Extract the vulnerability overview section using Beautiful Soup
    """
    soup = BeautifulSoup(html_content, 'html.parser')
    
    # Look for the vulnerability overview heading
    vuln_heading = soup.find('h3', string=lambda text: text and 'vulnerability overview' in text.lower())
    
    if vuln_heading:
        # Get all content between this heading and the next h3
        content_parts = []
        for sibling in vuln_heading.next_siblings:
            if sibling.name == 'h3':
                break
            if hasattr(sibling, 'get_text'):
                content_parts.append(sibling.get_text(strip=True))
            elif isinstance(sibling, str):
                content_parts.append(sibling.strip())
        
        vulnerability_text = ' '.join(content_parts).strip()
        if vulnerability_text:
            return vulnerability_text
    
    return "Vulnerability overview not found"

def fetch_cisa_advisories() -> List[Dict[str, Any]]:
    """
    Fetch ICS security advisories from CISA RSS feed
    """
    try:
        # Parse RSS feed
        feed = feedparser.parse(CISA_ICS_RSS_URL)
        
        advisories = []
        for i, entry in enumerate(feed.entries[:MAX_ADVISORIES]):
            content = entry.get('summary', '') + ' ' + entry.get('title', '')
            vulnerability_overview = extract_vulnerability_overview(content)
            advisory = {
                'id': entry.get('id', f'advisory_{i}'),
                'title': entry.get('title', 'No Title'),
                'summary': entry.get('summary', 'No Summary'),
                'link': entry.get('link', ''),
                'published': entry.get('published', str(datetime.now())),
                'content': entry.get('summary', '') + ' ' + entry.get('title', ''),
                'vulnerability_overview': vulnerability_overview
                
            }
            advisories.append(advisory)
            print(f"Fetched advisory {i+1}: {advisory['title']}")
            print(f"Vulnerability Overview {advisory['vulnerability_overview']}")
            
        return advisories
        
    except Exception as e:
        print(f"Error fetching CISA advisories: {e}")


def create_advisory_fetch_tool():
    """Create function tool for fetching advisories"""
    return FunctionTool.from_defaults(
        fn=fetch_cisa_advisories,
        name="fetch_cisa_advisories",
        description="Fetch the latest ICS security advisories from CISA RSS feed"
    )


def create_mitre_mapping_tool():
    """Create function tool for MITRE ATT&CK mapping"""
    def mitre_mapping_wrapper(content: str, llm_client=None):
        return map_to_mitre_attack(content, llm_client)
    
    return FunctionTool.from_defaults(
        fn=mitre_mapping_wrapper,
        name="map_to_mitre_attack",
        description="Map advisory content to MITRE ATT&CK techniques"
    )