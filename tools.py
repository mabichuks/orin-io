import feedparser
import requests
import json
from datetime import datetime
from typing import List, Dict, Any
from llama_index.core.tools import FunctionTool
from constants import CISA_ICS_RSS_URL, MAX_ADVISORIES, MITRE_MAPPING_PROMPT, embed_model, llm_model

REFINED_PROMPT_TEMPLATE = """
You are a cybersecurity expert analyzing an ICS (Industrial Control Systems) security advisory.
Your task is to map this advisory to the most relevant MITRE ATT&CK techniques.

IMPORTANT: You have been provided with pre-filtered candidate techniques that are most likely relevant.
Focus your analysis on these candidates, but you may also suggest if none are truly appropriate.

Advisory Content:
{advisory_content}

Candidate MITRE ATT&CK Techniques (pre-filtered for relevance):
{techniques_to_analyze}

Instructions:
1. Analyze the advisory for attack vectors, vulnerabilities, and potential impacts
2. Map to 1-3 most relevant techniques from the candidates provided
3. Provide confidence level (high/medium/low) based on how well the technique matches
4. Give brief reasoning for each mapping

Respond with a valid JSON object in this exact format:
{{
    "mapped_techniques": ["T0XXX", "T0YYY"],
    "reasoning": {{
        "T0XXX": "Brief explanation why this technique applies",
        "T0YYY": "Brief explanation why this technique applies"
    }},
    "confidence": "high|medium|low",
    "similarity_scores": {{"T0XXX": 0.85, "T0YYY": 0.72}}
}}
Return only valid JSON. Do not include ```json or any markdown formatting. No explanation. Just output raw JSON.
"""

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


def find_similar_mitre_techniques(advisory_content: str, mitre_embeddings: Dict, top_k: int = 5):
    """
    Find top-k most similar MITRE ATT&CK techniques using embedding similarity
    """
    import numpy as np
    from typing import List, Tuple
    
    # Generate embedding for advisory content
    advisory_embedding = embed_model.get_text_embedding(advisory_content)
    
    # Calculate cosine similarity with all MITRE techniques
    similarities = []
    
    for technique_id, data in mitre_embeddings.items():
        mitre_emb = np.array(data['embedding'])
        advisory_emb = np.array(advisory_embedding)
        
        # Cosine similarity
        cosine_sim = np.dot(mitre_emb, advisory_emb) / (
            np.linalg.norm(mitre_emb) * np.linalg.norm(advisory_emb)
        )
        
        similarities.append({
            'technique_id': technique_id,
            'similarity': float(cosine_sim),
            'details': data['details']
        })
    
    # Sort by similarity and return top-k
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
        
        # Enhanced prompt for refined analysis
        refined_prompt = REFINED_PROMPT_TEMPLATE.format(
            advisory_content=advisory_content,
            techniques_to_analyze=json.dumps(techniques_to_analyze, indent=2)
        )
        print(f"Refined prompt: {refined_prompt}...")
        response = llm_model.complete(refined_prompt)
        print(f"LLM response: {response.text}...")

        mapping = json.loads(response.text)
        print(f"Final mapping: {mapping}...")
        return mapping
        # Try to parse JSON response
        # try:
        #     mapping = json.loads(response.text)
            
            # Validate the response structure
            # if not isinstance(mapping.get('mapped_techniques'), list):
            #     raise ValueError("Invalid mapped_techniques format")
            
            # Add embedding similarity scores if available
            # if candidate_techniques:
            #     candidates_list = find_similar_mitre_techniques(
            #         advisory_content, embed_model, mitre_embeddings, top_k=5
            #     )
            #     similarity_scores = {
            #         cand['technique_id']: round(cand['similarity'], 3)
            #         for cand in candidates_list
            #     }
            #     mapping['embedding_similarities'] = similarity_scores
        #     print(f"Final mapping: {mapping}...")
        #     return mapping
        # except Exception as e:
        #     print(f"Error parsing LLM response: {e}")
    except Exception as e:
        print(f"Error in map_to_mitre_attack: {e}")


def fetch_cisa_advisories() -> List[Dict[str, Any]]:
    """
    Fetch ICS security advisories from CISA RSS feed
    """
    try:
        # Parse RSS feed
        feed = feedparser.parse(CISA_ICS_RSS_URL)
        
        advisories = []
        for i, entry in enumerate(feed.entries[:MAX_ADVISORIES]):
            advisory = {
                'id': entry.get('id', f'advisory_{i}'),
                'title': entry.get('title', 'No Title'),
                'summary': entry.get('summary', 'No Summary'),
                'link': entry.get('link', ''),
                'published': entry.get('published', str(datetime.now())),
                'content': entry.get('summary', '') + ' ' + entry.get('title', '')
            }
            advisories.append(advisory)
            print(f"Fetched advisory {i+1}: {advisory['title']}")
            
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