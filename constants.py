import os

from dotenv import load_dotenv
from llama_index.embeddings.openai import OpenAIEmbedding, OpenAIEmbeddingModelType
from llama_index.llms.openai import OpenAI

load_dotenv()

openai_api_key = os.getenv("OPENAI_API_KEY")
embed_model = OpenAIEmbedding(openai_api_key=openai_api_key,
                               model=OpenAIEmbeddingModelType.TEXT_EMBED_3_LARGE)
llm_model = OpenAI(api_key=openai_api_key,
                   model="gpt-4o",)

CISA_ICS_RSS_URL = "https://us-cert.cisa.gov/ics/advisories/advisories.xml"


VECTOR_STORE_PATH = "vector_store/"
INDEX_PERSIST_PATH = "index/"

# MITRE ATT&CK mapping prompt template
MITRE_MAPPING_PROMPT = """
Given the following ICS security advisory, identify and map it to relevant MITRE ATT&CK techniques.
Consider the vulnerabilities, attack vectors, and potential impacts described.

Advisory Content: {advisory_content}

Available MITRE ATT&CK Techniques (JSON format):
{mitre_techniques}

Please respond with a JSON object containing:
- "mapped_techniques": list of technique IDs that apply
- "reasoning": brief explanation for each mapping
- "confidence": confidence level (high/medium/low) for each mapping

Format your response as valid JSON.
"""



# Number of advisories to process
MAX_ADVISORIES = 10

