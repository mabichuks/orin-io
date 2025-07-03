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

# Number of advisories to process
MAX_ADVISORIES = 60


# Enhanced MITRE ATT&CK mapping prompt template
REFINED_MITRE_PROMPT_TEMPLATE = """
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

Only respond with a valid JSON object in this exact format and nothig else
{{
  "type": "object",
  "properties": {{
    "mapped_techniques": {{
      "type": "array",
      "description": "List of MITRE ATT&CK technique IDs that apply the MOST to the advisory. This could be zero, one or more techniques but should not exceed three.",
      "maxItems": 3,
      "items": {{
        "type": "string",
        "description": "MITRE ATT&CK technique ID, e.g., T1234"
      }}
    }}
  }}
}}

do not include any addtional text in your response such as markdown like ```json, only the JSON object as described above.
"""



# Advisory summary generation prompt template
ADVISORY_SUMMARY_PROMPT_TEMPLATE = """
Provide a concise 2-3 sentence summary of this ICS security advisory. Focus on:
- What the vulnerability is
- The risk
- Affected systems or products
- Summary of the vulnerabilities, including a CVE Id if available, the CVSS score, and the CVSS vector
- CVE Id should be in a html link format like <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-12345">CVE-2023-12345</a>
- The potential impact
- The mitigations

Advisory content:
{advisory_content}

Provide only the summary, no additional text:
"""

# Threat intelligence summary prompt template
THREAT_INTELLIGENCE_SUMMARY_PROMPT = """
Provide a comprehensive threat intelligence summary based on the latest ICS security advisories.
Include:
1. Overview of current threat landscape
2. Most critical vulnerabilities
3. Common attack patterns (MITRE ATT&CK techniques)
4. Recommended security measures
5. Key affected systems/vendors

Format the response in a structured manner.
"""


ENHANCED_RAG_TEMPLATE = """You are a cybersecurity expert specializing in Industrial Control Systems (ICS) and SCADA security. 

Context Information: {context_str}
Query: {query_str}

Instructions:
- Answer based ONLY on the provided context information
- Include relevant MITRE ATT&CK techniques when available
- Cite specific advisory IDs (e.g., ICSA-24-XXX-XX) when referencing vulnerabilities
- Provide actionable security recommendations when possible

Please structure your response with:
- **Summary**: Key findings from the advisories
- **Technical Details**: Vulnerabilities, affected systems, attack vectors
- **MITRE Mapping**: Relevant ATT&CK techniques (if applicable)
- **Recommendations**: Specific mitigation steps
- **References**: Advisory IDs and additional resources
"""