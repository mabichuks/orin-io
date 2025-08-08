# AI-Powered ICS Threat Intelligence Platform

This project is an **AI-powered web application** that automatically fetches, analyzes, and visualizes Cyber Threat Intelligence (CTI) for **Industrial Control Systems (ICS)**.  
It leverages a **Large Language Model (LLM)** to generate summaries, map vulnerabilities to the **MITRE ATT&CK for ICS** framework, and power a conversational AI assistant.

---

## Features

- **Automated Data Ingestion**  
  Fetches the latest ICS security advisories from the **CISA RSS feed**.

- **AI-Powered Analysis**

  - Generates concise summaries of complex advisories.
  - Automatically maps vulnerabilities to **MITRE ATT&CK for ICS** techniques using a novel two-stage process.

- **Interactive Dashboard**  
  A user-friendly interface built with **Streamlit** to visualize key metrics, trends, and the latest advisories.

- **AI Security Assistant**  
  A conversational chat interface powered by a **Retrieval-Augmented Generation (RAG)** system that allows users to query the intelligence knowledge base in natural language.

---

## Technology Stack

- **Backend & AI Orchestration:** Python, LlamaIndex
- **Frontend:** Streamlit
- **LLM & Embeddings:** OpenAI GPT-4o, text-embed-3-large
- **Vector Database:** Pinecone
- **Data Processing:** Pandas, NumPy

---

## Getting Started

Follow these instructions to set up and run the application on your local machine.

### Prerequisites

- Python 3.8 or higher
- An **OpenAI API Key**
- A **Pinecone API Key** and a pre-configured Pinecone index (default name: `ai-cti`)

---

### Setup Instructions

#### **Step 1: Install Dependencies**

```
pip install -r requirements.txt
```

#### **Step 2: Set Up Environment Variable in .env file**

```
OPENAI_API_KEY="your_openai_api_key_here"
PINECONE_API_KEY="your_pinecone_api_key_here"
```

#### Step 4: Populate the Vector Database (One-Time Setup)

```
python setup_database.py

```

#### Step 5: Run the Application

```
streamlit run app.py
```
