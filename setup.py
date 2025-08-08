from indexmanager import IndexManager
import os
from dotenv import load_dotenv

def main():
    """
    This script performs the one-time setup for the application.
    It fetches the latest CISA advisories, processes them, creates embeddings,
    and upserts the data into the Pinecone vector database.
    """
    load_dotenv()
    
    # Ensure API keys are available in the .env file
    if not os.getenv("OPENAI_API_KEY") or not os.getenv("PINECONE_API_KEY"):
        print("Error: Please set OPENAI_API_KEY and PINECONE_API_KEY in your .env file.")
        return

    print("Starting database setup...")
    print("This process may take a few minutes as it involves fetching data and calling AI models.")

    try:
        # The default index name is "ai-cti".
        index_name = "ai-cti" 
        index_manager = IndexManager(index_name)
        
        print(f"Creating and populating index '{index_name}'...")
        index_manager.create_index()
        
        print("\nDatabase setup complete!")
        print("You can now run the main application using: streamlit run app.py")
    except Exception as e:
        print(f"\nAn error occurred during setup: {e}")
        print("Please check your API keys, Pinecone index name, and internet connection.")

if __name__ == "__main__":
    main()
