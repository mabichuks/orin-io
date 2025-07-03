UI_STYLE = """
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
        height: 100%;
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
        margin-top: 1rem;
    }
    .metric-card {
        background-color: #f8f9fa;
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #2e7bb8;
        margin: 0.5rem 0;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 2rem;
    }
    .stTabs [data-baseweb="tab"] {
        padding: 1rem 2rem;
        font-size: 1.1rem;
    }
</style>
"""