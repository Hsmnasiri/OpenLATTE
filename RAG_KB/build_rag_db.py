import argparse
from rag_vector_db import RAGVectorDB

def main():
    """
    Command-line script to build and save the RAG vector database.
    It reads a knowledge base file and creates FAISS indexes and metadata files.
    """
    parser = argparse.ArgumentParser(description="Build and save the RAG vector database.")
    parser.add_argument(
        '--kb-file', 
        type=str, 
        required=True, 
        help="Path to the knowledge base .jsonl file (e.g., final_knowledge_base.jsonl)."
    )
    parser.add_argument(
        '--db-path', 
        type=str, 
        default='rag_db', 
        help="Directory to save the database files."
    )
    args = parser.parse_args()

    # Initialize the database manager
    vector_db = RAGVectorDB(db_path=args.db_path)
    
    # Build the database from the knowledge base file
    vector_db.build_from_kb(args.kb_file)
    
    # Save the indexes and metadata to disk
    vector_db.save()

if __name__ == "__main__":
    main()
