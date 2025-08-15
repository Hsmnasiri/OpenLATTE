import json
import logging
import numpy as np
import faiss
from sentence_transformers import SentenceTransformer
from pathlib import Path

# Setup basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class RAGVectorDB:
    """
    Manages the creation, loading, and searching of a vector database for RAG.
    This class handles both code and text embeddings using FAISS and SentenceTransformers.
    """
    def __init__(self, db_path='rag_db', model_name='all-MiniLM-L6-v2'):
        """
        Initializes the vector database manager.

        Args:
            db_path (str): The directory to store or load the database files.
            model_name (str): The name of the SentenceTransformer model to use for embeddings.
        """
        self.db_path = Path(db_path)
        self.db_path.mkdir(parents=True, exist_ok=True)
        
        # Paths for different components of the database
        self.code_index_path = self.db_path / "code.index"
        self.text_index_path = self.db_path / "text.index"
        self.metadata_path = self.db_path / "metadata.json"
        
        # Initialize the embedding model
        logging.info(f"Loading sentence-transformer model: {model_name}")
        self.model = SentenceTransformer(model_name)
        
        # Initialize FAISS indexes and metadata storage
        self.code_index = None
        self.text_index = None
        self.metadata = []

    def build_from_kb(self, kb_file_path):
        """
        Builds the entire vector database from a knowledge base file.

        Args:
            kb_file_path (str): Path to the .jsonl knowledge base file.
        """
        logging.info(f"Building vector database from: {kb_file_path}")
        
        code_docs = []
        text_docs = []
        
        with open(kb_file_path, 'r', encoding='utf-8') as f:
            for i, line in enumerate(f):
                entry = json.loads(line)
                
                # Store original data as metadata, with a unique ID
                entry_metadata = {
                    'id': i,
                    'vulnerability': entry.get('vulnerability'),
                    'vulnerability_cause': entry.get('vulnerability_cause'),
                    'fixing_solution': entry.get('fixing_solution')
                }
                self.metadata.append(entry_metadata)

                # Add code and text to their respective lists for embedding
                code_docs.append(entry.get('bad_code', ''))
                code_docs.append(entry.get('good_code', ''))
                text_docs.append(entry.get('functional_semantics', ''))

        # --- Create Code Index ---
        if code_docs:
            logging.info(f"Creating embeddings for {len(code_docs)} code snippets...")
            code_embeddings = self.model.encode(code_docs, convert_to_tensor=False, show_progress_bar=True)
            embedding_dim = code_embeddings.shape[1]
            self.code_index = faiss.IndexFlatL2(embedding_dim)
            self.code_index = faiss.IndexIDMap(self.code_index)
            # We create IDs from 0 to N-1 for the code snippets
            ids = np.arange(len(code_docs)).astype('int64')
            self.code_index.add_with_ids(code_embeddings.astype('float32'), ids)
            logging.info(f"Code index created with {self.code_index.ntotal} vectors.")
        
        # --- Create Text Index ---
        if text_docs:
            logging.info(f"Creating embeddings for {len(text_docs)} semantic descriptions...")
            text_embeddings = self.model.encode(text_docs, convert_to_tensor=False, show_progress_bar=True)
            embedding_dim = text_embeddings.shape[1]
            self.text_index = faiss.IndexFlatL2(embedding_dim)
            self.text_index = faiss.IndexIDMap(self.text_index)
            # IDs for text correspond to the metadata ID
            ids = np.arange(len(text_docs)).astype('int64')
            self.text_index.add_with_ids(text_embeddings.astype('float32'), ids)
            logging.info(f"Text index created with {self.text_index.ntotal} vectors.")

    def save(self):
        """Saves the FAISS indexes and metadata to disk."""
        logging.info(f"Saving database to {self.db_path}...")
        if self.code_index:
            faiss.write_index(self.code_index, str(self.code_index_path))
        if self.text_index:
            faiss.write_index(self.text_index, str(self.text_index_path))
        with open(self.metadata_path, 'w', encoding='utf-8') as f:
            json.dump(self.metadata, f, indent=2)
        logging.info("Database saved successfully.")

    def load(self):
        """Loads the FAISS indexes and metadata from disk."""
        if not self.code_index_path.exists() or not self.text_index_path.exists() or not self.metadata_path.exists():
            logging.error("Database files not found. Please build the database first.")
            return False
            
        logging.info(f"Loading database from {self.db_path}...")
        self.code_index = faiss.read_index(str(self.code_index_path))
        self.text_index = faiss.read_index(str(self.text_index_path))
        with open(self.metadata_path, 'r', encoding='utf-8') as f:
            self.metadata = json.load(f)
        logging.info(f"Database loaded successfully. Found {self.code_index.ntotal} code vectors and {self.text_index.ntotal} text vectors.")
        return True

    def search(self, query_text, k=5, search_type='all'):
        """
        Searches the vector database for similar entries.

        Args:
            query_text (str): The text to search for (can be code or natural language).
            k (int): The number of top results to return.
            search_type (str): 'code', 'text', or 'all'.

        Returns:
            list: A list of tuples, each containing (metadata, score).
        """
        if not self.code_index or not self.text_index:
            logging.error("Indexes are not loaded or built. Cannot perform search.")
            return []

        query_embedding = self.model.encode([query_text]).astype('float32')
        
        results = {}

        # --- Search Code ---
        if search_type in ['code', 'all']:
            distances, ids = self.code_index.search(query_embedding, k)
            for i, doc_id in enumerate(ids[0]):
                if doc_id != -1: # FAISS returns -1 for no result
                    # Map the code ID back to the original metadata entry ID
                    # Since we have 2 code snippets per entry (bad, good), we divide by 2
                    metadata_id = doc_id // 2
                    score = 1 / (1 + distances[0][i]) # Normalize distance to a similarity score
                    if metadata_id not in results or score > results[metadata_id][1]:
                         results[metadata_id] = (self.metadata[metadata_id], score, 'code')

        # --- Search Text ---
        if search_type in ['text', 'all']:
            distances, ids = self.text_index.search(query_embedding, k)
            for i, doc_id in enumerate(ids[0]):
                 if doc_id != -1:
                    metadata_id = doc_id
                    score = 1 / (1 + distances[0][i])
                    if metadata_id not in results or score > results[metadata_id][1]:
                        results[metadata_id] = (self.metadata[metadata_id], score, 'text')
        
        # Convert results dict to a sorted list
        sorted_results = sorted(results.values(), key=lambda x: x[1], reverse=True)
        
        return sorted_results[:k]

