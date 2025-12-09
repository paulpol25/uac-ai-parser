"""
Vector Store for RAG-based retrieval.

Provides embedding storage and semantic search over UAC artifacts
using ChromaDB for local persistence.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class VectorStore:
    """
    Vector store for semantic search over forensic artifacts.
    
    Uses ChromaDB for local vector storage with sentence-transformers
    for embedding generation.
    
    Example:
        ```python
        store = VectorStore(persist_dir="./chroma_db")
        
        # Add documents
        store.add_documents(chunks)
        
        # Search
        results = store.search("suspicious SSH activity", top_k=5)
        for doc, score in results:
            print(f"{score:.3f}: {doc[:100]}...")
        ```
    """
    
    def __init__(
        self,
        persist_dir: str | Path | None = None,
        collection_name: str = "uac_artifacts",
        embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2",
    ):
        """
        Initialize vector store.
        
        Args:
            persist_dir: Directory for persistent storage (memory if None)
            collection_name: Name for the ChromaDB collection
            embedding_model: Sentence transformer model for embeddings
        """
        self.persist_dir = Path(persist_dir) if persist_dir else None
        self.collection_name = collection_name
        self.embedding_model_name = embedding_model
        
        self._chroma_client = None
        self._collection = None
        self._embedding_function = None
        
        self._initialize()
    
    def _initialize(self) -> None:
        """Initialize ChromaDB and embedding function."""
        try:
            import chromadb
            from chromadb.config import Settings
            
            # Initialize ChromaDB
            if self.persist_dir:
                self.persist_dir.mkdir(parents=True, exist_ok=True)
                self._chroma_client = chromadb.PersistentClient(
                    path=str(self.persist_dir),
                    settings=Settings(anonymized_telemetry=False),
                )
            else:
                self._chroma_client = chromadb.Client(
                    settings=Settings(anonymized_telemetry=False),
                )
            
            # Initialize embedding function
            self._embedding_function = self._create_embedding_function()
            
            # Get or create collection
            self._collection = self._chroma_client.get_or_create_collection(
                name=self.collection_name,
                embedding_function=self._embedding_function,
                metadata={"description": "UAC forensic artifacts for RAG"},
            )
            
            logger.info(
                f"Initialized vector store: {self.collection_name} "
                f"({self._collection.count()} documents)"
            )
            
        except ImportError as e:
            logger.error(f"Failed to import required packages: {e}")
            raise ImportError(
                "ChromaDB is required. Install with: pip install chromadb sentence-transformers"
            )
    
    def _create_embedding_function(self):
        """Create embedding function using sentence-transformers."""
        try:
            from chromadb.utils import embedding_functions
            
            return embedding_functions.SentenceTransformerEmbeddingFunction(
                model_name=self.embedding_model_name,
            )
        except Exception as e:
            logger.warning(f"Failed to load embedding model: {e}. Using default.")
            from chromadb.utils import embedding_functions
            return embedding_functions.DefaultEmbeddingFunction()
    
    def add_documents(
        self,
        documents: list[Any],  # DocumentChunk from preprocessor
        batch_size: int = 100,
    ) -> int:
        """
        Add documents to the vector store.
        
        Args:
            documents: List of DocumentChunk objects
            batch_size: Number of documents to add per batch
            
        Returns:
            Number of documents added
        """
        if not documents:
            return 0
        
        total_added = 0
        
        for i in range(0, len(documents), batch_size):
            batch = documents[i:i + batch_size]
            
            ids = []
            contents = []
            metadatas = []
            
            for doc in batch:
                # Use chunk_id or generate one
                doc_id = getattr(doc, "chunk_id", None)
                if not doc_id:
                    doc_id = hashlib.md5(doc.content[:100].encode()).hexdigest()
                
                ids.append(doc_id)
                contents.append(doc.content)
                
                # Prepare metadata (ChromaDB has restrictions on types)
                metadata = {
                    "source": getattr(doc, "source", "unknown"),
                    "source_type": getattr(doc, "source_type", "unknown"),
                    "artifact_type": getattr(doc, "artifact_type", "unknown"),
                }
                
                # Add relevance tags as comma-separated string
                if hasattr(doc, "relevance_tags") and doc.relevance_tags:
                    metadata["tags"] = ",".join(doc.relevance_tags)
                
                # Add timestamp if available
                if hasattr(doc, "timestamp") and doc.timestamp:
                    metadata["timestamp"] = doc.timestamp.isoformat()
                
                metadatas.append(metadata)
            
            try:
                self._collection.add(
                    ids=ids,
                    documents=contents,
                    metadatas=metadatas,
                )
                total_added += len(batch)
                
            except Exception as e:
                logger.warning(f"Failed to add batch: {e}")
        
        logger.info(f"Added {total_added} documents to vector store")
        return total_added
    
    def search(
        self,
        query: str,
        top_k: int = 5,
        filter_metadata: dict[str, Any] | None = None,
        include_distances: bool = True,
    ) -> list[tuple[str, dict[str, Any], float]]:
        """
        Search for relevant documents.
        
        Args:
            query: Search query
            top_k: Number of results to return
            filter_metadata: Optional metadata filters
            include_distances: Whether to include similarity scores
            
        Returns:
            List of (document, metadata, score) tuples
        """
        results = self._collection.query(
            query_texts=[query],
            n_results=top_k,
            where=filter_metadata,
            include=["documents", "metadatas", "distances"],
        )
        
        output = []
        
        documents = results.get("documents", [[]])[0]
        metadatas = results.get("metadatas", [[]])[0]
        distances = results.get("distances", [[]])[0]
        
        for i, doc in enumerate(documents):
            metadata = metadatas[i] if i < len(metadatas) else {}
            distance = distances[i] if i < len(distances) else 1.0
            
            # Convert distance to similarity score (1 - distance for L2)
            score = max(0, 1 - distance)
            
            output.append((doc, metadata, score))
        
        return output
    
    def search_by_tag(
        self,
        tags: list[str],
        top_k: int = 10,
    ) -> list[tuple[str, dict[str, Any], float]]:
        """
        Search for documents containing specific tags.
        
        Args:
            tags: List of tags to search for
            top_k: Number of results to return
            
        Returns:
            List of (document, metadata, score) tuples
        """
        # Search using tag as query and filter
        query = " ".join(tags)
        
        # ChromaDB where filter for tags
        tag_filter = None
        if tags:
            # Use $contains for tag matching
            tag_filter = {
                "tags": {"$contains": tags[0]}
            }
        
        return self.search(query, top_k=top_k, filter_metadata=tag_filter)
    
    def search_by_artifact_type(
        self,
        artifact_type: str,
        query: str,
        top_k: int = 5,
    ) -> list[tuple[str, dict[str, Any], float]]:
        """
        Search within a specific artifact type.
        
        Args:
            artifact_type: Type of artifact (process, network, bodyfile, etc.)
            query: Search query
            top_k: Number of results
            
        Returns:
            List of (document, metadata, score) tuples
        """
        return self.search(
            query,
            top_k=top_k,
            filter_metadata={"artifact_type": artifact_type},
        )
    
    def get_context_for_query(
        self,
        query: str,
        max_tokens: int = 4000,
        top_k: int = 10,
    ) -> str:
        """
        Get relevant context for an LLM query.
        
        Args:
            query: User query
            max_tokens: Approximate max tokens for context
            top_k: Number of chunks to consider
            
        Returns:
            Combined context string
        """
        results = self.search(query, top_k=top_k)
        
        context_parts = []
        estimated_tokens = 0
        
        for doc, metadata, score in results:
            # Rough token estimation (4 chars per token)
            doc_tokens = len(doc) // 4
            
            if estimated_tokens + doc_tokens > max_tokens:
                break
            
            # Format with source info
            source = metadata.get("source", "unknown")
            artifact_type = metadata.get("artifact_type", "unknown")
            
            context_parts.append(
                f"--- Source: {source} ({artifact_type}) [relevance: {score:.2f}] ---\n{doc}\n"
            )
            
            estimated_tokens += doc_tokens
        
        return "\n".join(context_parts)
    
    def count(self) -> int:
        """Get number of documents in the store."""
        return self._collection.count()
    
    def clear(self) -> None:
        """Clear all documents from the collection."""
        self._chroma_client.delete_collection(self.collection_name)
        self._collection = self._chroma_client.create_collection(
            name=self.collection_name,
            embedding_function=self._embedding_function,
        )
        logger.info(f"Cleared collection: {self.collection_name}")
    
    def delete(self) -> None:
        """Delete the collection entirely."""
        self._chroma_client.delete_collection(self.collection_name)
        logger.info(f"Deleted collection: {self.collection_name}")
