"""Local embedding generation (SentenceTransformers, CPU) - no external API
key needed. Used both to embed each tool description at catalog-ingestion
time and to embed each incoming query at discovery time."""
import hashlib
import logging

import numpy as np

logger = logging.getLogger("operations-manager.embeddings")


class ToolEmbeddings:
    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        from sentence_transformers import SentenceTransformer

        logger.info("Loading embedding model '%s'...", model_name)
        self.model = SentenceTransformer(model_name)
        self.dimension = self.model.get_sentence_embedding_dimension()
        self._cache: dict[str, np.ndarray] = {}
        self._max_cache_size = 2000
        logger.info("Embedding model ready (dimension=%d)", self.dimension)

    def embed(self, text: str) -> list[float]:
        """Return an L2-normalized embedding as a plain list of floats.
        Couchbase's Search vector index here uses dot_product similarity, so
        normalizing before storing/querying makes dot_product equivalent to
        cosine similarity."""
        if not text or not text.strip():
            raise ValueError("Cannot embed empty text")

        cache_key = hashlib.md5(text.encode("utf-8")).hexdigest()
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        vec = self.model.encode(text, convert_to_numpy=True).astype(np.float32)
        norm = np.linalg.norm(vec)
        if norm > 0:
            vec = vec / norm
        result = vec.tolist()

        if len(self._cache) >= self._max_cache_size:
            self._cache.pop(next(iter(self._cache)))
        self._cache[cache_key] = result
        return result
