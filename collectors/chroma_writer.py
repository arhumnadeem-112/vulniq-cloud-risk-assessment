"""
chroma_writer.py
----------------
Shared ChromaDB upsert module used by all collection scripts.
Reads CHROMA_HOST and CHROMA_PORT from environment.

Usage:
    from chroma_writer import upsert_documents
    upsert_documents(
        collection_name="vuln_text",
        documents=["CVE text..."],
        metadatas=[{"cve_id": "CVE-2024-1234", "source": "nvd", ...}],
        ids=["nvd::CVE-2024-1234::0"],
    )
"""

import os
import logging
import chromadb
from chromadb.config import Settings

log = logging.getLogger(__name__)

_client = None
CHUNK_SIZE = 512   # max tokens per document chunk
MAX_CHARS  = 2048  # approx char limit before chunking (1 token ≈ 4 chars)


def get_client() -> chromadb.HttpClient:
    global _client
    if _client is None:
        host = os.environ.get("CHROMA_HOST", "localhost")
        port = int(os.environ.get("CHROMA_PORT", "8000"))
        _client = chromadb.HttpClient(
            host=host,
            port=port,
            settings=Settings(anonymized_telemetry=False),
        )
        log.info("ChromaDB client connected to %s:%d", host, port)
    return _client


def get_or_create_collection(name: str):
    client = get_client()
    return client.get_or_create_collection(
        name=name,
        metadata={"hnsw:space": "cosine"},
    )


def chunk_text(text: str, max_chars: int = MAX_CHARS) -> list[str]:
    """Split text into chunks at sentence boundaries where possible."""
    if len(text) <= max_chars:
        return [text]
    chunks = []
    while text:
        if len(text) <= max_chars:
            chunks.append(text)
            break
        # Try to split at last sentence boundary within max_chars
        boundary = text[:max_chars].rfind(". ")
        if boundary == -1:
            boundary = max_chars
        else:
            boundary += 1  # include the period
        chunks.append(text[:boundary].strip())
        text = text[boundary:].strip()
    return chunks


def upsert_documents(
    collection_name: str,
    documents: list[str],
    metadatas: list[dict],
    ids: list[str],
) -> int:
    """
    Upsert documents into a ChromaDB collection.
    Automatically chunks documents that exceed MAX_CHARS.
    Returns total number of chunks upserted.
    """
    if not documents:
        return 0

    collection = get_or_create_collection(collection_name)

    final_docs, final_metas, final_ids = [], [], []
    for doc, meta, doc_id in zip(documents, metadatas, ids):
        chunks = chunk_text(doc)
        for idx, chunk in enumerate(chunks):
            final_docs.append(chunk)
            final_metas.append({**meta, "chunk_index": idx,
                                 "total_chunks": len(chunks)})
            final_ids.append(f"{doc_id}::{idx}")

    # ChromaDB upsert in batches of 100
    BATCH = 100
    total = 0
    for start in range(0, len(final_docs), BATCH):
        end = start + BATCH
        collection.upsert(
            documents=final_docs[start:end],
            metadatas=final_metas[start:end],
            ids=final_ids[start:end],
        )
        total += len(final_docs[start:end])

    log.info("chroma upsert: collection=%s chunks=%d", collection_name, total)
    return total
