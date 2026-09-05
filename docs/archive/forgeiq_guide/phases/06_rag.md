# Phase 6 — Context Retrieval / RAG

**Time: ~2.5 hours** | **Checkpoint: query returns relevant file chunks**

## What you're building

A hybrid retrieval system that combines keyword search (grep) with semantic search (Gemini embeddings + ChromaDB) to find relevant code files for a given task.

## Step 6.1 — Create `src/forgeiq/context/indexer.py`

```python
"""Index a repository: walk files, chunk, embed, store in ChromaDB."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import chromadb
from langchain_google_genai import GoogleGenerativeAIEmbeddings

CODE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rs", ".rb",
    ".c", ".cpp", ".h", ".cs", ".php",
    ".html", ".css", ".scss",
    ".json", ".yaml", ".yml", ".toml", ".xml",
    ".md", ".txt", ".rst",
    ".sql", ".sh",
}

IGNORE_DIRS = {
    ".git", "__pycache__", "node_modules", ".venv", "venv",
    ".tox", ".mypy_cache", ".ruff_cache", ".pytest_cache",
    "dist", "build", ".egg-info", ".eggs",
}

IGNORE_FILES = {".env", ".DS_Store", "uv.lock", "package-lock.json"}
MAX_FILE_SIZE = 100_000  # 100KB
CHUNK_SIZE = 100  # lines
CHUNK_OVERLAP = 20  # lines
MAX_CHUNK_LINES = 150  # Files <= this are one chunk


@dataclass
class CodeChunk:
    file_path: str      # Relative to repo root
    start_line: int
    end_line: int
    content: str
    language: str


def _detect_language(path: Path) -> str:
    ext_map = {".py": "python", ".js": "javascript", ".ts": "typescript",
               ".java": "java", ".go": "go", ".rs": "rust", ".rb": "ruby",
               ".html": "html", ".css": "css", ".json": "json",
               ".yaml": "yaml", ".yml": "yaml", ".md": "markdown"}
    return ext_map.get(path.suffix, "text")


def walk_repo(repo_path: Path) -> list[Path]:
    """Walk the repo and return all indexable files."""
    files = []
    for root, dirs, filenames in os.walk(repo_path):
        # Prune ignored directories
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        for fname in filenames:
            p = Path(root) / fname
            if fname in IGNORE_FILES:
                continue
            if p.suffix not in CODE_EXTENSIONS and fname not in ("Makefile", "Dockerfile"):
                continue
            if p.stat().st_size > MAX_FILE_SIZE:
                continue
            files.append(p)
    return files


def chunk_file(file_path: Path, repo_root: Path) -> list[CodeChunk]:
    """Split a file into chunks."""
    try:
        content = file_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return []

    lines = content.splitlines(keepends=True)
    rel_path = str(file_path.relative_to(repo_root))
    language = _detect_language(file_path)

    if len(lines) <= MAX_CHUNK_LINES:
        return [CodeChunk(
            file_path=rel_path,
            start_line=1,
            end_line=len(lines),
            content=content,
            language=language,
        )]

    chunks = []
    start = 0
    while start < len(lines):
        end = min(start + CHUNK_SIZE, len(lines))
        chunk_content = "".join(lines[start:end])
        chunks.append(CodeChunk(
            file_path=rel_path,
            start_line=start + 1,
            end_line=end,
            content=chunk_content,
            language=language,
        ))
        start += CHUNK_SIZE - CHUNK_OVERLAP

    return chunks


def build_index(repo_path: str) -> tuple[chromadb.Collection, list[CodeChunk]]:
    """Index a repository into ChromaDB. Returns the collection and chunks."""
    repo = Path(repo_path).resolve()
    files = walk_repo(repo)

    all_chunks = []
    for f in files:
        all_chunks.extend(chunk_file(f, repo))

    if not all_chunks:
        raise ValueError(f"No indexable files found in {repo}")

    # Embed with Gemini
    embeddings = GoogleGenerativeAIEmbeddings(model="models/text-embedding-004")
    texts = [c.content for c in all_chunks]
    vectors = embeddings.embed_documents(texts)

    # Store in ChromaDB (ephemeral — in memory only)
    client = chromadb.EphemeralClient()
    collection = client.get_or_create_collection(
        name="repo_context",
        metadata={"hnsw:space": "cosine"},
    )
    collection.add(
        ids=[f"chunk_{i}" for i in range(len(all_chunks))],
        documents=texts,
        embeddings=vectors,
        metadatas=[{"file_path": c.file_path, "start_line": c.start_line,
                    "end_line": c.end_line, "language": c.language}
                   for c in all_chunks],
    )

    return collection, all_chunks
```

**Key decisions to defend:**
- Ephemeral ChromaDB — index fresh each run, no stale data
- Line-based chunking, not AST — simpler, language-agnostic, good enough
- 100-line chunks with 20-line overlap — balances context window vs granularity
- Gemini text-embedding-004 — same provider as the LLM, no extra API key

## Step 6.2 — Create `src/forgeiq/context/retriever.py`

```python
"""Hybrid retriever: combines semantic search with grep keyword search."""

from __future__ import annotations

import subprocess
from pathlib import Path

import chromadb
from langchain_google_genai import GoogleGenerativeAIEmbeddings

from .indexer import CodeChunk


def grep_search(query: str, repo_path: str, top_k: int = 10) -> list[str]:
    """Keyword search via grep. Returns list of relative file paths sorted by match count."""
    repo = Path(repo_path).resolve()
    try:
        result = subprocess.run(
            ["grep", "-rlI", query, str(repo)],
            capture_output=True, text=True, timeout=10,
        )
    except subprocess.TimeoutExpired:
        return []

    if not result.stdout.strip():
        return []

    # Get files sorted by match count
    file_counts: dict[str, int] = {}
    count_result = subprocess.run(
        ["grep", "-rcI", query, str(repo)],
        capture_output=True, text=True, timeout=10,
    )
    for line in count_result.stdout.strip().split("\n"):
        if ":" in line:
            path, count = line.rsplit(":", 1)
            try:
                rel = str(Path(path).relative_to(repo))
                file_counts[rel] = int(count)
            except (ValueError, TypeError):
                continue

    sorted_files = sorted(file_counts.keys(), key=lambda f: file_counts[f], reverse=True)
    return sorted_files[:top_k]


def semantic_search(
    query: str,
    collection: chromadb.Collection,
    top_k: int = 10,
) -> list[dict]:
    """Semantic search via ChromaDB. Returns list of {file_path, content, score} dicts."""
    embeddings = GoogleGenerativeAIEmbeddings(model="models/text-embedding-004")
    query_vector = embeddings.embed_query(query)

    results = collection.query(
        query_embeddings=[query_vector],
        n_results=top_k,
    )

    hits = []
    for i, doc in enumerate(results["documents"][0]):
        meta = results["metadatas"][0][i]
        distance = results["distances"][0][i] if results.get("distances") else 0
        hits.append({
            "file_path": meta["file_path"],
            "start_line": meta["start_line"],
            "end_line": meta["end_line"],
            "content": doc,
            "score": 1 - distance,  # cosine distance to similarity
        })
    return hits


def merge_results(
    semantic_hits: list[dict],
    grep_files: list[str],
    all_chunks: list[CodeChunk],
    top_k: int = 10,
) -> list[dict]:
    """Merge semantic and grep results. Files appearing in both get boosted."""
    scores: dict[str, float] = {}

    # Semantic: position-based scoring
    for i, hit in enumerate(semantic_hits):
        fp = hit["file_path"]
        scores[fp] = scores.get(fp, 0) + (len(semantic_hits) - i)

    # Grep: position-based scoring
    for i, fp in enumerate(grep_files):
        scores[fp] = scores.get(fp, 0) + (len(grep_files) - i)

    # Sort by combined score
    ranked_files = sorted(scores.keys(), key=lambda f: scores[f], reverse=True)[:top_k]

    # Build result: find the best chunk for each file
    result = []
    semantic_by_file = {h["file_path"]: h for h in semantic_hits}
    chunk_by_file = {}
    for c in all_chunks:
        if c.file_path not in chunk_by_file:
            chunk_by_file[c.file_path] = c

    for fp in ranked_files:
        if fp in semantic_by_file:
            result.append(semantic_by_file[fp])
        elif fp in chunk_by_file:
            c = chunk_by_file[fp]
            result.append({
                "file_path": c.file_path,
                "start_line": c.start_line,
                "end_line": c.end_line,
                "content": c.content,
                "score": 0,
            })

    return result


def format_context(hits: list[dict], repo_path: str) -> str:
    """Format retrieval results into a context string for the LLM."""
    parts = ["## Relevant Files\n"]
    for hit in hits:
        fp = hit["file_path"]
        start = hit.get("start_line", 1)
        end = hit.get("end_line", "?")
        lang = Path(fp).suffix.lstrip(".")
        parts.append(f"### {fp} (lines {start}-{end})")
        parts.append(f"```{lang}")
        parts.append(hit["content"].rstrip())
        parts.append("```\n")
    return "\n".join(parts)
```

## Step 6.3 — Create `tests/test_context.py`

```python
import pytest
from pathlib import Path
from forgeiq.context.indexer import walk_repo, chunk_file, CodeChunk


def test_walk_repo_finds_python_files(tmp_path):
    (tmp_path / "app.py").write_text("x = 1")
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__" / "app.cpython.pyc").write_text("")
    files = walk_repo(tmp_path)
    assert len(files) == 1
    assert files[0].name == "app.py"


def test_walk_repo_ignores_git(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("")
    (tmp_path / "main.py").write_text("")
    files = walk_repo(tmp_path)
    assert all(".git" not in str(f) for f in files)


def test_chunk_small_file(tmp_path):
    f = tmp_path / "small.py"
    f.write_text("line1\nline2\nline3\n")
    chunks = chunk_file(f, tmp_path)
    assert len(chunks) == 1
    assert chunks[0].start_line == 1


def test_chunk_large_file(tmp_path):
    f = tmp_path / "big.py"
    f.write_text("\n".join(f"line_{i}" for i in range(200)))
    chunks = chunk_file(f, tmp_path)
    assert len(chunks) > 1
```

## Checkpoint ✅

```bash
uv run pytest tests/test_context.py -v
```

Commit:
```bash
git add .
git commit -m "Phase 6: hybrid RAG — indexer + retriever + tests"
```

## What you should be able to explain

- Why hybrid (grep + semantic)? Grep catches exact identifiers; embeddings catch intent/synonyms
- Why ChromaDB ephemeral? Small repos, fresh index each run, no stale data
- Why not tree-sitter? Language-agnostic line chunking is simpler and sufficient for this scope
- Why not a reranker? Position-based merge is simple, effective, and adds no dependency
```
