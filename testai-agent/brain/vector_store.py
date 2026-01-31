"""
TestAI Agent - Vector Brain (ChromaDB)

The Brain stores and retrieves QA knowledge using semantic search.
This eliminates context window issues by fetching only relevant rules.

Design Philosophy:
- Local-first: No external services
- Fast: In-process vector search
- Persistent: Survives restarts
- Human-like: Returns knowledge in digestible chunks
- Graceful Fallback: Works even without ChromaDB
"""

import os
import re
import hashlib
from pathlib import Path
from typing import List, Dict, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import Counter
import math

# ChromaDB for local vector storage
try:
    import chromadb
    from chromadb.config import Settings
    CHROMA_AVAILABLE = True
except ImportError:
    CHROMA_AVAILABLE = False
    print("⚠️  ChromaDB not installed. Run: pip install chromadb")


@dataclass
class KnowledgeChunk:
    """A piece of QA knowledge stored in the brain."""
    id: str
    content: str
    section: str
    category: str  # 'rule', 'example', 'checklist', 'edge_case'
    tags: List[str] = field(default_factory=list)
    page_types: List[str] = field(default_factory=list)
    relevance_score: float = 0.0

    def __str__(self) -> str:
        return f"[{self.category.upper()}] {self.section}: {self.content[:100]}..."


@dataclass
class SearchResult:
    """Result from a brain query - human-readable."""
    chunks: List[KnowledgeChunk]
    query: str
    total_found: int
    confidence: float  # How confident we are these are relevant

    def summarize(self) -> str:
        """Human-friendly summary of what we found."""
        if not self.chunks:
            return f"Hmm, I couldn't find specific rules for '{self.query}'. Let me use general testing principles."

        categories = set(c.category for c in self.chunks)
        return (
            f"Found {self.total_found} relevant pieces of knowledge "
            f"({', '.join(categories)}). "
            f"Confidence: {self.confidence:.0%}"
        )


class QABrain:
    """
    The QA Knowledge Brain - stores and retrieves testing wisdom.

    Usage:
        brain = QABrain()
        brain.ingest_knowledge("./QA_BRAIN.md")

        # Find relevant rules for a feature
        results = brain.search("login page validation rules")

        # Get rules for specific page type
        rules = brain.get_for_page_type("login")
    """

    def __init__(self, persist_directory: str = "./.brain_data"):
        """
        Initialize the QA Brain.

        Args:
            persist_directory: Where to store the vector database
        """
        self.persist_dir = Path(persist_directory)
        self.persist_dir.mkdir(parents=True, exist_ok=True)

        self._client = None
        self._collection = None
        self._is_loaded = False
        self._chunk_count = 0

        if CHROMA_AVAILABLE:
            self._init_chroma()

    def _init_chroma(self):
        """Initialize ChromaDB client and collection."""
        self._client = chromadb.PersistentClient(
            path=str(self.persist_dir),
            settings=Settings(anonymized_telemetry=False)
        )

        # Create or get the QA knowledge collection
        self._collection = self._client.get_or_create_collection(
            name="qa_brain",
            metadata={"description": "QA testing knowledge base"}
        )

        self._chunk_count = self._collection.count()
        self._is_loaded = self._chunk_count > 0

    @property
    def is_ready(self) -> bool:
        """Check if brain has knowledge loaded."""
        return self._is_loaded and self._chunk_count > 0

    def get_status(self) -> Dict[str, Any]:
        """Get brain status - human friendly."""
        return {
            "ready": self.is_ready,
            "knowledge_chunks": self._chunk_count,
            "storage_path": str(self.persist_dir),
            "message": (
                f"Brain loaded with {self._chunk_count} pieces of QA knowledge. Ready to help!"
                if self.is_ready else
                "Brain is empty. Please ingest QA_BRAIN.md first."
            )
        }

    def ingest_knowledge(self, file_path: str, force_reload: bool = False) -> Dict[str, Any]:
        """
        Ingest QA knowledge from a markdown file into the vector store.

        Args:
            file_path: Path to QA_BRAIN.md or similar
            force_reload: If True, clear existing knowledge first

        Returns:
            Status dict with chunk count and categories
        """
        if not CHROMA_AVAILABLE:
            return {"error": "ChromaDB not available. Please install it."}

        file_path = Path(file_path)
        if not file_path.exists():
            return {"error": f"File not found: {file_path}"}

        # Check if already ingested (by file hash)
        content = file_path.read_text(encoding='utf-8')
        file_hash = hashlib.md5(content.encode()).hexdigest()

        if not force_reload and self._is_already_ingested(file_hash):
            return {
                "status": "already_loaded",
                "message": "Knowledge base already loaded. Use force_reload=True to re-ingest.",
                "chunks": self._chunk_count
            }

        # Clear existing if force reload
        if force_reload:
            self._client.delete_collection("qa_brain")
            self._collection = self._client.create_collection(
                name="qa_brain",
                metadata={"description": "QA testing knowledge base"}
            )

        # Parse and chunk the content
        chunks = self._parse_markdown(content)

        # Add to vector store
        self._add_chunks(chunks, file_hash)

        self._chunk_count = self._collection.count()
        self._is_loaded = True

        # Categorize what we loaded
        categories = {}
        for chunk in chunks:
            cat = chunk['category']
            categories[cat] = categories.get(cat, 0) + 1

        return {
            "status": "success",
            "message": f"Loaded {len(chunks)} knowledge chunks into brain!",
            "chunks": len(chunks),
            "categories": categories,
            "file_hash": file_hash
        }

    def search(
        self,
        query: str,
        limit: int = 5,
        category: Optional[str] = None,
        page_type: Optional[str] = None
    ) -> SearchResult:
        """
        Search the brain for relevant knowledge.

        Args:
            query: What to search for (natural language)
            limit: Max results to return
            category: Filter by category (rule, example, checklist, edge_case)
            page_type: Filter by page type (login, checkout, etc.)

        Returns:
            SearchResult with relevant chunks
        """
        if not self.is_ready:
            return SearchResult(
                chunks=[],
                query=query,
                total_found=0,
                confidence=0.0
            )

        # Build where filter
        where_filter = None
        if category or page_type:
            conditions = []
            if category:
                conditions.append({"category": category})
            if page_type:
                conditions.append({"page_types": {"$contains": page_type}})

            if len(conditions) == 1:
                where_filter = conditions[0]
            else:
                where_filter = {"$and": conditions}

        # Query ChromaDB
        try:
            results = self._collection.query(
                query_texts=[query],
                n_results=limit,
                where=where_filter if where_filter else None
            )
        except Exception as e:
            print(f"Search error: {e}")
            return SearchResult(chunks=[], query=query, total_found=0, confidence=0.0)

        # Convert to KnowledgeChunks
        chunks = []
        distances = results.get('distances', [[]])[0]

        for i, doc_id in enumerate(results.get('ids', [[]])[0]):
            metadata = results.get('metadatas', [[]])[0][i] if results.get('metadatas') else {}
            content = results.get('documents', [[]])[0][i] if results.get('documents') else ""

            # Convert distance to similarity (ChromaDB uses L2 distance)
            distance = distances[i] if i < len(distances) else 1.0
            similarity = 1.0 / (1.0 + distance)  # Convert to 0-1 range

            chunk = KnowledgeChunk(
                id=doc_id,
                content=content,
                section=metadata.get('section', 'Unknown'),
                category=metadata.get('category', 'rule'),
                tags=metadata.get('tags', '').split(',') if metadata.get('tags') else [],
                page_types=metadata.get('page_types', '').split(',') if metadata.get('page_types') else [],
                relevance_score=similarity
            )
            chunks.append(chunk)

        # Calculate overall confidence
        avg_score = sum(c.relevance_score for c in chunks) / len(chunks) if chunks else 0.0

        return SearchResult(
            chunks=chunks,
            query=query,
            total_found=len(chunks),
            confidence=avg_score
        )

    def get_for_page_type(self, page_type: str, limit: int = 10) -> SearchResult:
        """Get all relevant knowledge for a specific page type."""
        return self.search(
            query=f"Testing rules for {page_type} page",
            limit=limit,
            page_type=page_type
        )

    def get_for_category(self, category: str, limit: int = 10) -> SearchResult:
        """Get knowledge by category (rule, example, checklist, edge_case)."""
        return self.search(
            query=f"{category} for testing",
            limit=limit,
            category=category
        )

    def get_edge_cases(self, feature: str, limit: int = 15) -> SearchResult:
        """Get edge cases for a specific feature."""
        return self.search(
            query=f"Edge cases boundary conditions for {feature}",
            limit=limit,
            category="edge_case"
        )

    def get_security_rules(self, feature: str, limit: int = 10) -> SearchResult:
        """Get security testing rules for a feature."""
        return self.search(
            query=f"Security vulnerabilities XSS injection authentication for {feature}",
            limit=limit
        )

    # =========================================================================
    # Private Methods
    # =========================================================================

    def _is_already_ingested(self, file_hash: str) -> bool:
        """Check if this file was already ingested."""
        if not self._collection:
            return False

        try:
            # Check metadata for file hash
            results = self._collection.get(
                ids=["__meta__"],
                include=["metadatas"]
            )
            if results['metadatas'] and results['metadatas'][0].get('file_hash') == file_hash:
                return True
        except:
            pass

        return False

    def _parse_markdown(self, content: str) -> List[Dict[str, Any]]:
        """Parse markdown into chunks suitable for vector storage."""
        chunks = []

        # Split by major sections (## headers)
        sections = content.split('\n## ')

        for i, section in enumerate(sections):
            if not section.strip():
                continue

            # Extract section header
            lines = section.split('\n')
            header = lines[0].strip('# ').strip() if lines else f"Section {i}"
            section_content = '\n'.join(lines[1:]) if len(lines) > 1 else ""

            # Detect category
            category = self._detect_category(header, section_content)

            # Detect page types this applies to
            page_types = self._detect_page_types(section_content)

            # Extract tags
            tags = self._extract_tags(header, section_content)

            # Split large sections into smaller chunks
            sub_chunks = self._split_into_chunks(section_content, max_chars=2000)

            for j, chunk_text in enumerate(sub_chunks):
                if len(chunk_text.strip()) < 50:  # Skip tiny chunks
                    continue

                chunk_id = f"chunk_{i}_{j}_{hashlib.md5(chunk_text.encode()).hexdigest()[:8]}"

                chunks.append({
                    "id": chunk_id,
                    "content": chunk_text,
                    "section": header,
                    "category": category,
                    "tags": ','.join(tags),
                    "page_types": ','.join(page_types)
                })

        return chunks

    def _detect_category(self, header: str, content: str) -> str:
        """Detect the category of a chunk."""
        header_lower = header.lower()
        content_lower = content.lower()

        if '```' in content:
            return 'example'
        if '- [ ]' in content or '☐' in content or 'checklist' in header_lower:
            return 'checklist'
        if 'edge' in header_lower or 'boundary' in content_lower:
            return 'edge_case'
        if 'security' in header_lower or 'vulnerab' in content_lower:
            return 'security'

        return 'rule'

    def _detect_page_types(self, content: str) -> List[str]:
        """Detect which page types this content applies to."""
        content_lower = content.lower()
        page_types = []

        type_keywords = {
            'login': ['login', 'signin', 'sign in', 'authentication'],
            'signup': ['signup', 'sign up', 'registration', 'register'],
            'checkout': ['checkout', 'payment', 'purchase', 'buy'],
            'search': ['search', 'find', 'query', 'filter'],
            'dashboard': ['dashboard', 'overview', 'analytics'],
            'settings': ['settings', 'preferences', 'configuration'],
            'profile': ['profile', 'account', 'user info'],
            'admin': ['admin', 'administrator', 'manage users'],
            'form': ['form', 'input', 'validation', 'submit'],
        }

        for page_type, keywords in type_keywords.items():
            if any(kw in content_lower for kw in keywords):
                page_types.append(page_type)

        return page_types if page_types else ['general']

    def _extract_tags(self, header: str, content: str) -> List[str]:
        """Extract relevant tags from content."""
        tags = []
        combined = (header + ' ' + content).lower()

        tag_keywords = [
            'security', 'validation', 'accessibility', 'performance',
            'api', 'form', 'auth', 'input', 'error', 'edge case',
            'xss', 'injection', 'session', 'csrf', 'ui', 'ux'
        ]

        for tag in tag_keywords:
            if tag in combined:
                tags.append(tag.replace(' ', '_'))

        return tags[:5]  # Limit to 5 tags

    def _split_into_chunks(self, text: str, max_chars: int = 2000) -> List[str]:
        """Split text into smaller chunks while preserving meaning."""
        if len(text) <= max_chars:
            return [text]

        chunks = []
        paragraphs = text.split('\n\n')
        current_chunk = ""

        for para in paragraphs:
            if len(current_chunk) + len(para) + 2 <= max_chars:
                current_chunk += para + '\n\n'
            else:
                if current_chunk.strip():
                    chunks.append(current_chunk.strip())
                current_chunk = para + '\n\n'

        if current_chunk.strip():
            chunks.append(current_chunk.strip())

        return chunks

    def _add_chunks(self, chunks: List[Dict[str, Any]], file_hash: str):
        """Add chunks to the vector store."""
        if not chunks:
            return

        # Add metadata record
        self._collection.add(
            ids=["__meta__"],
            documents=["Metadata record"],
            metadatas=[{"file_hash": file_hash, "ingested_at": datetime.now().isoformat()}]
        )

        # Add chunks in batches
        batch_size = 100
        for i in range(0, len(chunks), batch_size):
            batch = chunks[i:i + batch_size]

            self._collection.add(
                ids=[c['id'] for c in batch],
                documents=[c['content'] for c in batch],
                metadatas=[{
                    'section': c['section'],
                    'category': c['category'],
                    'tags': c['tags'],
                    'page_types': c['page_types']
                } for c in batch]
            )


# ─────────────────────────────────────────────────────────────────
# In-Memory Fallback Brain (No ChromaDB Required)
# ─────────────────────────────────────────────────────────────────

class InMemoryBrain:
    """
    Fallback brain that works without ChromaDB.
    Uses TF-IDF-like scoring for semantic matching.
    """

    def __init__(self):
        """Initialize in-memory brain."""
        self.chunks: List[Dict[str, Any]] = []
        self._idf_cache: Dict[str, float] = {}
        self._chunk_count = 0
        self._is_loaded = False

    @property
    def is_ready(self) -> bool:
        """Check if brain has knowledge loaded."""
        return self._is_loaded and self._chunk_count > 0

    def get_status(self) -> Dict[str, Any]:
        """Get brain status."""
        return {
            "ready": self.is_ready,
            "knowledge_chunks": self._chunk_count,
            "storage_path": "in-memory",
            "message": (
                f"Brain loaded with {self._chunk_count} pieces of QA knowledge (in-memory)."
                if self.is_ready else
                "Brain is empty. Please load knowledge first."
            )
        }

    def add_chunk(
        self,
        chunk_id: str,
        content: str,
        section: str,
        category: str,
        tags: List[str] = None,
        page_types: List[str] = None,
    ):
        """Add a knowledge chunk."""
        self.chunks.append({
            "id": chunk_id,
            "content": content,
            "section": section,
            "category": category,
            "tags": tags or [],
            "page_types": page_types or [],
            "tokens": self._tokenize(content.lower()),
        })
        self._chunk_count = len(self.chunks)
        self._is_loaded = True
        self._idf_cache = {}  # Clear cache when adding

    def _tokenize(self, text: str) -> List[str]:
        """Tokenize text into words."""
        # Remove punctuation and split
        text = re.sub(r'[^\w\s]', ' ', text.lower())
        tokens = text.split()
        # Remove very short tokens and stopwords
        stopwords = {'the', 'a', 'an', 'is', 'are', 'was', 'were', 'be', 'been',
                     'being', 'have', 'has', 'had', 'do', 'does', 'did', 'will',
                     'would', 'could', 'should', 'may', 'might', 'must', 'shall',
                     'can', 'for', 'and', 'or', 'but', 'in', 'on', 'at', 'to',
                     'from', 'with', 'by', 'of', 'this', 'that', 'these', 'those'}
        return [t for t in tokens if len(t) > 2 and t not in stopwords]

    def _compute_idf(self, term: str) -> float:
        """Compute inverse document frequency for a term."""
        if term in self._idf_cache:
            return self._idf_cache[term]

        doc_count = sum(1 for c in self.chunks if term in c['tokens'])
        if doc_count == 0:
            idf = 0.0
        else:
            idf = math.log(len(self.chunks) / doc_count) + 1

        self._idf_cache[term] = idf
        return idf

    def _score_chunk(self, chunk: Dict[str, Any], query_tokens: List[str]) -> float:
        """Score a chunk against query using TF-IDF-like scoring."""
        chunk_tokens = chunk['tokens']
        if not chunk_tokens:
            return 0.0

        # Count term frequencies
        chunk_tf = Counter(chunk_tokens)

        score = 0.0
        for term in query_tokens:
            tf = chunk_tf.get(term, 0) / len(chunk_tokens)  # Normalized TF
            idf = self._compute_idf(term)
            score += tf * idf

        # Normalize by query length
        if query_tokens:
            score /= len(query_tokens)

        # Boost for exact phrase matches
        content_lower = chunk['content'].lower()
        query_text = ' '.join(query_tokens)
        if query_text in content_lower:
            score *= 1.5

        return score

    def search(
        self,
        query: str,
        limit: int = 5,
        category: Optional[str] = None,
        page_type: Optional[str] = None,
    ) -> SearchResult:
        """
        Search for relevant knowledge chunks.

        Args:
            query: Search query
            limit: Maximum results
            category: Filter by category
            page_type: Filter by page type

        Returns:
            SearchResult with matching chunks
        """
        if not self.is_ready:
            return SearchResult(
                chunks=[],
                query=query,
                total_found=0,
                confidence=0.0
            )

        query_tokens = self._tokenize(query.lower())

        # Score all chunks
        scored_chunks = []
        for chunk in self.chunks:
            # Apply filters
            if category and chunk['category'] != category:
                continue
            if page_type and page_type not in chunk['page_types']:
                continue

            score = self._score_chunk(chunk, query_tokens)
            if score > 0:
                scored_chunks.append((chunk, score))

        # Sort by score
        scored_chunks.sort(key=lambda x: x[1], reverse=True)

        # Convert to KnowledgeChunks
        result_chunks = []
        for chunk, score in scored_chunks[:limit]:
            # Normalize score to 0-1 range
            normalized_score = min(1.0, score * 2)

            result_chunks.append(KnowledgeChunk(
                id=chunk['id'],
                content=chunk['content'],
                section=chunk['section'],
                category=chunk['category'],
                tags=chunk['tags'],
                page_types=chunk['page_types'],
                relevance_score=normalized_score,
            ))

        avg_score = sum(c.relevance_score for c in result_chunks) / len(result_chunks) if result_chunks else 0.0

        return SearchResult(
            chunks=result_chunks,
            query=query,
            total_found=len(result_chunks),
            confidence=avg_score,
        )

    def get_for_page_type(self, page_type: str, limit: int = 10) -> SearchResult:
        """Get knowledge for a page type."""
        return self.search(
            query=f"Testing rules for {page_type}",
            limit=limit,
            page_type=page_type
        )

    def get_for_category(self, category: str, limit: int = 10) -> SearchResult:
        """Get knowledge by category."""
        return self.search(
            query=f"{category} testing",
            limit=limit,
            category=category
        )

    def get_all_by_page_type(self, page_type: str) -> List[KnowledgeChunk]:
        """Get all chunks for a page type without scoring."""
        chunks = []
        for chunk in self.chunks:
            if page_type in chunk['page_types']:
                chunks.append(KnowledgeChunk(
                    id=chunk['id'],
                    content=chunk['content'],
                    section=chunk['section'],
                    category=chunk['category'],
                    tags=chunk['tags'],
                    page_types=chunk['page_types'],
                    relevance_score=1.0,
                ))
        return chunks

    def get_all_by_category(self, category: str) -> List[KnowledgeChunk]:
        """Get all chunks for a category without scoring."""
        chunks = []
        for chunk in self.chunks:
            if chunk['category'] == category:
                chunks.append(KnowledgeChunk(
                    id=chunk['id'],
                    content=chunk['content'],
                    section=chunk['section'],
                    category=chunk['category'],
                    tags=chunk['tags'],
                    page_types=chunk['page_types'],
                    relevance_score=1.0,
                ))
        return chunks


# ─────────────────────────────────────────────────────────────────
# Smart Brain Factory
# ─────────────────────────────────────────────────────────────────

def create_brain(persist_dir: str = "./.brain_data") -> QABrain:
    """Create a QA Brain instance (ChromaDB or fallback)."""
    return QABrain(persist_directory=persist_dir)


def create_in_memory_brain() -> InMemoryBrain:
    """Create an in-memory brain (no persistence)."""
    return InMemoryBrain()


def load_brain_from_generator(generator) -> InMemoryBrain:
    """
    Create a brain from a CitedTestGenerator's knowledge base.

    This allows the Brain to be populated from the pre-defined
    knowledge in the generators without needing a markdown file.

    Args:
        generator: A CitedTestGenerator with knowledge_base

    Returns:
        InMemoryBrain populated with the generator's knowledge
    """
    brain = InMemoryBrain()

    for section_id, kb in generator.knowledge_base.items():
        # Create a chunk for each rule
        for i, rule in enumerate(kb.get('rules', [])):
            brain.add_chunk(
                chunk_id=f"{section_id}_{i}",
                content=rule,
                section=f"Section {section_id}: {kb.get('title', 'Unknown')}",
                category='rule',
                tags=kb.get('tags', []),
                page_types=kb.get('page_types', ['general']),
            )

    return brain
