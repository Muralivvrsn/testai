"""
TestAI Agent - Vector Brain (ChromaDB)

The Brain stores and retrieves QA knowledge with PRECISE CITATIONS.
Every test case generated will cite exactly which section it came from.

Key Features:
- Section-level tagging (e.g., "Section 7.1 - Email Validation")
- Confidence scoring for retrieval accuracy
- Zero hallucination through explicit source tracking
"""

import os
import re
import hashlib
from pathlib import Path
from typing import List, Dict, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

try:
    import chromadb
    from chromadb.config import Settings
    CHROMA_AVAILABLE = True
except ImportError:
    CHROMA_AVAILABLE = False


class KnowledgeCategory(Enum):
    """Categories of QA knowledge."""
    SECURITY = "security"
    FUNCTIONAL = "functional"
    UI_UX = "ui_ux"
    PERFORMANCE = "performance"
    EDGE_CASE = "edge_case"
    VALIDATION = "validation"
    ACCESSIBILITY = "accessibility"
    API = "api"
    RULE = "rule"
    EXAMPLE = "example"
    CHECKLIST = "checklist"


@dataclass
class CitedKnowledge:
    """
    A piece of QA knowledge with FULL citation information.

    This is the core of our zero-hallucination system.
    Every test case must cite its source.
    """
    id: str
    content: str
    section_id: str           # e.g., "7.1"
    section_title: str        # e.g., "Email Validation"
    category: KnowledgeCategory
    tags: List[str] = field(default_factory=list)
    page_types: List[str] = field(default_factory=list)
    relevance_score: float = 0.0

    @property
    def citation(self) -> str:
        """Generate a formal citation string."""
        return f"Source: Section {self.section_id} - {self.section_title}"

    @property
    def short_citation(self) -> str:
        """Short citation for inline use."""
        return f"[{self.section_id}]"

    def __str__(self) -> str:
        return f"[{self.category.value.upper()}] {self.section_id}: {self.content[:80]}..."


@dataclass
class RetrievalResult:
    """Result from querying the Brain with citations."""
    knowledge: List[CitedKnowledge]
    query: str
    total_found: int
    confidence: float
    retrieval_time_ms: float = 0.0

    def get_citations(self) -> List[str]:
        """Get all unique citations from this result."""
        return list(set(k.citation for k in self.knowledge))

    def summarize(self) -> str:
        """Human-readable summary."""
        if not self.knowledge:
            return f"No relevant knowledge found for '{self.query}'."

        categories = set(k.category.value for k in self.knowledge)
        sections = set(k.section_id for k in self.knowledge)

        return (
            f"Retrieved {self.total_found} knowledge items from sections "
            f"{', '.join(sorted(sections))} ({', '.join(categories)}). "
            f"Confidence: {self.confidence:.0%}"
        )


class QABrain:
    """
    The QA Knowledge Brain - stores and retrieves testing wisdom WITH CITATIONS.

    Architecture:
    - Uses ChromaDB for vector storage
    - Each chunk is tagged with section_id and section_title
    - Retrieval returns CitedKnowledge objects with full provenance

    Usage:
        brain = QABrain()
        brain.ingest("./QA_BRAIN.md")

        # Get knowledge with citations
        result = brain.retrieve("login page validation")
        for knowledge in result.knowledge:
            print(f"{knowledge.content}")
            print(f"  → {knowledge.citation}")
    """

    def __init__(self, persist_directory: str = "./.brain_data"):
        """Initialize the Brain."""
        self.persist_dir = Path(persist_directory)
        self.persist_dir.mkdir(parents=True, exist_ok=True)

        self._client = None
        self._collection = None
        self._is_loaded = False
        self._chunk_count = 0
        self._sections: Dict[str, str] = {}  # section_id -> section_title

        if CHROMA_AVAILABLE:
            self._init_chroma()

    def _init_chroma(self):
        """Initialize ChromaDB."""
        self._client = chromadb.PersistentClient(
            path=str(self.persist_dir),
            settings=Settings(anonymized_telemetry=False)
        )

        self._collection = self._client.get_or_create_collection(
            name="qa_brain_v2",
            metadata={"description": "QA knowledge with citations"}
        )

        self._chunk_count = self._collection.count()
        self._is_loaded = self._chunk_count > 0

    @property
    def is_ready(self) -> bool:
        """Check if brain has knowledge."""
        return self._is_loaded and self._chunk_count > 0

    def get_status(self) -> Dict[str, Any]:
        """Get brain status for PROGRESS.md."""
        return {
            "ready": self.is_ready,
            "status": "Active" if self.is_ready else "Pending",
            "knowledge_chunks": self._chunk_count,
            "sections_indexed": len(self._sections),
            "storage_path": str(self.persist_dir),
        }

    def ingest(self, file_path: str, force_reload: bool = False) -> Dict[str, Any]:
        """
        Ingest QA knowledge from markdown with SECTION-LEVEL TAGGING.

        The markdown must have numbered sections like:
        ## 1. Input Validation
        ## 2.1 Email Fields

        Returns ingestion stats.
        """
        if not CHROMA_AVAILABLE:
            return {"error": "ChromaDB not available"}

        path = Path(file_path)
        if not path.exists():
            return {"error": f"File not found: {path}"}

        content = path.read_text(encoding='utf-8')
        file_hash = hashlib.md5(content.encode()).hexdigest()

        # Check if already ingested
        if not force_reload and self._is_already_ingested(file_hash):
            return {
                "status": "already_loaded",
                "message": "Knowledge already ingested. Use force_reload=True to re-ingest.",
                "chunks": self._chunk_count
            }

        # Clear if force reload
        if force_reload:
            self._client.delete_collection("qa_brain_v2")
            self._collection = self._client.create_collection(
                name="qa_brain_v2",
                metadata={"description": "QA knowledge with citations"}
            )

        # Parse with section tracking
        chunks = self._parse_with_sections(content)

        # Add to ChromaDB
        self._add_chunks(chunks, file_hash)

        self._chunk_count = self._collection.count()
        self._is_loaded = True

        # Build stats
        categories = {}
        for chunk in chunks:
            cat = chunk['category']
            categories[cat] = categories.get(cat, 0) + 1

        return {
            "status": "success",
            "message": f"Ingested {len(chunks)} knowledge chunks with citations!",
            "chunks": len(chunks),
            "sections": len(self._sections),
            "categories": categories,
            "file_hash": file_hash
        }

    def retrieve(
        self,
        query: str,
        limit: int = 5,
        category: Optional[KnowledgeCategory] = None,
        min_confidence: float = 0.3
    ) -> RetrievalResult:
        """
        Retrieve relevant knowledge WITH CITATIONS.

        This is the core RAG retrieval that ensures zero hallucination
        by attaching source information to every piece of knowledge.
        """
        import time
        start = time.time()

        if not self.is_ready:
            return RetrievalResult(
                knowledge=[],
                query=query,
                total_found=0,
                confidence=0.0
            )

        # Build filter
        where_filter = None
        if category:
            where_filter = {"category": category.value}

        try:
            results = self._collection.query(
                query_texts=[query],
                n_results=limit,
                where=where_filter
            )
        except Exception as e:
            print(f"Retrieval error: {e}")
            return RetrievalResult(
                knowledge=[],
                query=query,
                total_found=0,
                confidence=0.0
            )

        # Convert to CitedKnowledge
        knowledge_list = []
        distances = results.get('distances', [[]])[0]

        for i, doc_id in enumerate(results.get('ids', [[]])[0]):
            metadata = results.get('metadatas', [[]])[0][i] if results.get('metadatas') else {}
            content = results.get('documents', [[]])[0][i] if results.get('documents') else ""

            # Calculate relevance score
            distance = distances[i] if i < len(distances) else 1.0
            relevance = 1.0 / (1.0 + distance)

            # Skip low confidence results
            if relevance < min_confidence:
                continue

            # Parse category
            cat_str = metadata.get('category', 'rule')
            try:
                category_enum = KnowledgeCategory(cat_str)
            except ValueError:
                category_enum = KnowledgeCategory.RULE

            knowledge = CitedKnowledge(
                id=doc_id,
                content=content,
                section_id=metadata.get('section_id', 'Unknown'),
                section_title=metadata.get('section_title', 'Unknown'),
                category=category_enum,
                tags=metadata.get('tags', '').split(',') if metadata.get('tags') else [],
                page_types=metadata.get('page_types', '').split(',') if metadata.get('page_types') else [],
                relevance_score=relevance
            )
            knowledge_list.append(knowledge)

        elapsed = (time.time() - start) * 1000
        avg_confidence = sum(k.relevance_score for k in knowledge_list) / len(knowledge_list) if knowledge_list else 0.0

        return RetrievalResult(
            knowledge=knowledge_list,
            query=query,
            total_found=len(knowledge_list),
            confidence=avg_confidence,
            retrieval_time_ms=elapsed
        )

    def retrieve_for_feature(self, feature: str, page_type: str = None) -> RetrievalResult:
        """Retrieve all relevant knowledge for a feature."""
        query = f"Testing rules for {feature}"
        if page_type:
            query += f" {page_type} page"

        return self.retrieve(query, limit=10)

    def retrieve_security_rules(self, feature: str) -> RetrievalResult:
        """Get security-specific rules."""
        return self.retrieve(
            f"Security vulnerabilities attacks for {feature}",
            limit=8,
            category=KnowledgeCategory.SECURITY
        )

    def retrieve_validation_rules(self, feature: str) -> RetrievalResult:
        """Get input validation rules."""
        return self.retrieve(
            f"Input validation rules for {feature}",
            limit=8,
            category=KnowledgeCategory.VALIDATION
        )

    # =========================================================================
    # Private Methods
    # =========================================================================

    def _is_already_ingested(self, file_hash: str) -> bool:
        """Check if file was already ingested."""
        if not self._collection:
            return False

        try:
            results = self._collection.get(
                ids=["__meta__"],
                include=["metadatas"]
            )
            if results['metadatas'] and results['metadatas'][0].get('file_hash') == file_hash:
                return True
        except:
            pass

        return False

    def _parse_with_sections(self, content: str) -> List[Dict[str, Any]]:
        """
        Parse markdown with SECTION-LEVEL tracking.

        Extracts:
        - Section ID (e.g., "7.1")
        - Section Title (e.g., "Email Validation")
        - Content
        - Category
        - Tags
        """
        chunks = []
        current_section_id = "0"
        current_section_title = "General"

        # Pattern for section headers: ## 1. Title or ## 1.1 Title
        section_pattern = re.compile(r'^##\s+(\d+(?:\.\d+)?)\.\s*(.+)$', re.MULTILINE)

        # Find all sections
        sections = []
        for match in section_pattern.finditer(content):
            sections.append({
                'id': match.group(1),
                'title': match.group(2).strip(),
                'start': match.start(),
                'header_end': match.end()
            })

        # Process each section
        for i, section in enumerate(sections):
            section_id = section['id']
            section_title = section['title']

            # Store section info
            self._sections[section_id] = section_title

            # Get section content
            start = section['header_end']
            end = sections[i + 1]['start'] if i + 1 < len(sections) else len(content)
            section_content = content[start:end].strip()

            if len(section_content) < 50:
                continue

            # Detect category
            category = self._detect_category(section_title, section_content)

            # Detect page types
            page_types = self._detect_page_types(section_content)

            # Extract tags
            tags = self._extract_tags(section_title, section_content)

            # Split into smaller chunks if needed
            sub_chunks = self._split_content(section_content, max_chars=1500)

            for j, chunk_text in enumerate(sub_chunks):
                if len(chunk_text.strip()) < 30:
                    continue

                chunk_id = f"sec_{section_id}_{j}_{hashlib.md5(chunk_text.encode()).hexdigest()[:8]}"

                chunks.append({
                    'id': chunk_id,
                    'content': chunk_text,
                    'section_id': section_id,
                    'section_title': section_title,
                    'category': category,
                    'tags': ','.join(tags),
                    'page_types': ','.join(page_types)
                })

        return chunks

    def _detect_category(self, title: str, content: str) -> str:
        """Detect knowledge category."""
        combined = (title + ' ' + content).lower()

        if any(w in combined for w in ['security', 'xss', 'injection', 'csrf', 'auth', 'vulnerab']):
            return KnowledgeCategory.SECURITY.value
        if any(w in combined for w in ['validation', 'validate', 'format', 'pattern']):
            return KnowledgeCategory.VALIDATION.value
        if any(w in combined for w in ['ui', 'ux', 'usability', 'display', 'visual']):
            return KnowledgeCategory.UI_UX.value
        if any(w in combined for w in ['performance', 'speed', 'load', 'latency']):
            return KnowledgeCategory.PERFORMANCE.value
        if any(w in combined for w in ['edge', 'boundary', 'corner', 'extreme']):
            return KnowledgeCategory.EDGE_CASE.value
        if any(w in combined for w in ['api', 'endpoint', 'request', 'response']):
            return KnowledgeCategory.API.value
        if any(w in combined for w in ['accessibility', 'a11y', 'screen reader']):
            return KnowledgeCategory.ACCESSIBILITY.value
        if '```' in content:
            return KnowledgeCategory.EXAMPLE.value
        if '- [ ]' in content or 'checklist' in combined:
            return KnowledgeCategory.CHECKLIST.value

        return KnowledgeCategory.FUNCTIONAL.value

    def _detect_page_types(self, content: str) -> List[str]:
        """Detect applicable page types."""
        content_lower = content.lower()
        page_types = []

        keywords = {
            'login': ['login', 'signin', 'sign in', 'authentication'],
            'signup': ['signup', 'sign up', 'register', 'registration'],
            'checkout': ['checkout', 'payment', 'purchase', 'cart'],
            'search': ['search', 'find', 'query', 'filter'],
            'profile': ['profile', 'account', 'settings'],
            'form': ['form', 'input', 'field', 'submit'],
            'dashboard': ['dashboard', 'analytics', 'overview'],
            'admin': ['admin', 'manage', 'administrator'],
        }

        for page_type, kws in keywords.items():
            if any(kw in content_lower for kw in kws):
                page_types.append(page_type)

        return page_types if page_types else ['general']

    def _extract_tags(self, title: str, content: str) -> List[str]:
        """Extract relevant tags."""
        tags = []
        combined = (title + ' ' + content).lower()

        tag_keywords = [
            'security', 'validation', 'input', 'output', 'error',
            'session', 'auth', 'password', 'email', 'api',
            'xss', 'sql', 'csrf', 'injection', 'encryption'
        ]

        for tag in tag_keywords:
            if tag in combined:
                tags.append(tag)

        return tags[:5]

    def _split_content(self, text: str, max_chars: int = 1500) -> List[str]:
        """Split content while preserving meaning."""
        if len(text) <= max_chars:
            return [text]

        chunks = []
        paragraphs = text.split('\n\n')
        current = ""

        for para in paragraphs:
            if len(current) + len(para) + 2 <= max_chars:
                current += para + '\n\n'
            else:
                if current.strip():
                    chunks.append(current.strip())
                current = para + '\n\n'

        if current.strip():
            chunks.append(current.strip())

        return chunks

    def _add_chunks(self, chunks: List[Dict[str, Any]], file_hash: str):
        """Add chunks to ChromaDB."""
        if not chunks:
            return

        # Add metadata record
        self._collection.add(
            ids=["__meta__"],
            documents=["Metadata"],
            metadatas=[{"file_hash": file_hash, "ingested_at": datetime.now().isoformat()}]
        )

        # Add in batches
        batch_size = 50
        for i in range(0, len(chunks), batch_size):
            batch = chunks[i:i + batch_size]

            self._collection.add(
                ids=[c['id'] for c in batch],
                documents=[c['content'] for c in batch],
                metadatas=[{
                    'section_id': c['section_id'],
                    'section_title': c['section_title'],
                    'category': c['category'],
                    'tags': c['tags'],
                    'page_types': c['page_types']
                } for c in batch]
            )


def create_brain(persist_dir: str = "./.brain_data") -> QABrain:
    """Create a QABrain instance."""
    return QABrain(persist_directory=persist_dir)
