"""
TestAI Agent - Artifact Manager

Manages test artifacts like screenshots, videos,
traces, and reports for CI/CD pipelines.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional
import hashlib
import os


class ArtifactType(Enum):
    """Types of test artifacts."""
    SCREENSHOT = "screenshot"
    VIDEO = "video"
    TRACE = "trace"
    LOG = "log"
    REPORT = "report"
    COVERAGE = "coverage"
    HAR = "har"
    JUNIT_XML = "junit_xml"
    JSON = "json"
    OTHER = "other"


class StorageBackend(Enum):
    """Storage backends for artifacts."""
    LOCAL = "local"
    S3 = "s3"
    GCS = "gcs"
    AZURE_BLOB = "azure_blob"
    ARTIFACTORY = "artifactory"


@dataclass
class TestArtifact:
    """A test artifact."""
    artifact_id: str
    name: str
    artifact_type: ArtifactType
    file_path: str
    file_size: int
    checksum: str
    test_id: Optional[str]
    run_id: Optional[str]
    created_at: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)
    url: Optional[str] = None
    retention_days: int = 30


@dataclass
class ArtifactUploadResult:
    """Result of artifact upload."""
    result_id: str
    artifact: TestArtifact
    success: bool
    storage_backend: StorageBackend
    upload_url: Optional[str]
    error: Optional[str] = None
    uploaded_at: Optional[datetime] = None


@dataclass
class ArtifactCollection:
    """A collection of related artifacts."""
    collection_id: str
    name: str
    run_id: str
    artifacts: List[TestArtifact]
    total_size: int
    created_at: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


class ArtifactManager:
    """
    Manages test artifacts.

    Features:
    - Multi-backend storage
    - Artifact organization
    - Retention policies
    - URL generation
    """

    def __init__(
        self,
        storage_backend: StorageBackend = StorageBackend.LOCAL,
        base_path: str = "./artifacts",
        retention_days: int = 30,
    ):
        """Initialize the manager."""
        self._backend = storage_backend
        self._base_path = base_path
        self._retention_days = retention_days
        self._artifacts: Dict[str, TestArtifact] = {}
        self._collections: Dict[str, ArtifactCollection] = {}
        self._artifact_counter = 0
        self._collection_counter = 0
        self._result_counter = 0

    def create_artifact(
        self,
        name: str,
        artifact_type: ArtifactType,
        file_path: str,
        file_size: Optional[int] = None,
        test_id: Optional[str] = None,
        run_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> TestArtifact:
        """Create an artifact record."""
        self._artifact_counter += 1
        artifact_id = f"ART-{self._artifact_counter:05d}"

        # Calculate size if not provided
        if file_size is None:
            file_size = self._get_file_size(file_path)

        # Calculate checksum
        checksum = self._calculate_checksum(file_path)

        artifact = TestArtifact(
            artifact_id=artifact_id,
            name=name,
            artifact_type=artifact_type,
            file_path=file_path,
            file_size=file_size,
            checksum=checksum,
            test_id=test_id,
            run_id=run_id,
            created_at=datetime.now(),
            metadata=metadata or {},
            retention_days=self._retention_days,
        )

        self._artifacts[artifact_id] = artifact
        return artifact

    def _get_file_size(self, file_path: str) -> int:
        """Get file size (simulated if file doesn't exist)."""
        try:
            return os.path.getsize(file_path)
        except OSError:
            # Simulate size for testing
            return 1024 * 10  # 10KB

    def _calculate_checksum(self, file_path: str) -> str:
        """Calculate file checksum."""
        try:
            with open(file_path, "rb") as f:
                content = f.read()
                return hashlib.sha256(content).hexdigest()
        except OSError:
            # Simulate checksum for testing
            return hashlib.sha256(file_path.encode()).hexdigest()

    def upload_artifact(
        self,
        artifact: TestArtifact,
        simulate: bool = True,
    ) -> ArtifactUploadResult:
        """Upload an artifact to storage."""
        self._result_counter += 1
        result_id = f"UPL-{self._result_counter:05d}"

        if simulate:
            # Simulated upload
            upload_url = self._generate_url(artifact)
            artifact.url = upload_url

            result = ArtifactUploadResult(
                result_id=result_id,
                artifact=artifact,
                success=True,
                storage_backend=self._backend,
                upload_url=upload_url,
                uploaded_at=datetime.now(),
            )
        else:
            # Real upload would happen here
            result = ArtifactUploadResult(
                result_id=result_id,
                artifact=artifact,
                success=False,
                storage_backend=self._backend,
                upload_url=None,
                error="Real upload not implemented",
            )

        return result

    def _generate_url(self, artifact: TestArtifact) -> str:
        """Generate URL for artifact."""
        if self._backend == StorageBackend.LOCAL:
            return f"file://{self._base_path}/{artifact.artifact_id}/{artifact.name}"
        elif self._backend == StorageBackend.S3:
            return f"https://s3.amazonaws.com/bucket/{artifact.artifact_id}/{artifact.name}"
        elif self._backend == StorageBackend.GCS:
            return f"https://storage.googleapis.com/bucket/{artifact.artifact_id}/{artifact.name}"
        else:
            return f"https://artifacts.example.com/{artifact.artifact_id}/{artifact.name}"

    def create_collection(
        self,
        name: str,
        run_id: str,
        artifact_ids: Optional[List[str]] = None,
    ) -> ArtifactCollection:
        """Create an artifact collection."""
        self._collection_counter += 1
        collection_id = f"COL-{self._collection_counter:05d}"

        artifacts = []
        if artifact_ids:
            artifacts = [
                self._artifacts[aid]
                for aid in artifact_ids
                if aid in self._artifacts
            ]

        total_size = sum(a.file_size for a in artifacts)

        collection = ArtifactCollection(
            collection_id=collection_id,
            name=name,
            run_id=run_id,
            artifacts=artifacts,
            total_size=total_size,
            created_at=datetime.now(),
        )

        self._collections[collection_id] = collection
        return collection

    def add_to_collection(
        self,
        collection_id: str,
        artifact_id: str,
    ) -> bool:
        """Add an artifact to a collection."""
        collection = self._collections.get(collection_id)
        artifact = self._artifacts.get(artifact_id)

        if not collection or not artifact:
            return False

        collection.artifacts.append(artifact)
        collection.total_size += artifact.file_size
        return True

    def get_artifact(self, artifact_id: str) -> Optional[TestArtifact]:
        """Get an artifact by ID."""
        return self._artifacts.get(artifact_id)

    def get_artifacts_for_test(self, test_id: str) -> List[TestArtifact]:
        """Get all artifacts for a test."""
        return [
            a for a in self._artifacts.values()
            if a.test_id == test_id
        ]

    def get_artifacts_for_run(self, run_id: str) -> List[TestArtifact]:
        """Get all artifacts for a run."""
        return [
            a for a in self._artifacts.values()
            if a.run_id == run_id
        ]

    def get_artifacts_by_type(
        self,
        artifact_type: ArtifactType,
    ) -> List[TestArtifact]:
        """Get artifacts by type."""
        return [
            a for a in self._artifacts.values()
            if a.artifact_type == artifact_type
        ]

    def delete_artifact(self, artifact_id: str) -> bool:
        """Delete an artifact."""
        if artifact_id in self._artifacts:
            del self._artifacts[artifact_id]
            return True
        return False

    def cleanup_expired(self) -> int:
        """Clean up expired artifacts."""
        now = datetime.now()
        expired_ids = []

        for artifact_id, artifact in self._artifacts.items():
            age_days = (now - artifact.created_at).days
            if age_days > artifact.retention_days:
                expired_ids.append(artifact_id)

        for artifact_id in expired_ids:
            del self._artifacts[artifact_id]

        return len(expired_ids)

    def get_storage_usage(self) -> Dict[str, Any]:
        """Get storage usage statistics."""
        by_type: Dict[str, int] = {}

        for artifact in self._artifacts.values():
            type_name = artifact.artifact_type.value
            by_type[type_name] = by_type.get(type_name, 0) + artifact.file_size

        total_size = sum(a.file_size for a in self._artifacts.values())

        return {
            "total_size_bytes": total_size,
            "total_size_mb": total_size / (1024 * 1024),
            "artifact_count": len(self._artifacts),
            "size_by_type": by_type,
        }

    def get_statistics(self) -> Dict[str, Any]:
        """Get manager statistics."""
        type_counts: Dict[str, int] = {}
        for artifact in self._artifacts.values():
            type_name = artifact.artifact_type.value
            type_counts[type_name] = type_counts.get(type_name, 0) + 1

        return {
            "storage_backend": self._backend.value,
            "retention_days": self._retention_days,
            "total_artifacts": len(self._artifacts),
            "total_collections": len(self._collections),
            "artifacts_by_type": type_counts,
        }

    def format_artifact(self, artifact: TestArtifact) -> str:
        """Format an artifact for display."""
        size_kb = artifact.file_size / 1024

        lines = [
            "=" * 50,
            f"  ARTIFACT: {artifact.name}",
            "=" * 50,
            "",
            f"  ID: {artifact.artifact_id}",
            f"  Type: {artifact.artifact_type.value}",
            f"  Size: {size_kb:.1f} KB",
            f"  Path: {artifact.file_path}",
            "",
            f"  Checksum: {artifact.checksum[:16]}...",
            f"  Created: {artifact.created_at.strftime('%Y-%m-%d %H:%M:%S')}",
            f"  Retention: {artifact.retention_days} days",
        ]

        if artifact.test_id:
            lines.append(f"  Test ID: {artifact.test_id}")

        if artifact.run_id:
            lines.append(f"  Run ID: {artifact.run_id}")

        if artifact.url:
            lines.append(f"  URL: {artifact.url}")

        lines.append("")
        lines.append("=" * 50)
        return "\n".join(lines)

    def format_collection(self, collection: ArtifactCollection) -> str:
        """Format a collection for display."""
        size_mb = collection.total_size / (1024 * 1024)

        lines = [
            "=" * 55,
            f"  ARTIFACT COLLECTION: {collection.name}",
            "=" * 55,
            "",
            f"  ID: {collection.collection_id}",
            f"  Run ID: {collection.run_id}",
            f"  Artifacts: {len(collection.artifacts)}",
            f"  Total Size: {size_mb:.2f} MB",
            "",
            "-" * 55,
            "  ARTIFACTS",
            "-" * 55,
            "",
        ]

        for artifact in collection.artifacts[:10]:
            lines.append(f"  • {artifact.name} ({artifact.artifact_type.value})")

        if len(collection.artifacts) > 10:
            lines.append(f"  ... and {len(collection.artifacts) - 10} more")

        lines.append("")
        lines.append("=" * 55)
        return "\n".join(lines)


def create_artifact_manager(
    storage_backend: StorageBackend = StorageBackend.LOCAL,
    base_path: str = "./artifacts",
    retention_days: int = 30,
) -> ArtifactManager:
    """Create an artifact manager instance."""
    return ArtifactManager(
        storage_backend=storage_backend,
        base_path=base_path,
        retention_days=retention_days,
    )
