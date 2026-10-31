from __future__ import annotations

import json
import os
from pathlib import Path
from threading import RLock
from typing import Any

from pydantic import ValidationError

from app.schemas.kb_schema import KnowledgeBaseDocument


class KnowledgeBaseLoadError(RuntimeError):
    """Raised when the configured knowledge base cannot be loaded or validated."""


class KnowledgeBaseRepository:
    """Loads and process-caches a validated knowledge base document."""

    def __init__(
        self,
        backend: str | None = None,
        file_path: Path | None = None,
        mongo_uri: str | None = None,
        mongo_database: str | None = None,
        mongo_collection: str | None = None,
    ) -> None:
        self.backend = (backend or os.getenv("KB_BACKEND", "file")).strip().lower()
        self.file_path = file_path or Path(__file__).resolve().parents[1] / "data" / "rule_store.json"
        self.mongo_uri = mongo_uri or os.getenv("MONGODB_URI")
        self.mongo_database = mongo_database or os.getenv(
            "MONGODB_DATABASE", "ai_risk_assessment"
        )
        self.mongo_collection = mongo_collection or os.getenv(
            "MONGODB_COLLECTION", "rule_store"
        )
        self._cached_document: KnowledgeBaseDocument | None = None
        self._lock = RLock()

    def get_knowledge_base(self) -> KnowledgeBaseDocument:
        with self._lock:
            if self._cached_document is None:
                raw_document = self._read_source()
                try:
                    self._cached_document = KnowledgeBaseDocument.model_validate(
                        raw_document
                    )
                except ValidationError as exc:
                    raise KnowledgeBaseLoadError(
                        "The configured knowledge base does not match its schema."
                    ) from exc
            return self._cached_document

    def refresh(self) -> KnowledgeBaseDocument:
        """Reload and validate the source, replacing the cache only on success."""
        with self._lock:
            raw_document = self._read_source()
            try:
                refreshed = KnowledgeBaseDocument.model_validate(raw_document)
            except ValidationError as exc:
                raise KnowledgeBaseLoadError(
                    "The configured knowledge base does not match its schema."
                ) from exc
            self._cached_document = refreshed
            return refreshed

    def _read_source(self) -> dict[str, Any]:
        if self.backend == "file":
            return self._read_file()
        if self.backend == "mongodb":
            return self._read_mongodb()
        raise KnowledgeBaseLoadError(
            f"Unsupported KB_BACKEND value: {self.backend!r}."
        )

    def _read_file(self) -> dict[str, Any]:
        try:
            with self.file_path.open("r", encoding="utf-8") as file:
                document = json.load(file)
        except (OSError, json.JSONDecodeError) as exc:
            raise KnowledgeBaseLoadError(
                f"Unable to read knowledge base file: {self.file_path}."
            ) from exc
        if not isinstance(document, dict):
            raise KnowledgeBaseLoadError(
                "The knowledge base JSON root must be an object."
            )
        return document

    def _read_mongodb(self) -> dict[str, Any]:
        if not self.mongo_uri:
            raise KnowledgeBaseLoadError(
                "MONGODB_URI must be set when KB_BACKEND=mongodb."
            )
        try:
            from pymongo import MongoClient
        except ImportError as exc:
            raise KnowledgeBaseLoadError(
                "MongoDB mode requires the pymongo package."
            ) from exc

        try:
            with MongoClient(self.mongo_uri, serverSelectionTimeoutMS=5000) as client:
                collection = client[self.mongo_database][self.mongo_collection]
                document = collection.find_one({"_id": "rule_store"})
                if document is None:
                    document_count = collection.count_documents({}, limit=2)
                    if document_count == 1:
                        document = collection.find_one()
                    elif document_count > 1:
                        raise KnowledgeBaseLoadError(
                            "MongoDB collection has multiple documents and none has "
                            "_id='rule_store'."
                        )
        except KnowledgeBaseLoadError:
            raise
        except Exception as exc:
            raise KnowledgeBaseLoadError(
                "Unable to retrieve the knowledge base from MongoDB."
            ) from exc

        if document is None:
            raise KnowledgeBaseLoadError(
                f"MongoDB collection {self.mongo_collection!r} contains no KB document."
            )
        payload = document.get("data", document)
        if not isinstance(payload, dict):
            raise KnowledgeBaseLoadError(
                "The MongoDB knowledge base document must contain an object."
            )
        return {key: value for key, value in payload.items() if key != "_id"}
