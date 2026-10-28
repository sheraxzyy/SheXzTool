"""File Integrity Monitor (FIM) Module for SheXzTool.

Attributed to developer brand: SheRaXzy Sentinel.
Computes SHA-256 hashes, maintains cryptographic baselines, detects modifications,
and enforces read-only safety with zero file alteration.
"""

from __future__ import annotations
import datetime
import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from shexztool.core.models import FimComparisonResult
from shexztool.core.validator import Validator

logger = logging.getLogger("shexztool.fim")

DEFAULT_IGNORED_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".idea", ".vscode"}
DEFAULT_IGNORED_EXTS = {".tmp", ".bak", ".log", ".swp"}


class FileIntegrityMonitor:
    """Manages cryptographic baselines and detects file modifications safely."""

    def __init__(self, baselines_dir: Optional[Path] = None):
        self.baselines_dir = baselines_dir or (Path(__file__).resolve().parent.parent.parent / "baselines")
        self.baselines_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def compute_sha256(file_path: Path, chunk_size: int = 65536) -> Optional[str]:
        """Compute SHA-256 hash of a file using buffered streaming.

        Returns None if file cannot be read.
        """
        try:
            hasher = hashlib.sha256()
            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    hasher.update(chunk)
            return hasher.hexdigest()
        except (PermissionError, FileNotFoundError, OSError) as e:
            logger.debug("Failed to hash %s: %s", file_path, e)
            return None

    def scan_path(
        self,
        target_path: Path,
        ignored_dirs: Optional[set[str]] = None,
        ignored_exts: Optional[set[str]] = None,
        on_progress: Optional[Callable[[int, str], None]] = None,
    ) -> Tuple[Dict[str, Dict[str, Any]], List[str]]:
        """Compute hashes for target file or directory tree.

        Guarantees:
        - NEVER follows symbolic links or junctions (prevents loops and external traversal).
        - NEVER modifies, writes to, or deletes scanned files.
        """
        target_path = target_path.resolve()
        ign_dirs = ignored_dirs if ignored_dirs is not None else DEFAULT_IGNORED_DIRS
        ign_exts = ignored_exts if ignored_exts is not None else DEFAULT_IGNORED_EXTS

        file_records: Dict[str, Dict[str, Any]] = {}
        errors: List[str] = []
        count = 0

        if target_path.is_file():
            # Check extension
            if target_path.suffix.lower() not in ign_exts:
                digest = self.compute_sha256(target_path)
                if digest:
                    stat = target_path.stat()
                    file_records[str(target_path)] = {
                        "sha256": digest,
                        "size_bytes": stat.st_size,
                        "mtime": stat.st_mtime,
                    }
                else:
                    errors.append(f"Permission denied or unreadable: {target_path}")
            return file_records, errors

        # Traverse directory
        for root, dirs, files in os.walk(str(target_path), followlinks=False):
            # In-place filter out ignored directory names so os.walk skips them
            dirs[:] = [d for d in dirs if d.lower() not in ign_dirs and not os.path.islink(os.path.join(root, d))]

            for fname in files:
                f_path = Path(root) / fname
                # Skip symlinks/junctions
                if f_path.is_symlink():
                    continue

                if f_path.suffix.lower() in ign_exts:
                    continue

                try:
                    rel_path = str(f_path.relative_to(target_path))
                    digest = self.compute_sha256(f_path)
                    if digest:
                        stat = f_path.stat()
                        file_records[rel_path] = {
                            "sha256": digest,
                            "size_bytes": stat.st_size,
                            "mtime": stat.st_mtime,
                        }
                        count += 1
                        if on_progress:
                            on_progress(count, rel_path)
                    else:
                        errors.append(f"Unreadable file: {f_path}")
                except Exception as e:
                    errors.append(f"Error accessing {f_path}: {e}")

        return file_records, errors

    def create_baseline(
        self,
        target_path: Path,
        baseline_name: Optional[str] = None,
        on_progress: Optional[Callable[[int, str], None]] = None,
    ) -> Tuple[Path, Dict[str, Any]]:
        """Generate a baseline JSON file recording cryptographic hashes of all files."""
        target_path = target_path.resolve()
        if not target_path.exists():
            raise FileNotFoundError(f"Target path does not exist: {target_path}")

        records, errors = self.scan_path(target_path, on_progress=on_progress)

        clean_name = Validator.sanitize_filename(baseline_name or f"baseline_{target_path.name}")
        timestamp_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        full_baseline_filename = f"{clean_name}_{timestamp_str}.json"
        dest_file = self.baselines_dir / full_baseline_filename

        payload = {
            "version": "1.0",
            "tool": "SheXzTool (SheRaXzy Sentinel)",
            "baseline_name": clean_name,
            "created_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "root_path": str(target_path),
            "is_single_file": target_path.is_file(),
            "algorithm": "sha256",
            "security_disclaimer": (
                "IMPORTANT: A cryptographic baseline establishes a trusted reference point. "
                "It is only as trustworthy as the system was when this baseline was created. "
                "Any subsequent deviation flags modifications, additions, or deletions."
            ),
            "total_files": len(records),
            "files": records,
            "errors": errors,
        }

        with open(dest_file, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

        logger.info("Saved baseline with %d files to %s", len(records), dest_file)
        return dest_file, payload

    def compare_baseline(
        self,
        baseline_path: Path,
        on_progress: Optional[Callable[[int, str], None]] = None,
    ) -> FimComparisonResult:
        """Compare current state of files against a recorded baseline."""
        baseline_path = Path(baseline_path).resolve()
        if not baseline_path.exists():
            raise FileNotFoundError(f"Baseline file not found: {baseline_path}")

        with open(baseline_path, "r", encoding="utf-8") as f:
            baseline_data = json.load(f)

        root_path_str = baseline_data.get("root_path")
        if not root_path_str:
            raise ValueError("Corrupted baseline: missing root_path.")

        root_path = Path(root_path_str)
        if not root_path.exists():
            raise FileNotFoundError(f"Monitored root path does not exist: {root_path}")

        baseline_files: Dict[str, Dict[str, Any]] = baseline_data.get("files", {})
        current_records, current_errors = self.scan_path(root_path, on_progress=on_progress)

        new_files: List[str] = []
        modified_files: List[Dict[str, str]] = []
        missing_files: List[str] = []
        unchanged_count = 0

        # Check files in current scan against baseline
        for curr_rel, curr_meta in current_records.items():
            if curr_rel not in baseline_files:
                new_files.append(curr_rel)
            else:
                base_meta = baseline_files[curr_rel]
                if curr_meta["sha256"] != base_meta["sha256"]:
                    modified_files.append({
                        "path": curr_rel,
                        "old_hash": base_meta["sha256"],
                        "new_hash": curr_meta["sha256"],
                        "old_size": str(base_meta.get("size_bytes", "N/A")),
                        "new_size": str(curr_meta.get("size_bytes", "N/A")),
                    })
                else:
                    unchanged_count += 1

        # Check for missing files (present in baseline, but absent now)
        for base_rel in baseline_files.keys():
            if base_rel not in current_records:
                missing_files.append(base_rel)

        new_files.sort()
        modified_files.sort(key=lambda x: x["path"])
        missing_files.sort()

        scan_ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return FimComparisonResult(
            root_path=str(root_path),
            baseline_timestamp=baseline_data.get("created_at", "Unknown"),
            scan_timestamp=scan_ts,
            new_files=new_files,
            modified_files=modified_files,
            missing_files=missing_files,
            unchanged_count=unchanged_count,
            errors=current_errors,
        )

    def list_baselines(self) -> List[Dict[str, Any]]:
        """List all saved baseline files in baselines directory."""
        items: List[Dict[str, Any]] = []
        if not self.baselines_dir.exists():
            return items

        for f in self.baselines_dir.glob("*.json"):
            try:
                with open(f, "r", encoding="utf-8") as fp:
                    data = json.load(fp)
                    items.append({
                        "file_path": str(f),
                        "filename": f.name,
                        "baseline_name": data.get("baseline_name", f.stem),
                        "created_at": data.get("created_at", "Unknown"),
                        "root_path": data.get("root_path", "Unknown"),
                        "total_files": data.get("total_files", 0),
                    })
            except Exception as e:
                logger.debug("Failed to read baseline %s: %s", f, e)

        items.sort(key=lambda x: x["created_at"], reverse=True)
        return items
