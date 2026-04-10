"""
ZIP Handler — extract and identify skill files from ZIP archives.
"""

import zipfile
import io
import os

# File extensions that could be skills/agents
SKILL_EXTENSIONS = {'.md', '.txt', '.yaml', '.yml', '.json', '.toml', '.py', '.ts', '.js'}

# Files to always skip
SKIP_PATTERNS = {
    'node_modules/', '__pycache__/', '.git/', '.env', 'package-lock.json',
    'bun.lock', 'yarn.lock', '.DS_Store', 'Thumbs.db',
}

MAX_FILES = 50
MAX_TOTAL_SIZE = 10 * 1024 * 1024  # 10MB total
MAX_SINGLE_FILE = 500_000  # 500KB per file


def extract_skills_from_zip(zip_bytes: bytes) -> list[dict]:
    """
    Extract potential skill files from a ZIP archive.
    Returns list of {filename, content, size}.
    """
    results = []
    total_size = 0

    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            # Security: check for zip bomb
            total_uncompressed = sum(info.file_size for info in zf.infolist())
            if total_uncompressed > MAX_TOTAL_SIZE:
                raise ValueError(
                    f"ZIP גדול מדי ({total_uncompressed / 1024 / 1024:.1f}MB). "
                    f"מקסימום: {MAX_TOTAL_SIZE / 1024 / 1024:.0f}MB"
                )

            for info in zf.infolist():
                # Skip directories
                if info.is_dir():
                    continue

                # Skip known non-skill paths
                if any(skip in info.filename for skip in SKIP_PATTERNS):
                    continue

                # Check extension
                _, ext = os.path.splitext(info.filename.lower())
                if ext not in SKILL_EXTENSIONS:
                    continue

                # Skip huge files
                if info.file_size > MAX_SINGLE_FILE:
                    continue

                # Skip tiny files (likely not skills)
                if info.file_size < 30:
                    continue

                # Limit number of files
                if len(results) >= MAX_FILES:
                    break

                try:
                    content = zf.read(info.filename).decode('utf-8', errors='replace')
                    total_size += len(content)
                    results.append({
                        'filename': info.filename,
                        'content': content,
                        'size': info.file_size,
                    })
                except Exception:
                    continue

    except zipfile.BadZipFile:
        raise ValueError("הקובץ לא ZIP תקין")

    if not results:
        raise ValueError(
            "לא נמצאו קבצי סקיל בתוך ה-ZIP. "
            "נתמכים: .md, .txt, .yaml, .yml, .json, .py, .ts, .js"
        )

    return results
