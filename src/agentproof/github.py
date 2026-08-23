"""Constrained retrieval of public GitHub repositories."""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import tempfile
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

GITHUB_REPO = re.compile(
    r"^https://github\.com/(?P<owner>[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/(?P<repo>[A-Za-z0-9_.-]+?)(?:\.git)?/?$"
)
MAX_ARCHIVE_BYTES = 25 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 100 * 1024 * 1024
MAX_ARCHIVE_FILES = 5_000
ALLOWED_RESPONSE_HOSTS = {"api.github.com", "codeload.github.com", "github.com"}


class GitHubFetchError(RuntimeError):
    """Raised when a public repository cannot be fetched safely."""


def parse_public_repo_url(url: str) -> tuple[str, str]:
    match = GITHUB_REPO.fullmatch(url.strip())
    if not match:
        raise GitHubFetchError("Expected a public repository URL like https://github.com/owner/repository")
    return match.group("owner"), match.group("repo")


def _headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "AgentProof/0.1",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("AGENTPROOF_GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _read_response(url: str, limit: int) -> bytes:
    request = Request(url, headers=_headers())  # noqa: S310 - URL is constructed from a validated GitHub repo
    try:
        with urlopen(request, timeout=30) as response:  # noqa: S310 - host is constructed, not user supplied
            final_url = urlparse(response.geturl())
            if final_url.scheme != "https" or final_url.hostname not in ALLOWED_RESPONSE_HOSTS:
                raise GitHubFetchError("GitHub redirected to an unapproved host")
            content_length = response.headers.get("Content-Length")
            if content_length and int(content_length) > limit:
                raise GitHubFetchError(f"Remote content exceeds the {limit // 1_048_576} MB safety limit")
            data = response.read(limit + 1)
    except HTTPError as exc:
        if exc.code == 404:
            raise GitHubFetchError("Repository was not found or is not public") from exc
        if exc.code == 403:
            raise GitHubFetchError("GitHub API rate limit reached; set AGENTPROOF_GITHUB_TOKEN") from exc
        raise GitHubFetchError(f"GitHub returned HTTP {exc.code}") from exc
    except (URLError, TimeoutError) as exc:
        raise GitHubFetchError(f"Could not reach GitHub: {exc}") from exc
    if len(data) > limit:
        raise GitHubFetchError(f"Remote content exceeds the {limit // 1_048_576} MB safety limit")
    return data


def repository_metadata(owner: str, repo: str) -> dict[str, object]:
    raw = _read_response(f"https://api.github.com/repos/{owner}/{repo}", 2 * 1024 * 1024)
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise GitHubFetchError("GitHub returned invalid repository metadata") from exc
    if not isinstance(payload, dict):
        raise GitHubFetchError("GitHub returned invalid repository metadata")
    if payload.get("private"):
        raise GitHubFetchError("The online scanner accepts public repositories only")
    return payload


def _safe_extract(archive_path: Path, destination: Path) -> Path:
    with zipfile.ZipFile(archive_path) as archive:
        members = archive.infolist()
        if len(members) > MAX_ARCHIVE_FILES:
            raise GitHubFetchError(f"Archive contains more than {MAX_ARCHIVE_FILES} files")
        total = sum(item.file_size for item in members)
        if total > MAX_UNCOMPRESSED_BYTES:
            raise GitHubFetchError("Uncompressed repository exceeds the 100 MB safety limit")

        roots: set[str] = set()
        extracted_paths: set[str] = set()
        for member in members:
            path = PurePosixPath(member.filename)
            if path.is_absolute() or ".." in path.parts:
                raise GitHubFetchError("Archive contains an unsafe path")
            if path.parts:
                roots.add(path.parts[0])
            mode = member.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise GitHubFetchError("Remote archives containing symbolic links are not accepted")
            if len(path.parts) > 1 and not member.is_dir():
                normalized = PurePosixPath(*path.parts[1:]).as_posix()
                if normalized in extracted_paths:
                    raise GitHubFetchError("Archive contains duplicate file paths")
                extracted_paths.add(normalized)

        if len(roots) != 1:
            raise GitHubFetchError("Archive does not have one repository root")
        root_name = next(iter(roots))
        for member in members:
            path = PurePosixPath(member.filename)
            if member.is_dir() or len(path.parts) <= 1:
                continue
            relative = Path(*path.parts[1:])
            output = destination / relative
            output.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member) as source, output.open("wb") as target:
                shutil.copyfileobj(source, target)
    return destination / root_name if (destination / root_name).exists() else destination


@contextmanager
def download_public_repository(url: str) -> Iterator[tuple[Path, dict[str, object]]]:
    """Download a public GitHub repository to a temporary, bounded directory."""

    owner, repo = parse_public_repo_url(url)
    metadata = repository_metadata(owner, repo)
    default_branch = str(metadata.get("default_branch") or "main")
    archive_url = f"https://api.github.com/repos/{owner}/{repo}/zipball/{default_branch}"
    data = _read_response(archive_url, MAX_ARCHIVE_BYTES)

    with tempfile.TemporaryDirectory(prefix="agentproof-") as temp:
        temp_path = Path(temp)
        archive_path = temp_path / "repository.zip"
        archive_path.write_bytes(data)
        extracted = temp_path / "repository"
        extracted.mkdir()
        _safe_extract(archive_path, extracted)
        yield (
            extracted,
            {
                "source": "github",
                "owner": owner,
                "repository": repo,
                "default_branch": default_branch,
                "html_url": metadata.get("html_url", url),
                "stars": metadata.get("stargazers_count", 0),
                "commit": None,
            },
        )
