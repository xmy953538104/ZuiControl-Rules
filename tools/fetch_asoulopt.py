"""Resolve fresh official metadata; download only a size/digest-bound release asset."""
import hashlib
import io
import json
import os
from pathlib import PurePosixPath
import re
import urllib.parse
import urllib.request
import zipfile

REPO = "nakixii/Magisk_AsoulOpt"
METADATA_URL = f"https://raw.githubusercontent.com/{REPO}/main/AsoulOpt.json"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_url(url, limit):
    headers = {"User-Agent": "ZuiControl-Rules-Lab/1", "Cache-Control": "no-cache"}
    if urllib.parse.urlsplit(url).hostname == "api.github.com" and os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = "Bearer " + os.environ["GITHUB_TOKEN"]
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=45) as response:
        data = response.read(limit + 1)
    require(len(data) <= limit, "HTTP body exceeds bound")
    return data


def resolve():
    raw = read_url(METADATA_URL, 65536)
    metadata = json.loads(raw)
    require(isinstance(metadata.get("versionCode"), int) and metadata["versionCode"] > 0,
            "invalid versionCode")
    require(isinstance(metadata.get("version"), str) and 0 < len(metadata["version"]) < 128,
            "invalid version")
    url = metadata["zipUrl"]
    parts = urllib.parse.urlsplit(url)
    prefix = f"/{REPO}/releases/download/"
    require(parts.scheme == "https" and parts.netloc == "github.com" and
            parts.path.startswith(prefix) and not parts.query and not parts.fragment,
            "asset URL is not the official release namespace")
    rest = parts.path[len(prefix):].split("/")
    require(len(rest) == 2 and all(rest), "invalid release URL")
    tag, name = map(urllib.parse.unquote, rest)
    release = json.loads(read_url(f"https://api.github.com/repos/{REPO}/releases/tags/"
                                 + urllib.parse.quote(tag, safe=""), 1048576))
    require(release["tag_name"] == tag and not release.get("draft"), "release tag mismatch/draft")
    assets = [a for a in release["assets"] if a["name"] == name]
    require(len(assets) == 1, "release asset missing/ambiguous")
    asset = assets[0]
    require(asset["browser_download_url"] == url and 0 < asset["size"] <= 4 * 1024 * 1024,
            "release asset URL/size mismatch")
    digest = asset.get("digest")
    require(digest is None or re.fullmatch(r"sha256:[0-9a-f]{64}", digest),
            "unknown asset digest format")
    commit = json.loads(read_url(f"https://api.github.com/repos/{REPO}/commits/main", 1048576))["sha"]
    pinned = read_url(f"https://raw.githubusercontent.com/{REPO}/{commit}/AsoulOpt.json", 65536)
    require(json.loads(pinned) == metadata and json.loads(read_url(METADATA_URL, 65536)) == metadata,
            "metadata changed during resolution; retry with fresh input")
    return dict(metadata_url=METADATA_URL, metadata_sha256=sha256(raw), repository=REPO,
                metadata_commit=commit, version=metadata["version"], version_code=metadata["versionCode"],
                tag=tag, zip_url=url, asset_name=name, asset_size=asset["size"],
                upstream_digest=digest, release_id=release["id"], asset_id=asset["id"],
                release_published_at=release["published_at"])


def identity(meta):
    return {k: meta[k] for k in ("version", "version_code", "tag", "zip_url", "asset_name",
                               "asset_size", "asset_id", "release_id", "upstream_digest",
                               "release_published_at")}


def unpack_module(data, meta):
    require(len(data) == meta["asset_size"], "download size mismatch")
    digest = sha256(data)
    require(meta["upstream_digest"] is None or "sha256:" + digest == meta["upstream_digest"],
            "download SHA256 mismatch")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        require(len(entries) <= 200 and sum(e.file_size for e in entries) <= 16 * 1024 * 1024,
                "archive exceeds entry/expanded bounds")
        names = [e.filename for e in entries]
        require(len(names) == len(set(names)), "duplicate ZIP paths")
        for entry in entries:
            path = PurePosixPath(entry.filename)
            require(not path.is_absolute() and ".." not in path.parts and
                    "\\" not in entry.filename and ":" not in entry.filename,
                    "unsafe ZIP path")
            require((entry.external_attr >> 16) & 0o170000 != 0o120000, "ZIP symlink rejected")
            require(entry.file_size <= 4 * 1024 * 1024 and not entry.flag_bits & 1,
                    "oversized/encrypted ZIP entry")
        require(names.count("AsoulOpt") == 1 and names.count("module.prop") == 1,
                "expected root ELF/module.prop missing")
        binary = archive.read("AsoulOpt")
        prop = dict(line.split("=", 1) for line in archive.read("module.prop").decode("utf8").splitlines()
                    if "=" in line and not line.startswith("#"))
        require(prop.get("version") == meta["version"] and
                prop.get("versionCode") == str(meta["version_code"]) and
                prop.get("updateJson") in (METADATA_URL, f"https://github.com/{REPO}/raw/main/AsoulOpt.json"),
                "module.prop disagrees with official metadata")
    return binary, digest


def download(meta):
    data = read_url(meta["zip_url"], 4 * 1024 * 1024)
    binary, digest = unpack_module(data, meta)
    readme = read_url(f"https://raw.githubusercontent.com/{REPO}/{meta['metadata_commit']}/README.md", 524288)
    packages = [line.strip() for line in readme.decode("utf8").splitlines()
                if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+", line.strip())]
    return binary, dict(meta, download_sha256=digest, binary_sha256=sha256(binary),
                        readme_sha256=sha256(readme)), packages
