import requests
import webbrowser
from pathlib import Path
from typing import Optional


def get_latest_github_release(owner: str, repo: str) -> Optional[str]:
    """Return the latest release tag from a GitHub repository."""
    url = f"https://api.github.com/repos/{owner}/{repo}/releases/latest"
    try:
        resp = requests.get(url, timeout=5)
        resp.raise_for_status()
        data = resp.json()

        return data.get("tag_name")
    except requests.RequestException:

        return None


def open_latest_build_webpage(owner: str, repo: str):
    url = f"https://github.com/{owner}/{repo}/releases/latest"
    webbrowser.open(url)

def download_file(url: str, destination: Path) -> None:
    r = requests.get(url, stream=True)
    r.raise_for_status()
    with open(destination, "wb") as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)

def get_release_asset_url(owner: str, repo: str, asset_name: str):
    url = f"https://api.github.com/repos/{owner}/{repo}/releases/latest"
    r = requests.get(url, timeout=5)
    r.raise_for_status()
    data = r.json()
    tag = data.get("tag_name")
    assets = data.get("assets")
    asset_name = asset_name.replace("VERSIONTAG", tag)
    print(asset_name)
    for asset in assets:
        if asset_name in asset["name"]:
            return asset["browser_download_url"]
    return None
