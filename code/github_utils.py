import requests
import webbrowser
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
