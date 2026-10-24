"""
__main__.py — Entry point for `python -m zephyrveil`

This file allows the package to be run directly with:
    uv run python -m zephyrveil
    python -m zephyrveil
"""

from zephyrveil.main import main

if __name__ == "__main__":
    # Delegate everything to main() which handles all startup logic
    main()
