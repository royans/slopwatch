"""Enable `python -m slopwatch` as an alias for the `slopwatch` console script.

Useful when the console script's install location (e.g. `~/.local/bin` for a
`pip install --user`) is not on `PATH`.
"""

from slopwatch.cli import main

if __name__ == "__main__":
    main()
