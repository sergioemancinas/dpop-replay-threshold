"""Put this directory on sys.path so `import pipeline` works from a bare pytest run.

The parent directory name contains a hyphen, so it cannot be a package and the
usual rootdir-relative import does not apply.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
