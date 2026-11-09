"""pytest 全局配置：保证仓库根的 fi 包可导入（无论以何种方式启动 pytest）。"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
