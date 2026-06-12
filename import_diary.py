import sys
import asyncio
sys.path.insert(0, '.')
from bucket_manager import BucketManager
from utils import load_config
from pathlib import Path

async def main():
    config = load_config()
    manager = BucketManager(config)
    file_path = sys.argv[1]
    content = Path(file_path).read_text(encoding='utf-8')
    name = Path(file_path).stem

    result = await manager.create(name=name, content=content, importance=8)
    print(f"结果: {result}")

asyncio.run(main())