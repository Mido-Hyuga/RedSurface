#!/usr/bin/env python3
"""
RedSurface - Attack Surface Intelligence Platform
Web Interface Entry Point
"""

import sys
import logging
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from utils.logger import setup_logger

def main():
    logger = setup_logger()
    logger.info("Initializing RedSurface Web Interface...")
    
    try:
        import uvicorn
        from app import create_app
        
        # We need to instantiate the app at module level for uvicorn to find it if run via "uvicorn main:app"
        # Wait, the best way for programmatic uvicorn is to pass the instance, 
        # or the factory string "app:create_app" with factory=True
        
        logger.info("  [*] Web Interface: http://127.0.0.1:5000")
        logger.info("  [*] API Docs:      http://127.0.0.1:5000/docs\n")
        
        # Using factory string is safer for reloading and workers
        uvicorn.run("app:create_app", host="0.0.0.0", port=5000, log_level="info", factory=True)
    except ImportError as e:
        logger.error(f"Failed to import dependencies: {e}")
        logger.error("Make sure all dependencies are installed: pip install -r requirements.txt")
        return 1
    except Exception as e:
        logger.error(f"Failed to start web server: {e}")
        return 1
        
    return 0

if __name__ == "__main__":
    sys.exit(main())
