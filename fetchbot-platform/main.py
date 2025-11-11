"""FetchBot.ai - Main Entry Point"""
import uvicorn
import logging
from api import app

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

if __name__ == "__main__":
    print("""
    ╔══════════════════════════════════════════════════════════╗
    ║                                                          ║
    ║                    FetchBot.ai v1.0                      ║
    ║         AI-Powered Multi-Tenant Pentest Platform         ║
    ║                                                          ║
    ║    Each organization gets dedicated AWS EC2 + IP         ║
    ║                                                          ║
    ╚══════════════════════════════════════════════════════════╝
    """)
    
    uvicorn.run(app, host="0.0.0.0", port=8001, log_level="info")
