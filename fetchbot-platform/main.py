"""FetchBot.ai - Main Entry Point"""
import uvicorn
from api import app

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
    
    Starting API server...
    """)
    
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
