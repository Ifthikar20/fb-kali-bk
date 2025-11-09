"""FetchBot.ai Configuration"""
from pydantic_settings import BaseSettings
from functools import lru_cache
from typing import Optional

class Settings(BaseSettings):
    # Platform
    platform_name: str = "FetchBot.ai"
    admin_email: str = "admin@fetchbot.ai"

    # Database
    database_url: str

    # Redis
    redis_url: str

    # AWS (Optional - only needed for EC2 deployment)
    aws_region: str = "us-east-1"
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    aws_vpc_id: Optional[str] = None
    aws_subnet_id: Optional[str] = None
    aws_security_group_id: Optional[str] = None
    aws_key_pair_name: Optional[str] = None
    aws_s3_bucket: Optional[str] = None

    # EC2 Bot Configuration
    bot_ami_id: Optional[str] = None
    bot_instance_type: str = "t3.medium"

    # AI (Required for Claude orchestration)
    anthropic_api_key: str

    # Orchestrator Configuration
    use_dynamic_agents: bool = False
    num_kali_agents: Optional[int] = None

    # Security
    jwt_secret: str = "dev_secret_change_in_production"

    class Config:
        env_file = ".env"

@lru_cache()
def get_settings():
    return Settings()
