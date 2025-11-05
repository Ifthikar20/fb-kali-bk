"""FetchBot.ai Configuration"""
from pydantic_settings import BaseSettings
from functools import lru_cache

class Settings(BaseSettings):
    # Platform
    platform_name: str = "FetchBot.ai"
    admin_email: str
    
    # Database
    database_url: str
    
    # Redis
    redis_url: str
    
    # AWS
    aws_region: str = "us-east-1"
    aws_access_key_id: str
    aws_secret_access_key: str
    aws_vpc_id: str
    aws_subnet_id: str
    aws_security_group_id: str
    aws_key_pair_name: str
    aws_s3_bucket: str
    
    # EC2 Bot Configuration
    bot_ami_id: str
    bot_instance_type: str = "t3.medium"
    
    # AI
    anthropic_api_key: str
    
    # Security
    jwt_secret: str
    
    class Config:
        env_file = ".env"

@lru_cache()
def get_settings():
    return Settings()
