"""FetchBot.ai AWS EC2 Manager"""
import boto3
from typing import Dict
from config import get_settings

settings = get_settings()

class AWSManager:
    def __init__(self):
        self.ec2_client = boto3.client(
            'ec2',
            region_name=settings.aws_region,
            aws_access_key_id=settings.aws_access_key_id,
            aws_secret_access_key=settings.aws_secret_access_key
        )
        self.s3_client = boto3.client(
            's3',
            region_name=settings.aws_region,
            aws_access_key_id=settings.aws_access_key_id,
            aws_secret_access_key=settings.aws_secret_access_key
        )
    
    def create_organization_infrastructure(self, org_name: str, org_id: str) -> Dict:
        """Create dedicated EC2 instance and Elastic IP"""
        print(f"[AWS] Creating infrastructure for {org_name}...")
        
        # Allocate Elastic IP
        eip_response = self.ec2_client.allocate_address(Domain='vpc')
        elastic_ip = eip_response['PublicIp']
        allocation_id = eip_response['AllocationId']
        print(f"[AWS] ✓ Allocated Elastic IP: {elastic_ip}")
        
        # Create EC2 instance
        user_data = self._generate_user_data(org_name, org_id)
        
        instance_response = self.ec2_client.run_instances(
            ImageId=settings.bot_ami_id,
            InstanceType=settings.bot_instance_type,
            KeyName=settings.aws_key_pair_name,
            MinCount=1,
            MaxCount=1,
            NetworkInterfaces=[{
                'SubnetId': settings.aws_subnet_id,
                'DeviceIndex': 0,
                'AssociatePublicIpAddress': True,
                'Groups': [settings.aws_security_group_id]
            }],
            UserData=user_data,
            TagSpecifications=[{
                'ResourceType': 'instance',
                'Tags': [
                    {'Key': 'Name', 'Value': f'fetchbot-{org_name}'},
                    {'Key': 'Organization', 'Value': org_name},
                    {'Key': 'Platform', 'Value': 'FetchBot.ai'}
                ]
            }]
        )
        
        instance_id = instance_response['Instances'][0]['InstanceId']
        print(f"[AWS] ✓ Launched instance: {instance_id}")
        
        # Wait for instance
        print(f"[AWS] Waiting for instance to start...")
        waiter = self.ec2_client.get_waiter('instance_running')
        waiter.wait(InstanceIds=[instance_id])
        
        # Associate Elastic IP
        self.ec2_client.associate_address(
            InstanceId=instance_id,
            AllocationId=allocation_id
        )
        print(f"[AWS] ✓ Associated {elastic_ip} with {instance_id}")
        
        return {
            'instance_id': instance_id,
            'elastic_ip': elastic_ip,
            'allocation_id': allocation_id
        }
    
    def _generate_user_data(self, org_name: str, org_id: str) -> str:
        """Generate EC2 user data script"""
        return f"""#!/bin/bash
set -e
echo "FetchBot.ai Bot Instance Setup"
apt-get update
apt-get install -y docker.io docker-compose
systemctl start docker
mkdir -p /opt/fetchbot
echo "Bots ready for {org_name}"
"""
    
    def stop_organization_instance(self, instance_id: str):
        """Stop EC2 instance"""
        self.ec2_client.stop_instances(InstanceIds=[instance_id])
    
    def start_organization_instance(self, instance_id: str):
        """Start EC2 instance"""
        self.ec2_client.start_instances(InstanceIds=[instance_id])
        waiter = self.ec2_client.get_waiter('instance_running')
        waiter.wait(InstanceIds=[instance_id])
    
    def get_instance_status(self, instance_id: str) -> Dict:
        """Get EC2 instance status"""
        response = self.ec2_client.describe_instances(InstanceIds=[instance_id])
        instance = response['Reservations'][0]['Instances'][0]
        return {
            'state': instance['State']['Name'],
            'public_ip': instance.get('PublicIpAddress'),
            'private_ip': instance.get('PrivateIpAddress')
        }
