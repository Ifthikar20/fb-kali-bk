#!/usr/bin/env python3
"""
Create admin user for FetchBot.ai
"""
from models import get_db, Organization, User
import secrets

# Generate slug from name
def generate_slug(name):
    return name.lower().replace(" ", "-").replace(".", "")

db = next(get_db())

print("Creating admin user...")
print("=" * 50)

# Create organization
org = Organization(
    name="Test Organization",
    slug=generate_slug("Test Organization"),
    admin_email="admin@fetchbot.ai",
    elastic_ip="127.0.0.1",  # Dummy IP for local testing
    active=True,
    max_concurrent_scans=5
)
db.add(org)
db.commit()
db.refresh(org)

print(f"✅ Created organization: {org.name}")
print(f"   ID: {org.id}")
print(f"   API Key: {org.api_key}")
print()

# Create admin user
user = User(
    username="admin",
    email="admin@fetchbot.ai",
    organization_id=org.id,
    full_name="Admin User",
    is_admin=True,
    active=True
)
user.set_password("admin123")  # Uses the model's set_password method

db.add(user)
db.commit()
db.refresh(user)

print(f"✅ Created user: {user.username}")
print(f"   Email: {user.email}")
print(f"   ID: {user.id}")
print()
print("=" * 50)
print()
print("Login Credentials:")
print(f"  Username: admin")
print(f"  Password: admin123")
print()
print("You can now log in to the platform!")
print()
