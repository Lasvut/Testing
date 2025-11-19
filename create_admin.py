#!/usr/bin/env python3
"""
Create default admin user for WAF system
Usage: python3 create_admin.py
"""

from database import init_db, create_user, get_all_users

def main():
    print("="*70)
    print("WAF System - User Creation")
    print("="*70)

    # Initialize database
    print("\n[1/3] Initializing database...")
    init_db()
    print("✓ Database initialized")

    # Check existing users
    print("\n[2/3] Checking for existing users...")
    users = get_all_users()

    if users:
        print(f"✓ Found {len(users)} existing user(s):")
        for user in users:
            print(f"   - {user['username']} (created: {user['created_at']})")
        print("\n⚠️  Users already exist. Skipping default user creation.")
    else:
        print("✓ No users found")

        # Create default admin user
        print("\n[3/3] Creating default admin user...")
        username = "admin"
        password = "admin123"

        try:
            create_user(username, password)
            print("✓ Default admin user created successfully!")
            print("\n" + "="*70)
            print("LOGIN CREDENTIALS")
            print("="*70)
            print(f"Username: {username}")
            print(f"Password: {password}")
            print("="*70)
            print("\n⚠️  IMPORTANT: Please change this password after logging in!")
            print("   Go to User Management page to create additional users.")
        except Exception as e:
            print(f"✗ Error creating user: {e}")
            return 1

    print("\n" + "="*70)
    print("✓ Setup complete! You can now run: python3 app.py")
    print("="*70 + "\n")
    return 0

if __name__ == "__main__":
    exit(main())
