#!/usr/bin/env python3
"""
Script to create an admin user for CookieBot.ai application.
Addresses the missing admin user creation mechanism identified in the review.
"""
import os
import sys
import getpass
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from app import create_app
from app.models.user import User
from app.utils.database import db


def create_admin_user():
    """Create an admin user interactively."""
    
    print("🔧 CookieBot.ai Admin User Creation")
    print("=" * 40)
    
    # Get user input
    email = input("Admin email: ").strip()
    if not email:
        print("❌ Email is required")
        return False
    
    # Get password securely
    while True:
        password = getpass.getpass("Admin password: ")
        if len(password) < 8:
            print("❌ Password must be at least 8 characters long")
            continue
        
        confirm_password = getpass.getpass("Confirm password: ")
        if password != confirm_password:
            print("❌ Passwords do not match")
            continue
        
        break
    
    first_name = input("First name: ").strip() or "Admin"
    last_name = input("Last name: ").strip() or "User"
    company = input("Company (optional): ").strip() or None
    
    # Create Flask app and database context
    app = create_app()
    
    with app.app_context():
        try:
            # Check if admin already exists
            existing_admin = User.query.filter_by(email=email).first()
            if existing_admin:
                print(f"❌ User with email {email} already exists")
                
                # Ask if they want to make existing user admin
                make_admin = input("Make this user an admin? (y/N): ").strip().lower()
                if make_admin == 'y':
                    existing_admin.is_admin = True
                    db.session.commit()
                    print(f"✅ User {email} is now an admin")
                    return True
                else:
                    return False
            
            # Create new admin user
            admin_user = User.create_user(
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name,
                company=company
            )
            
            # Make user admin
            admin_user.is_admin = True
            admin_user.subscription_tier = 'enterprise'  # Give admin enterprise access
            
            db.session.commit()
            
            print(f"✅ Admin user created successfully!")
            print(f"   Email: {email}")
            print(f"   Name: {first_name} {last_name}")
            print(f"   Admin: Yes")
            print(f"   Subscription: Enterprise")
            
            return True
            
        except Exception as e:
            print(f"❌ Failed to create admin user: {str(e)}")
            db.session.rollback()
            return False


def list_admin_users():
    """List all admin users."""
    
    app = create_app()
    
    with app.app_context():
        try:
            admin_users = User.query.filter_by(is_admin=True).all()
            
            if not admin_users:
                print("No admin users found.")
                return
            
            print("\n👑 Admin Users:")
            print("-" * 50)
            
            for user in admin_users:
                print(f"ID: {user.id}")
                print(f"Email: {user.email}")
                print(f"Name: {user.first_name} {user.last_name}")
                print(f"Created: {user.created_at}")
                print(f"Last Login: {user.last_login_at or 'Never'}")
                print("-" * 50)
                
        except Exception as e:
            print(f"❌ Failed to list admin users: {str(e)}")


def remove_admin_privileges():
    """Remove admin privileges from a user."""
    
    email = input("Email of user to remove admin privileges: ").strip()
    if not email:
        print("❌ Email is required")
        return False
    
    app = create_app()
    
    with app.app_context():
        try:
            user = User.query.filter_by(email=email).first()
            
            if not user:
                print(f"❌ User with email {email} not found")
                return False
            
            if not user.is_admin:
                print(f"❌ User {email} is not an admin")
                return False
            
            # Confirm removal
            confirm = input(f"Remove admin privileges from {email}? (y/N): ").strip().lower()
            if confirm != 'y':
                print("❌ Operation cancelled")
                return False
            
            user.is_admin = False
            db.session.commit()
            
            print(f"✅ Admin privileges removed from {email}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to remove admin privileges: {str(e)}")
            db.session.rollback()
            return False


def main():
    """Main function with menu."""
    
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == 'create':
            create_admin_user()
        elif command == 'list':
            list_admin_users()
        elif command == 'remove':
            remove_admin_privileges()
        else:
            print(f"❌ Unknown command: {command}")
            print("Available commands: create, list, remove")
    else:
        # Interactive menu
        while True:
            print("\n🔧 CookieBot.ai Admin Management")
            print("=" * 35)
            print("1. Create admin user")
            print("2. List admin users")
            print("3. Remove admin privileges")
            print("4. Exit")
            
            choice = input("\nSelect option (1-4): ").strip()
            
            if choice == '1':
                create_admin_user()
            elif choice == '2':
                list_admin_users()
            elif choice == '3':
                remove_admin_privileges()
            elif choice == '4':
                print("👋 Goodbye!")
                break
            else:
                print("❌ Invalid choice. Please select 1-4.")


if __name__ == '__main__':
    main()

