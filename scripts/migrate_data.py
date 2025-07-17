#!/usr/bin/env python3
"""
Data migration script to migrate from the old monolithic structure to the new modular structure.
This script helps migrate existing data while maintaining data integrity.
"""
import os
import sys
import json
from pathlib import Path
from datetime import datetime

# Add the project root to the Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from app import create_app
from app.models.user import User
from app.models.website import Website
from app.models.analytics import AnalyticsEvent
from app.utils.database import db


class DataMigrator:
    """Data migration utility class."""
    
    def __init__(self):
        self.app = create_app()
        self.stats = {
            'users_migrated': 0,
            'websites_migrated': 0,
            'analytics_migrated': 0,
            'errors': []
        }
    
    def migrate_from_backup(self, backup_file_path: str):
        """Migrate data from a JSON backup file."""
        
        print(f"🔄 Starting data migration from {backup_file_path}")
        
        try:
            with open(backup_file_path, 'r') as f:
                backup_data = json.load(f)
        except Exception as e:
            print(f"❌ Failed to read backup file: {str(e)}")
            return False
        
        with self.app.app_context():
            try:
                # Start transaction
                db.session.begin()
                
                # Migrate users
                if 'users' in backup_data:
                    self._migrate_users(backup_data['users'])
                
                # Migrate websites
                if 'websites' in backup_data:
                    self._migrate_websites(backup_data['websites'])
                
                # Migrate analytics
                if 'analytics' in backup_data:
                    self._migrate_analytics(backup_data['analytics'])
                
                # Commit transaction
                db.session.commit()
                
                print("✅ Migration completed successfully!")
                self._print_stats()
                
                return True
                
            except Exception as e:
                db.session.rollback()
                print(f"❌ Migration failed: {str(e)}")
                self._print_stats()
                return False
    
    def _migrate_users(self, users_data):
        """Migrate user data."""
        
        print("👥 Migrating users...")
        
        for user_data in users_data:
            try:
                # Check if user already exists
                existing_user = User.query.filter_by(email=user_data['email']).first()
                if existing_user:
                    print(f"⚠️  User {user_data['email']} already exists, skipping")
                    continue
                
                # Create new user
                user = User(
                    email=user_data['email'],
                    password_hash=user_data.get('password_hash', ''),
                    first_name=user_data.get('first_name', 'Unknown'),
                    last_name=user_data.get('last_name', 'User'),
                    company=user_data.get('company'),
                    subscription_tier=user_data.get('subscription_tier', 'free'),
                    subscription_status=user_data.get('subscription_status', 'active'),
                    revenue_balance=user_data.get('revenue_balance', 0.0),
                    stripe_customer_id=user_data.get('stripe_customer_id'),
                    is_admin=user_data.get('is_admin', False),
                    created_at=self._parse_datetime(user_data.get('created_at')),
                    updated_at=self._parse_datetime(user_data.get('updated_at'))
                )
                
                db.session.add(user)
                db.session.flush()  # Get the ID
                
                self.stats['users_migrated'] += 1
                print(f"✅ Migrated user: {user.email}")
                
            except Exception as e:
                error_msg = f"Failed to migrate user {user_data.get('email', 'unknown')}: {str(e)}"
                self.stats['errors'].append(error_msg)
                print(f"❌ {error_msg}")
    
    def _migrate_websites(self, websites_data):
        """Migrate website data."""
        
        print("🌐 Migrating websites...")
        
        for website_data in websites_data:
            try:
                # Find user by email
                user_email = website_data.get('user_email')
                if not user_email:
                    continue
                
                user = User.query.filter_by(email=user_email).first()
                if not user:
                    error_msg = f"User {user_email} not found for website {website_data.get('domain')}"
                    self.stats['errors'].append(error_msg)
                    print(f"❌ {error_msg}")
                    continue
                
                # Check if website already exists
                existing_website = Website.query.filter_by(
                    user_id=user.id,
                    domain=website_data['domain']
                ).first()
                
                if existing_website:
                    print(f"⚠️  Website {website_data['domain']} already exists, skipping")
                    continue
                
                # Create new website
                website = Website(
                    user_id=user.id,
                    domain=website_data['domain'],
                    client_id=website_data.get('client_id', Website.generate_client_id()),
                    status=website_data.get('status', 'pending'),
                    visitors_today=website_data.get('visitors_today', 0),
                    consent_rate=website_data.get('consent_rate', 0.0),
                    revenue_today=website_data.get('revenue_today', 0.0),
                    created_at=self._parse_datetime(website_data.get('created_at')),
                    updated_at=self._parse_datetime(website_data.get('updated_at'))
                )
                
                # Generate integration code
                website.generate_integration_code()
                
                db.session.add(website)
                db.session.flush()  # Get the ID
                
                self.stats['websites_migrated'] += 1
                print(f"✅ Migrated website: {website.domain}")
                
            except Exception as e:
                error_msg = f"Failed to migrate website {website_data.get('domain', 'unknown')}: {str(e)}"
                self.stats['errors'].append(error_msg)
                print(f"❌ {error_msg}")
    
    def _migrate_analytics(self, analytics_data):
        """Migrate analytics data."""
        
        print("📊 Migrating analytics...")
        
        for event_data in analytics_data:
            try:
                # Find website by client_id or domain
                website = None
                
                if 'client_id' in event_data:
                    website = Website.query.filter_by(client_id=event_data['client_id']).first()
                elif 'website_domain' in event_data:
                    website = Website.query.filter_by(domain=event_data['website_domain']).first()
                
                if not website:
                    continue  # Skip if website not found
                
                # Create analytics event
                event = AnalyticsEvent(
                    website_id=website.id,
                    event_type=event_data.get('event_type', 'page_view'),
                    visitor_id=event_data.get('visitor_id'),
                    consent_given=event_data.get('consent_given'),
                    revenue_generated=event_data.get('revenue_generated', 0.0),
                    metadata=event_data.get('metadata', {}),
                    created_at=self._parse_datetime(event_data.get('created_at'))
                )
                
                db.session.add(event)
                
                self.stats['analytics_migrated'] += 1
                
                if self.stats['analytics_migrated'] % 1000 == 0:
                    print(f"📊 Migrated {self.stats['analytics_migrated']} analytics events...")
                
            except Exception as e:
                error_msg = f"Failed to migrate analytics event: {str(e)}"
                self.stats['errors'].append(error_msg)
    
    def _parse_datetime(self, date_string):
        """Parse datetime string to datetime object."""
        if not date_string:
            return datetime.utcnow()
        
        try:
            # Try different datetime formats
            formats = [
                '%Y-%m-%d %H:%M:%S',
                '%Y-%m-%dT%H:%M:%S',
                '%Y-%m-%dT%H:%M:%S.%f',
                '%Y-%m-%d %H:%M:%S.%f'
            ]
            
            for fmt in formats:
                try:
                    return datetime.strptime(date_string, fmt)
                except ValueError:
                    continue
            
            # If all formats fail, return current time
            return datetime.utcnow()
            
        except Exception:
            return datetime.utcnow()
    
    def _print_stats(self):
        """Print migration statistics."""
        
        print("\n📈 Migration Statistics:")
        print("=" * 30)
        print(f"Users migrated: {self.stats['users_migrated']}")
        print(f"Websites migrated: {self.stats['websites_migrated']}")
        print(f"Analytics events migrated: {self.stats['analytics_migrated']}")
        print(f"Errors encountered: {len(self.stats['errors'])}")
        
        if self.stats['errors']:
            print("\n❌ Errors:")
            for error in self.stats['errors'][:10]:  # Show first 10 errors
                print(f"  - {error}")
            
            if len(self.stats['errors']) > 10:
                print(f"  ... and {len(self.stats['errors']) - 10} more errors")
    
    def create_backup(self, output_file: str):
        """Create a backup of current data."""
        
        print(f"💾 Creating backup to {output_file}")
        
        with self.app.app_context():
            try:
                backup_data = {
                    'created_at': datetime.utcnow().isoformat(),
                    'users': [],
                    'websites': [],
                    'analytics': []
                }
                
                # Backup users
                users = User.query.all()
                for user in users:
                    backup_data['users'].append({
                        'id': user.id,
                        'email': user.email,
                        'password_hash': user.password_hash,
                        'first_name': user.first_name,
                        'last_name': user.last_name,
                        'company': user.company,
                        'subscription_tier': user.subscription_tier,
                        'subscription_status': user.subscription_status,
                        'revenue_balance': float(user.revenue_balance or 0),
                        'stripe_customer_id': user.stripe_customer_id,
                        'is_admin': user.is_admin,
                        'created_at': user.created_at.isoformat() if user.created_at else None,
                        'updated_at': user.updated_at.isoformat() if user.updated_at else None
                    })
                
                # Backup websites
                websites = Website.query.all()
                for website in websites:
                    backup_data['websites'].append({
                        'id': website.id,
                        'user_email': website.user.email,
                        'domain': website.domain,
                        'client_id': website.client_id,
                        'status': website.status,
                        'visitors_today': website.visitors_today,
                        'consent_rate': float(website.consent_rate or 0),
                        'revenue_today': float(website.revenue_today or 0),
                        'created_at': website.created_at.isoformat() if website.created_at else None,
                        'updated_at': website.updated_at.isoformat() if website.updated_at else None
                    })
                
                # Backup analytics (limit to recent data to avoid huge files)
                recent_date = datetime.utcnow() - timedelta(days=90)  # Last 90 days
                analytics = AnalyticsEvent.query.filter(
                    AnalyticsEvent.created_at >= recent_date
                ).all()
                
                for event in analytics:
                    backup_data['analytics'].append({
                        'id': event.id,
                        'website_domain': event.website.domain,
                        'client_id': event.website.client_id,
                        'event_type': event.event_type,
                        'visitor_id': event.visitor_id,
                        'consent_given': event.consent_given,
                        'revenue_generated': float(event.revenue_generated or 0),
                        'metadata': event.metadata,
                        'created_at': event.created_at.isoformat() if event.created_at else None
                    })
                
                # Write backup file
                with open(output_file, 'w') as f:
                    json.dump(backup_data, f, indent=2)
                
                print(f"✅ Backup created successfully!")
                print(f"   Users: {len(backup_data['users'])}")
                print(f"   Websites: {len(backup_data['websites'])}")
                print(f"   Analytics: {len(backup_data['analytics'])}")
                
                return True
                
            except Exception as e:
                print(f"❌ Backup failed: {str(e)}")
                return False


def main():
    """Main function."""
    
    migrator = DataMigrator()
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python migrate_data.py backup <output_file>")
        print("  python migrate_data.py migrate <backup_file>")
        return
    
    command = sys.argv[1].lower()
    
    if command == 'backup':
        if len(sys.argv) < 3:
            output_file = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        else:
            output_file = sys.argv[2]
        
        migrator.create_backup(output_file)
    
    elif command == 'migrate':
        if len(sys.argv) < 3:
            print("❌ Backup file path required")
            return
        
        backup_file = sys.argv[2]
        if not os.path.exists(backup_file):
            print(f"❌ Backup file {backup_file} not found")
            return
        
        migrator.migrate_from_backup(backup_file)
    
    else:
        print(f"❌ Unknown command: {command}")
        print("Available commands: backup, migrate")


if __name__ == '__main__':
    main()

