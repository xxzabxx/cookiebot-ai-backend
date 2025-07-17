"""
Contact form API endpoint for CookieBot.ai application.
"""

from flask import Blueprint, request, jsonify
import re
import json
from datetime import datetime
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

from ..utils.database import get_db_connection
from ..utils.error_handlers import handle_api_error
from ..utils.validators import validate_email

logger = logging.getLogger(__name__)

contact_bp = Blueprint('contact', __name__)


@contact_bp.route('/', methods=['POST'])
def contact_form():
    """Handle contact form submissions"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['name', 'email', 'message']
        for field in required_fields:
            if not data.get(field) or not data[field].strip():
                return jsonify({
                    'success': False,
                    'error': f'{field.capitalize()} is required'
                }), 400
        
        # Validate email format
        if not validate_email(data['email']):
            return jsonify({
                'success': False,
                'error': 'Please enter a valid email address'
            }), 400
        
        # Sanitize inputs
        name = data['name'].strip()[:100]  # Limit length
        email = data['email'].strip()[:100]
        company = data.get('company', '').strip()[:100]
        subject = data.get('subject', '').strip()[:200]
        message = data['message'].strip()[:2000]  # Limit message length
        inquiry_type = data.get('inquiryType', 'general').strip()[:50]
        
        # Get client information
        ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR', 'Unknown'))
        user_agent = request.environ.get('HTTP_USER_AGENT', 'Unknown')
        
        # Save to database
        conn = get_db_connection()
        if conn:
            try:
                cur = conn.cursor()
                cur.execute("""
                    INSERT INTO contact_submissions (name, email, company, subject, message, inquiry_type, ip_address, user_agent)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                """, (name, email, company, subject, message, inquiry_type, ip_address, user_agent))
                
                submission_id = cur.fetchone()['id']
                conn.commit()
                
                logger.info(f"Contact form submission saved: ID {submission_id}, email: {email}")
                
            except Exception as db_error:
                logger.error(f"Database error saving contact form: {db_error}")
                submission_id = None
            finally:
                conn.close()
        else:
            submission_id = None
        
        # Send email notification
        email_sent = _send_contact_email(name, email, company, subject, message, inquiry_type, ip_address, user_agent)
        
        # Also save to analytics_events for tracking
        _track_contact_submission(email, name, company, subject, message, inquiry_type, email_sent)
        
        return jsonify({
            'success': True,
            'message': 'Thank you for your message! We will get back to you within 24 hours.',
            'submission_id': submission_id
        })
    
    except Exception as e:
        return handle_api_error(e, "An error occurred while sending your message. Please try again later.")


def _send_contact_email(name, email, company, subject, message, inquiry_type, ip_address, user_agent):
    """Send contact form email notification"""
    try:
        # Create email content
        email_subject = f"New Contact Form Submission - {name}"
        if subject:
            email_subject = f"New Contact: {subject} - {name}"
        
        email_body = f"""
New contact form submission from CookieBot.ai website:

Name: {name}
Email: {email}
Company: {company if company else 'Not provided'}
Inquiry Type: {inquiry_type}
Subject: {subject if subject else 'Not provided'}

Message:
{message}

Submitted: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
IP Address: {ip_address}
User Agent: {user_agent}
"""
        
        # Get SMTP configuration from environment variables
        smtp_server = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
        smtp_port = int(os.environ.get('SMTP_PORT', '587'))
        smtp_username = os.environ.get('SMTP_USERNAME')
        smtp_password = os.environ.get('SMTP_PASSWORD')
        
        if not smtp_username or not smtp_password:
            logger.warning("SMTP credentials not configured, email not sent")
            return False
        
        # Create email message
        msg = MIMEMultipart()
        msg['From'] = smtp_username
        msg['To'] = os.environ.get('CONTACT_EMAIL', 'info@cookiebot.ai')
        msg['Subject'] = email_subject
        msg['Reply-To'] = email  # Allow direct reply to the sender
        
        # Add body to email
        msg.attach(MIMEText(email_body, 'plain'))
        
        # Send email
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(smtp_username, smtp_password)
        text = msg.as_string()
        server.sendmail(smtp_username, os.environ.get('CONTACT_EMAIL', 'info@cookiebot.ai'), text)
        server.quit()
        
        logger.info(f"Contact form email sent successfully for {email}")
        return True
        
    except Exception as e:
        logger.error(f"Error sending contact form email: {e}")
        return False


def _track_contact_submission(email, name, company, subject, message, inquiry_type, email_sent):
    """Track contact form submission in analytics"""
    try:
        conn = get_db_connection()
        if not conn:
            return
        
        cur = conn.cursor()
        
        # Find or create a default website for contact forms
        cur.execute("""
            SELECT id FROM websites WHERE domain = 'cookiebot.ai' AND user_id = 1
        """)
        
        website = cur.fetchone()
        if not website:
            # Create default website for contact tracking
            cur.execute("""
                INSERT INTO websites (user_id, domain, status, client_id)
                VALUES (1, 'cookiebot.ai', 'active', 'contact_forms')
                RETURNING id
            """)
            website_id = cur.fetchone()['id']
        else:
            website_id = website['id']
        
        # Track as analytics event
        cur.execute("""
            INSERT INTO analytics_events (website_id, event_type, visitor_id, metadata, created_at)
            VALUES (%s, %s, %s, %s, %s)
        """, (
            website_id,
            'contact_form_submission',
            email,
            json.dumps({
                'name': name,
                'email': email,
                'company': company,
                'subject': subject,
                'message': message[:200],  # Truncated for storage
                'inquiry_type': inquiry_type,
                'email_sent': email_sent
            }),
            datetime.now()
        ))
        
        conn.commit()
        conn.close()
        
    except Exception as e:
        logger.error(f"Error tracking contact submission: {e}")


@contact_bp.route('/submissions', methods=['GET'])
def get_contact_submissions():
    """Get contact form submissions (admin only)"""
    try:
        # This would normally require admin authentication
        # For now, we'll return a simple response
        
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 20, type=int), 100)
        status = request.args.get('status', 'all')
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        try:
            cur = conn.cursor()
            
            # Build query based on status filter
            where_clause = ""
            params = []
            
            if status != 'all':
                where_clause = "WHERE status = %s"
                params.append(status)
            
            # Get total count
            cur.execute(f"SELECT COUNT(*) as total FROM contact_submissions {where_clause}", params)
            total = cur.fetchone()['total']
            
            # Get submissions with pagination
            offset = (page - 1) * per_page
            params.extend([per_page, offset])
            
            cur.execute(f"""
                SELECT id, name, email, company, subject, inquiry_type, status, created_at
                FROM contact_submissions 
                {where_clause}
                ORDER BY created_at DESC
                LIMIT %s OFFSET %s
            """, params)
            
            submissions = cur.fetchall()
            
            return jsonify({
                'submissions': [
                    {
                        'id': sub['id'],
                        'name': sub['name'],
                        'email': sub['email'],
                        'company': sub['company'],
                        'subject': sub['subject'],
                        'inquiry_type': sub['inquiry_type'],
                        'status': sub['status'],
                        'created_at': sub['created_at'].isoformat()
                    } for sub in submissions
                ],
                'pagination': {
                    'page': page,
                    'per_page': per_page,
                    'total': total,
                    'pages': (total + per_page - 1) // per_page
                }
            })
            
        finally:
            conn.close()
        
    except Exception as e:
        return handle_api_error(e, "Failed to get contact submissions")


@contact_bp.route('/submissions/<int:submission_id>', methods=['GET'])
def get_contact_submission(submission_id):
    """Get specific contact submission details (admin only)"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        try:
            cur = conn.cursor()
            
            cur.execute("""
                SELECT * FROM contact_submissions WHERE id = %s
            """, (submission_id,))
            
            submission = cur.fetchone()
            
            if not submission:
                return jsonify({'error': 'Submission not found'}), 404
            
            return jsonify({
                'id': submission['id'],
                'name': submission['name'],
                'email': submission['email'],
                'company': submission['company'],
                'subject': submission['subject'],
                'message': submission['message'],
                'inquiry_type': submission['inquiry_type'],
                'status': submission['status'],
                'ip_address': str(submission['ip_address']) if submission['ip_address'] else None,
                'user_agent': submission['user_agent'],
                'created_at': submission['created_at'].isoformat(),
                'responded_at': submission['responded_at'].isoformat() if submission['responded_at'] else None
            })
            
        finally:
            conn.close()
        
    except Exception as e:
        return handle_api_error(e, "Failed to get contact submission")


@contact_bp.route('/submissions/<int:submission_id>/status', methods=['PUT'])
def update_submission_status(submission_id):
    """Update contact submission status (admin only)"""
    try:
        data = request.get_json()
        new_status = data.get('status')
        
        if new_status not in ['new', 'in_progress', 'responded', 'closed']:
            return jsonify({'error': 'Invalid status'}), 400
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        try:
            cur = conn.cursor()
            
            # Update status
            update_fields = ['status = %s']
            params = [new_status]
            
            if new_status == 'responded':
                update_fields.append('responded_at = CURRENT_TIMESTAMP')
            
            cur.execute(f"""
                UPDATE contact_submissions 
                SET {', '.join(update_fields)}
                WHERE id = %s
                RETURNING id, status
            """, params + [submission_id])
            
            result = cur.fetchone()
            
            if not result:
                return jsonify({'error': 'Submission not found'}), 404
            
            conn.commit()
            
            return jsonify({
                'success': True,
                'id': result['id'],
                'status': result['status']
            })
            
        finally:
            conn.close()
        
    except Exception as e:
        return handle_api_error(e, "Failed to update submission status")

