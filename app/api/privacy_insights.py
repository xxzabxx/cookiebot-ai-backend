"""
Privacy Insights API endpoints for CookieBot.ai application.
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
import json
import time
from datetime import datetime
import logging

from ..utils.database import get_db_connection
from ..utils.error_handlers import handle_api_error

logger = logging.getLogger(__name__)

privacy_insights_bp = Blueprint('privacy_insights', __name__)


@privacy_insights_bp.route('/', methods=['POST'])
def get_privacy_insights():
    """Get privacy insights content for the widget"""
    try:
        data = request.get_json()
        client_id = data.get('clientId')
        domain = data.get('domain')
        language = data.get('language', 'en')
        context = data.get('context', {})
        
        if not client_id:
            return jsonify({'error': 'Client ID required'}), 400
        
        # Get language code
        lang_code = language.split('-')[0] if language else 'en'
        
        conn = get_db_connection()
        if not conn:
            # Fallback to static content if database unavailable
            return jsonify(_get_fallback_insights(lang_code))
        
        try:
            cur = conn.cursor()
            
            # Get insights from database
            cur.execute("""
                SELECT insight_id, title, description, category, cpc
                FROM privacy_insights 
                WHERE language = %s AND active = TRUE
                ORDER BY RANDOM()
                LIMIT 6
            """, (lang_code,))
            
            insights = cur.fetchall()
            
            if not insights:
                # Fallback to English if no insights in requested language
                cur.execute("""
                    SELECT insight_id, title, description, category, cpc
                    FROM privacy_insights 
                    WHERE language = 'en' AND active = TRUE
                    ORDER BY RANDOM()
                    LIMIT 6
                """)
                insights = cur.fetchall()
            
            # Convert to response format
            response_insights = []
            for insight in insights:
                response_insights.append({
                    'id': insight['insight_id'],
                    'title': insight['title'],
                    'description': insight['description'],
                    'category': insight['category'],
                    'sponsored': True,
                    'cpc': float(insight['cpc'])
                })
            
            # Log the request
            logger.info(f"Privacy insights requested for client {client_id}, domain {domain}, language {lang_code}")
            
            return jsonify(response_insights)
            
        finally:
            conn.close()
        
    except Exception as e:
        logger.error(f"Error getting privacy insights: {str(e)}")
        # Return fallback content on error
        lang_code = request.get_json().get('language', 'en').split('-')[0]
        return jsonify(_get_fallback_insights(lang_code))


@privacy_insights_bp.route('/click', methods=['POST'])
def track_privacy_insight_click():
    """Track privacy insight clicks for revenue sharing"""
    try:
        data = request.get_json()
        client_id = data.get('clientId')
        insight_id = data.get('insightId')
        domain = data.get('domain')
        timestamp = data.get('timestamp')
        revenue_share = data.get('revenueShare', 0.6)  # Default 60% to website owner
        
        if not all([client_id, insight_id, domain]):
            return jsonify({'error': 'Missing required fields'}), 400
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        try:
            cur = conn.cursor()
            
            # Get insight CPC
            cur.execute("""
                SELECT cpc FROM privacy_insights WHERE insight_id = %s
            """, (insight_id,))
            
            insight = cur.fetchone()
            base_revenue = float(insight['cpc']) if insight else 0.15
            
            website_owner_revenue = base_revenue * revenue_share
            platform_revenue = base_revenue * (1 - revenue_share)
            
            # Find website by client_id
            cur.execute("""
                SELECT id, user_id FROM websites WHERE client_id = %s
            """, (client_id,))
            
            website = cur.fetchone()
            
            if website:
                website_id = website['id']
                user_id = website['user_id']
                
                # Store the click event in analytics_events table
                cur.execute("""
                    INSERT INTO analytics_events (website_id, event_type, visitor_id, consent_given, revenue_generated, metadata, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (
                    website_id,
                    'privacy_insight_click',
                    f"privacy_insight_{insight_id}_{int(time.time())}",
                    True,
                    website_owner_revenue,
                    json.dumps({
                        'insight_id': insight_id,
                        'domain': domain,
                        'base_revenue': base_revenue,
                        'revenue_share': revenue_share,
                        'platform_revenue': platform_revenue
                    }),
                    timestamp or datetime.utcnow()
                ))
                
                # Update user's revenue balance
                cur.execute("""
                    UPDATE users 
                    SET revenue_balance = COALESCE(revenue_balance, 0) + %s
                    WHERE id = %s
                """, (website_owner_revenue, user_id))
                
                # Update website's daily revenue
                cur.execute("""
                    UPDATE websites 
                    SET revenue_today = revenue_today + %s
                    WHERE id = %s
                """, (website_owner_revenue, website_id))
                
            else:
                # Create a basic website record for unregistered domains
                cur.execute("""
                    INSERT INTO websites (user_id, domain, client_id, status)
                    VALUES (%s, %s, %s, %s)
                    RETURNING id
                """, (1, domain, client_id, 'unregistered'))  # Default user ID for unregistered
                
                website_id = cur.fetchone()['id']
                
                # Store the event
                cur.execute("""
                    INSERT INTO analytics_events (website_id, event_type, visitor_id, consent_given, revenue_generated, metadata, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (
                    website_id,
                    'privacy_insight_click',
                    f"privacy_insight_{insight_id}_{int(time.time())}",
                    True,
                    0.0,  # No revenue for unregistered websites
                    json.dumps({
                        'insight_id': insight_id,
                        'domain': domain,
                        'unregistered': True
                    }),
                    timestamp or datetime.utcnow()
                ))
            
            conn.commit()
            
            logger.info(f"Privacy insight click tracked: {insight_id} for client {client_id}, revenue: ${website_owner_revenue:.4f}")
            
            return jsonify({
                'success': True,
                'revenue': website_owner_revenue,
                'insight_id': insight_id,
                'timestamp': timestamp
            })
            
        finally:
            conn.close()
        
    except Exception as e:
        return handle_api_error(e, "Failed to track privacy insight click")


@privacy_insights_bp.route('/stats', methods=['GET'])
@jwt_required()
def get_privacy_insights_stats():
    """Get privacy insights statistics for dashboard"""
    try:
        current_user_id = int(get_jwt_identity())
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        try:
            cur = conn.cursor()
            
            # Get total privacy insight clicks and revenue
            cur.execute("""
                SELECT 
                    COUNT(*) as total_clicks,
                    COALESCE(SUM(revenue_generated), 0) as total_revenue,
                    COUNT(DISTINCT DATE(created_at)) as active_days
                FROM analytics_events ae
                JOIN websites w ON ae.website_id = w.id
                WHERE w.user_id = %s 
                AND ae.event_type = 'privacy_insight_click'
                AND ae.created_at >= NOW() - INTERVAL '30 days'
            """, (current_user_id,))
            
            stats = cur.fetchone()
            
            # Get daily breakdown for the last 7 days
            cur.execute("""
                SELECT 
                    DATE(created_at) as date,
                    COUNT(*) as clicks,
                    COALESCE(SUM(revenue_generated), 0) as revenue
                FROM analytics_events ae
                JOIN websites w ON ae.website_id = w.id
                WHERE w.user_id = %s 
                AND ae.event_type = 'privacy_insight_click'
                AND ae.created_at >= NOW() - INTERVAL '7 days'
                GROUP BY DATE(created_at)
                ORDER BY date DESC
            """, (current_user_id,))
            
            daily_stats = cur.fetchall()
            
            # Get top performing insights
            cur.execute("""
                SELECT 
                    ae.metadata->>'insight_id' as insight_id,
                    COUNT(*) as clicks,
                    COALESCE(SUM(revenue_generated), 0) as revenue
                FROM analytics_events ae
                JOIN websites w ON ae.website_id = w.id
                WHERE w.user_id = %s 
                AND ae.event_type = 'privacy_insight_click'
                AND ae.created_at >= NOW() - INTERVAL '30 days'
                GROUP BY ae.metadata->>'insight_id'
                ORDER BY revenue DESC
                LIMIT 5
            """, (current_user_id,))
            
            top_insights = cur.fetchall()
            
            return jsonify({
                'total_clicks': stats['total_clicks'] if stats else 0,
                'total_revenue': float(stats['total_revenue']) if stats else 0.0,
                'active_days': stats['active_days'] if stats else 0,
                'daily_stats': [
                    {
                        'date': str(row['date']),
                        'clicks': row['clicks'],
                        'revenue': float(row['revenue'])
                    } for row in daily_stats
                ],
                'top_insights': [
                    {
                        'insight_id': row['insight_id'],
                        'clicks': row['clicks'],
                        'revenue': float(row['revenue'])
                    } for row in top_insights
                ]
            })
            
        finally:
            conn.close()
        
    except Exception as e:
        return handle_api_error(e, "Failed to get privacy insights stats")


@privacy_insights_bp.route('/config', methods=['GET', 'POST'])
@jwt_required()
def privacy_insights_config():
    """Get or update privacy insights configuration for a website"""
    try:
        current_user_id = int(get_jwt_identity())
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        try:
            if request.method == 'GET':
                website_id = request.args.get('website_id')
                if not website_id:
                    return jsonify({'error': 'Website ID required'}), 400
                
                cur = conn.cursor()
                cur.execute("""
                    SELECT integration_code, domain, status
                    FROM websites 
                    WHERE id = %s AND user_id = %s
                """, (website_id, current_user_id))
                
                website = cur.fetchone()
                if not website:
                    return jsonify({'error': 'Website not found'}), 404
                
                # Default privacy insights configuration
                config = {
                    'enabled': True,
                    'widget_delay': 3000,  # 3 seconds
                    'widget_duration': 15000,  # 15 seconds
                    'revenue_share': 0.6,  # 60% to website owner
                    'language': 'auto',
                    'categories': ['security', 'privacy'],
                    'frequency': 'medium',  # low, medium, high
                    'position': 'bottom-right'
                }
                
                return jsonify({
                    'website': {
                        'id': website_id,
                        'domain': website['domain'],
                        'integration_code': website['integration_code'],
                        'status': website['status']
                    },
                    'privacy_insights_config': config
                })
            
            elif request.method == 'POST':
                data = request.get_json()
                website_id = data.get('website_id')
                config = data.get('config', {})
                
                if not website_id:
                    return jsonify({'error': 'Website ID required'}), 400
                
                # Validate website ownership
                cur = conn.cursor()
                cur.execute("""
                    SELECT id FROM websites 
                    WHERE id = %s AND user_id = %s
                """, (website_id, current_user_id))
                
                if not cur.fetchone():
                    return jsonify({'error': 'Website not found'}), 404
                
                # Store configuration in user_dashboard_configs or website-specific table
                # For now, we'll log the configuration
                logger.info(f"Privacy insights config updated for website {website_id}: {config}")
                
                return jsonify({
                    'success': True,
                    'message': 'Privacy insights configuration updated',
                    'config': config
                })
                
        finally:
            conn.close()
            
    except Exception as e:
        return handle_api_error(e, "Failed to handle privacy insights config")


def _get_fallback_insights(lang_code: str):
    """Get fallback privacy insights when database is unavailable"""
    insights_library = {
        'en': [
            {
                'id': 'password-security',
                'title': 'Strengthen Your Password Security',
                'description': 'Use unique passwords for each account and enable two-factor authentication to protect your personal data.',
                'category': 'security',
                'sponsored': True,
                'cpc': 0.15
            },
            {
                'id': 'privacy-settings',
                'title': 'Review Your Social Media Privacy',
                'description': 'Check your privacy settings on social platforms to control who can see your personal information.',
                'category': 'privacy',
                'sponsored': True,
                'cpc': 0.12
            },
            {
                'id': 'data-backup',
                'title': 'Backup Your Important Data',
                'description': 'Regular backups protect against data loss from cyber attacks, hardware failure, or accidental deletion.',
                'category': 'security',
                'sponsored': True,
                'cpc': 0.18
            },
            {
                'id': 'browser-privacy',
                'title': 'Enhance Your Browser Privacy',
                'description': 'Use private browsing mode and clear cookies regularly to reduce online tracking.',
                'category': 'privacy',
                'sponsored': True,
                'cpc': 0.14
            },
            {
                'id': 'wifi-security',
                'title': 'Secure Your WiFi Connection',
                'description': 'Avoid public WiFi for sensitive activities and use a VPN to encrypt your internet connection.',
                'category': 'security',
                'sponsored': True,
                'cpc': 0.20
            },
            {
                'id': 'email-protection',
                'title': 'Protect Your Email Privacy',
                'description': 'Be cautious with email attachments and links, and use encrypted email services when possible.',
                'category': 'privacy',
                'sponsored': True,
                'cpc': 0.16
            }
        ],
        'es': [
            {
                'id': 'password-security',
                'title': 'Fortalece la Seguridad de tus Contraseñas',
                'description': 'Usa contraseñas únicas para cada cuenta y activa la autenticación de dos factores.',
                'category': 'security',
                'sponsored': True,
                'cpc': 0.15
            },
            {
                'id': 'privacy-settings',
                'title': 'Revisa tu Privacidad en Redes Sociales',
                'description': 'Verifica la configuración de privacidad en plataformas sociales para controlar quién ve tu información.',
                'category': 'privacy',
                'sponsored': True,
                'cpc': 0.12
            }
        ],
        'fr': [
            {
                'id': 'password-security',
                'title': 'Renforcez la Sécurité de vos Mots de Passe',
                'description': 'Utilisez des mots de passe uniques et activez l\'authentification à deux facteurs.',
                'category': 'security',
                'sponsored': True,
                'cpc': 0.15
            },
            {
                'id': 'privacy-settings',
                'title': 'Vérifiez vos Paramètres de Confidentialité',
                'description': 'Contrôlez vos paramètres de confidentialité sur les réseaux sociaux pour protéger vos informations.',
                'category': 'privacy',
                'sponsored': True,
                'cpc': 0.12
            }
        ]
    }
    
    return insights_library.get(lang_code, insights_library['en'])

