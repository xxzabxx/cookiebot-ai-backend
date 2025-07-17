"""
Compliance scanning API endpoints for CookieBot.ai application.
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
import uuid
import threading
from datetime import datetime
import logging

from ..utils.database import get_db_connection
from ..services.website_analyzer import RealWebsiteAnalyzer
from ..utils.validators import validate_url
from ..utils.error_handlers import handle_api_error

logger = logging.getLogger(__name__)

compliance_bp = Blueprint('compliance', __name__)

# Global storage for active scans
active_scans = {}


@compliance_bp.route('/real-scan', methods=['POST'])
@jwt_required()
def start_real_compliance_scan():
    """Start a real compliance scan"""
    try:
        user_id = int(get_jwt_identity())
        data = request.get_json()
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        # Validate URL format
        if not validate_url(url):
            return jsonify({'error': 'Invalid URL format'}), 400
        
        # Generate scan ID
        scan_id = str(uuid.uuid4())
        
        # Initialize scan in memory
        active_scans[scan_id] = {
            'status': 'running',
            'progress': 0,
            'results': None,
            'started_at': datetime.utcnow().isoformat(),
            'user_id': user_id
        }
        
        logger.info(f"[SCAN {scan_id}] Starting real compliance scan for URL: {url}")
        
        # Start analysis in background thread
        def run_analysis():
            try:
                analyzer = RealWebsiteAnalyzer()
                results = analyzer.analyze_website(url, scan_id)
                
                # Update scan results
                active_scans[scan_id]['status'] = 'completed'
                active_scans[scan_id]['progress'] = 100
                active_scans[scan_id]['results'] = results
                active_scans[scan_id]['completed_at'] = datetime.utcnow().isoformat()
                
                # Save to database
                conn = get_db_connection()
                if conn:
                    try:
                        cur = conn.cursor()
                        
                        # Find or create website record
                        domain = results.get('domain', '')
                        cur.execute("""
                            SELECT id FROM websites WHERE user_id = %s AND domain = %s
                        """, (user_id, domain))
                        
                        website = cur.fetchone()
                        if not website:
                            # Create website record
                            cur.execute("""
                                INSERT INTO websites (user_id, domain, status)
                                VALUES (%s, %s, 'active')
                                RETURNING id
                            """, (user_id, domain))
                            website_id = cur.fetchone()['id']
                        else:
                            website_id = website['id']
                        
                        # Save scan results
                        cur.execute("""
                            INSERT INTO compliance_scans (
                                website_id, scan_type, status, results, recommendations,
                                compliance_score, cookies_found, scripts_found, scan_url
                            )
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """, (
                            website_id, 'full_scan', 'completed', 
                            results, '\n'.join(results.get('recommendations', [])),
                            results.get('compliance_score', 0),
                            len(results.get('cookies', [])),
                            len(results.get('scripts', [])),
                            url
                        ))
                        
                        conn.commit()
                        conn.close()
                        
                    except Exception as db_error:
                        logger.error(f"[SCAN {scan_id}] Database save error: {db_error}")
                        if conn:
                            conn.close()
                
                logger.info(f"[SCAN {scan_id}] Scan completed successfully")
                
            except Exception as e:
                logger.error(f"[SCAN {scan_id}] Background analysis failed: {str(e)}")
                active_scans[scan_id]['status'] = 'error'
                active_scans[scan_id]['progress'] = 100
                active_scans[scan_id]['error'] = str(e)
        
        # Start background thread
        thread = threading.Thread(target=run_analysis)
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'scan_id': scan_id,
            'status': 'running',
            'message': 'Compliance scan started successfully'
        }), 200
        
    except Exception as e:
        return handle_api_error(e, "Failed to start compliance scan")


@compliance_bp.route('/real-scan/<scan_id>/status', methods=['GET'])
@jwt_required()
def get_real_scan_status(scan_id):
    """Get the status of a real compliance scan"""
    try:
        user_id = int(get_jwt_identity())
        
        if scan_id not in active_scans:
            return jsonify({'error': 'Scan not found'}), 404
        
        scan_data = active_scans[scan_id]
        
        # Verify ownership
        if scan_data.get('user_id') != user_id:
            return jsonify({'error': 'Access denied'}), 403
        
        response = {
            'scan_id': scan_id,
            'status': scan_data['status'],
            'progress': scan_data['progress'],
            'started_at': scan_data['started_at']
        }
        
        if scan_data['status'] == 'completed' and scan_data.get('results'):
            response['results'] = scan_data['results']
        elif scan_data['status'] == 'error':
            response['error'] = scan_data.get('error', 'Unknown error')
        
        return jsonify(response), 200
        
    except Exception as e:
        return handle_api_error(e, "Failed to get scan status")


@compliance_bp.route('/scans', methods=['GET'])
@jwt_required()
def get_compliance_scans():
    """Get user's compliance scan history"""
    try:
        user_id = int(get_jwt_identity())
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 10, type=int), 50)
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        try:
            cur = conn.cursor()
            
            # Get total count
            cur.execute("""
                SELECT COUNT(*) as total
                FROM compliance_scans cs
                JOIN websites w ON cs.website_id = w.id
                WHERE w.user_id = %s
            """, (user_id,))
            
            total = cur.fetchone()['total']
            
            # Get scans with pagination
            offset = (page - 1) * per_page
            cur.execute("""
                SELECT cs.*, w.domain
                FROM compliance_scans cs
                JOIN websites w ON cs.website_id = w.id
                WHERE w.user_id = %s
                ORDER BY cs.created_at DESC
                LIMIT %s OFFSET %s
            """, (user_id, per_page, offset))
            
            scans = cur.fetchall()
            
            return jsonify({
                'scans': [
                    {
                        'id': scan['id'],
                        'domain': scan['domain'],
                        'scan_type': scan['scan_type'],
                        'status': scan['status'],
                        'compliance_score': scan['compliance_score'],
                        'cookies_found': scan['cookies_found'],
                        'scripts_found': scan['scripts_found'],
                        'created_at': scan['created_at'].isoformat(),
                        'completed_at': scan['completed_at'].isoformat() if scan['completed_at'] else None
                    } for scan in scans
                ],
                'pagination': {
                    'page': page,
                    'per_page': per_page,
                    'total': total,
                    'pages': (total + per_page - 1) // per_page
                }
            }), 200
            
        finally:
            conn.close()
        
    except Exception as e:
        return handle_api_error(e, "Failed to get compliance scans")


@compliance_bp.route('/scans/<int:scan_id>', methods=['GET'])
@jwt_required()
def get_compliance_scan_details(scan_id):
    """Get detailed compliance scan results"""
    try:
        user_id = int(get_jwt_identity())
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        try:
            cur = conn.cursor()
            
            # Get scan details with ownership verification
            cur.execute("""
                SELECT cs.*, w.domain
                FROM compliance_scans cs
                JOIN websites w ON cs.website_id = w.id
                WHERE cs.id = %s AND w.user_id = %s
            """, (scan_id, user_id))
            
            scan = cur.fetchone()
            
            if not scan:
                return jsonify({'error': 'Scan not found'}), 404
            
            return jsonify({
                'id': scan['id'],
                'domain': scan['domain'],
                'scan_type': scan['scan_type'],
                'status': scan['status'],
                'compliance_score': scan['compliance_score'],
                'cookies_found': scan['cookies_found'],
                'scripts_found': scan['scripts_found'],
                'scan_url': scan['scan_url'],
                'results': scan['results'],
                'recommendations': scan['recommendations'],
                'error_message': scan['error_message'],
                'created_at': scan['created_at'].isoformat(),
                'completed_at': scan['completed_at'].isoformat() if scan['completed_at'] else None
            }), 200
            
        finally:
            conn.close()
        
    except Exception as e:
        return handle_api_error(e, "Failed to get scan details")


@compliance_bp.route('/health', methods=['GET'])
def compliance_health_check():
    """Health check endpoint for compliance scanner"""
    return jsonify({
        'status': 'healthy',
        'service': 'compliance-scanner',
        'timestamp': datetime.utcnow().isoformat(),
        'active_scans': len(active_scans)
    }), 200


@compliance_bp.route('/scan-website', methods=['POST'])
@jwt_required()
def scan_website():
    """Quick website scan endpoint"""
    try:
        user_id = int(get_jwt_identity())
        data = request.get_json()
        
        website_id = data.get('website_id')
        if not website_id:
            return jsonify({'error': 'Website ID is required'}), 400
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        try:
            cur = conn.cursor()
            
            # Verify website ownership
            cur.execute("""
                SELECT domain FROM websites 
                WHERE id = %s AND user_id = %s
            """, (website_id, user_id))
            
            website = cur.fetchone()
            if not website:
                return jsonify({'error': 'Website not found'}), 404
            
            # Generate scan ID and start scan
            scan_id = str(uuid.uuid4())
            url = f"https://{website['domain']}"
            
            # Create scan record
            cur.execute("""
                INSERT INTO compliance_scans (website_id, scan_type, status, scan_url)
                VALUES (%s, %s, %s, %s)
                RETURNING id
            """, (website_id, 'quick_scan', 'running', url))
            
            db_scan_id = cur.fetchone()['id']
            conn.commit()
            
            # Initialize scan in memory
            active_scans[scan_id] = {
                'status': 'running',
                'progress': 0,
                'results': None,
                'started_at': datetime.utcnow().isoformat(),
                'user_id': user_id,
                'db_scan_id': db_scan_id
            }
            
            # Start background analysis
            def run_quick_analysis():
                try:
                    analyzer = RealWebsiteAnalyzer()
                    results = analyzer.analyze_website(url, scan_id)
                    
                    # Update memory
                    active_scans[scan_id]['status'] = 'completed'
                    active_scans[scan_id]['progress'] = 100
                    active_scans[scan_id]['results'] = results
                    
                    # Update database
                    conn = get_db_connection()
                    if conn:
                        cur = conn.cursor()
                        cur.execute("""
                            UPDATE compliance_scans 
                            SET status = 'completed', results = %s, recommendations = %s,
                                compliance_score = %s, cookies_found = %s, scripts_found = %s,
                                completed_at = CURRENT_TIMESTAMP
                            WHERE id = %s
                        """, (
                            results, '\n'.join(results.get('recommendations', [])),
                            results.get('compliance_score', 0),
                            len(results.get('cookies', [])),
                            len(results.get('scripts', [])),
                            db_scan_id
                        ))
                        conn.commit()
                        conn.close()
                        
                except Exception as e:
                    logger.error(f"Quick scan error: {e}")
                    active_scans[scan_id]['status'] = 'error'
                    active_scans[scan_id]['error'] = str(e)
            
            thread = threading.Thread(target=run_quick_analysis)
            thread.daemon = True
            thread.start()
            
            return jsonify({
                'scan_id': scan_id,
                'db_scan_id': db_scan_id,
                'status': 'running',
                'message': 'Website scan started'
            }), 200
            
        finally:
            if conn:
                conn.close()
        
    except Exception as e:
        return handle_api_error(e, "Failed to start website scan")

