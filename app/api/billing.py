"""
Billing and subscription API endpoints for CookieBot.ai application.
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
import stripe
import os
import json
from datetime import datetime, timedelta
import logging

from ..utils.database import get_db_connection
from ..utils.error_handlers import handle_api_error

logger = logging.getLogger(__name__)

# Configure Stripe
stripe.api_key = os.environ.get('STRIPE_SECRET_KEY')

billing_bp = Blueprint('billing', __name__)


@billing_bp.route('/plans', methods=['GET'])
def get_subscription_plans():
    """Get available subscription plans"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        try:
            cur = conn.cursor()
            cur.execute("""
                SELECT * FROM subscription_plans 
                WHERE active = TRUE 
                ORDER BY sort_order, monthly_price
            """)
            
            plans = cur.fetchall()
            
            return jsonify({
                'plans': [
                    {
                        'id': plan['id'],
                        'name': plan['name'],
                        'display_name': plan['display_name'],
                        'description': plan['description'],
                        'monthly_price': float(plan['monthly_price']),
                        'yearly_price': float(plan['yearly_price']) if plan['yearly_price'] else None,
                        'website_limit': plan['website_limit'],
                        'api_call_limit': plan['api_call_limit'],
                        'support_ticket_limit': plan['support_ticket_limit'],
                        'revenue_share': float(plan['revenue_share']),
                        'features': plan['features'],
                        'stripe_price_id': plan['stripe_price_id'],
                        'stripe_yearly_price_id': plan['stripe_yearly_price_id']
                    } for plan in plans
                ]
            })
            
        finally:
            conn.close()
        
    except Exception as e:
        return handle_api_error(e, "Failed to get subscription plans")


@billing_bp.route('/subscribe', methods=['POST'])
@jwt_required()
def create_subscription():
    """Create a new subscription"""
    try:
        current_user_id = int(get_jwt_identity())
        data = request.get_json()
        
        plan_name = data.get('plan')
        billing_cycle = data.get('billing_cycle', 'monthly')  # monthly or yearly
        payment_method_id = data.get('payment_method_id')
        
        if not all([plan_name, payment_method_id]):
            return jsonify({'error': 'Plan and payment method required'}), 400
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        try:
            cur = conn.cursor()
            
            # Get user and plan details
            cur.execute("SELECT * FROM users WHERE id = %s", (current_user_id,))
            user = cur.fetchone()
            
            cur.execute("SELECT * FROM subscription_plans WHERE name = %s", (plan_name,))
            plan = cur.fetchone()
            
            if not user or not plan:
                return jsonify({'error': 'User or plan not found'}), 404
            
            # Get or create Stripe customer
            stripe_customer_id = user['stripe_customer_id']
            if not stripe_customer_id:
                customer = stripe.Customer.create(
                    email=user['email'],
                    name=f"{user['first_name']} {user['last_name']}".strip(),
                    metadata={'user_id': current_user_id}
                )
                stripe_customer_id = customer.id
                
                # Update user with Stripe customer ID
                cur.execute("""
                    UPDATE users SET stripe_customer_id = %s WHERE id = %s
                """, (stripe_customer_id, current_user_id))
            
            # Attach payment method to customer
            stripe.PaymentMethod.attach(
                payment_method_id,
                customer=stripe_customer_id
            )
            
            # Set as default payment method
            stripe.Customer.modify(
                stripe_customer_id,
                invoice_settings={'default_payment_method': payment_method_id}
            )
            
            # Determine price ID based on billing cycle
            if billing_cycle == 'yearly' and plan['stripe_yearly_price_id']:
                price_id = plan['stripe_yearly_price_id']
            else:
                price_id = plan['stripe_price_id']
            
            if not price_id:
                return jsonify({'error': 'Price not configured for this plan'}), 400
            
            # Create subscription
            subscription = stripe.Subscription.create(
                customer=stripe_customer_id,
                items=[{'price': price_id}],
                payment_behavior='default_incomplete',
                expand=['latest_invoice.payment_intent'],
                metadata={
                    'user_id': current_user_id,
                    'plan_name': plan_name,
                    'billing_cycle': billing_cycle
                }
            )
            
            # Update user subscription info
            cur.execute("""
                UPDATE users 
                SET subscription_tier = %s, 
                    subscription_status = %s,
                    subscription_started_at = %s,
                    stripe_subscription_id = %s
                WHERE id = %s
            """, (
                plan_name,
                subscription.status,
                datetime.utcnow(),
                subscription.id,
                current_user_id
            ))
            
            # Log subscription event
            cur.execute("""
                INSERT INTO subscription_events (user_id, event_type, to_plan, amount, currency, stripe_subscription_id)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                current_user_id,
                'subscription_created',
                plan_name,
                plan['monthly_price'] if billing_cycle == 'monthly' else plan['yearly_price'],
                'USD',
                subscription.id
            ))
            
            conn.commit()
            
            return jsonify({
                'subscription_id': subscription.id,
                'client_secret': subscription.latest_invoice.payment_intent.client_secret,
                'status': subscription.status
            })
            
        finally:
            conn.close()
        
    except stripe.error.StripeError as e:
        logger.error(f"Stripe error: {e}")
        return jsonify({'error': f'Payment error: {str(e)}'}), 400
    except Exception as e:
        return handle_api_error(e, "Failed to create subscription")


@billing_bp.route('/subscription', methods=['GET'])
@jwt_required()
def get_current_subscription():
    """Get current user's subscription details"""
    try:
        current_user_id = int(get_jwt_identity())
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        try:
            cur = conn.cursor()
            
            # Get user subscription info
            cur.execute("""
                SELECT u.*, sp.display_name, sp.description, sp.monthly_price, sp.yearly_price,
                       sp.website_limit, sp.api_call_limit, sp.support_ticket_limit, sp.revenue_share, sp.features
                FROM users u
                LEFT JOIN subscription_plans sp ON u.subscription_tier = sp.name
                WHERE u.id = %s
            """, (current_user_id,))
            
            user = cur.fetchone()
            
            if not user:
                return jsonify({'error': 'User not found'}), 404
            
            # Get usage for current month
            current_month = datetime.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            cur.execute("""
                SELECT * FROM usage_tracking 
                WHERE user_id = %s AND month = %s
            """, (current_user_id, current_month))
            
            usage = cur.fetchone()
            
            # Get recent subscription events
            cur.execute("""
                SELECT * FROM subscription_events 
                WHERE user_id = %s 
                ORDER BY created_at DESC 
                LIMIT 5
            """, (current_user_id,))
            
            events = cur.fetchall()
            
            subscription_data = {
                'tier': user['subscription_tier'],
                'status': user['subscription_status'],
                'started_at': user['subscription_started_at'].isoformat() if user['subscription_started_at'] else None,
                'stripe_subscription_id': user['stripe_subscription_id'],
                'plan': {
                    'name': user['subscription_tier'],
                    'display_name': user['display_name'],
                    'description': user['description'],
                    'monthly_price': float(user['monthly_price']) if user['monthly_price'] else 0,
                    'yearly_price': float(user['yearly_price']) if user['yearly_price'] else None,
                    'website_limit': user['website_limit'],
                    'api_call_limit': user['api_call_limit'],
                    'support_ticket_limit': user['support_ticket_limit'],
                    'revenue_share': float(user['revenue_share']) if user['revenue_share'] else 0.6,
                    'features': user['features'] or []
                },
                'usage': {
                    'api_calls': usage['api_calls'] if usage else 0,
                    'websites_created': usage['websites_created'] if usage else 0,
                    'support_tickets': usage['support_tickets'] if usage else 0,
                    'compliance_scans': usage['compliance_scans'] if usage else 0,
                    'privacy_insights_clicks': usage['privacy_insights_clicks'] if usage else 0
                },
                'recent_events': [
                    {
                        'event_type': event['event_type'],
                        'from_plan': event['from_plan'],
                        'to_plan': event['to_plan'],
                        'amount': float(event['amount']) if event['amount'] else None,
                        'created_at': event['created_at'].isoformat()
                    } for event in events
                ]
            }
            
            return jsonify(subscription_data)
            
        finally:
            conn.close()
        
    except Exception as e:
        return handle_api_error(e, "Failed to get subscription details")


@billing_bp.route('/subscription/cancel', methods=['POST'])
@jwt_required()
def cancel_subscription():
    """Cancel current subscription"""
    try:
        current_user_id = int(get_jwt_identity())
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        try:
            cur = conn.cursor()
            
            # Get user's subscription
            cur.execute("""
                SELECT stripe_subscription_id, subscription_tier 
                FROM users WHERE id = %s
            """, (current_user_id,))
            
            user = cur.fetchone()
            
            if not user or not user['stripe_subscription_id']:
                return jsonify({'error': 'No active subscription found'}), 404
            
            # Cancel subscription in Stripe
            subscription = stripe.Subscription.modify(
                user['stripe_subscription_id'],
                cancel_at_period_end=True
            )
            
            # Update user status
            cur.execute("""
                UPDATE users 
                SET subscription_status = 'cancelled'
                WHERE id = %s
            """, (current_user_id,))
            
            # Log cancellation event
            cur.execute("""
                INSERT INTO subscription_events (user_id, event_type, from_plan, stripe_subscription_id)
                VALUES (%s, %s, %s, %s)
            """, (
                current_user_id,
                'subscription_cancelled',
                user['subscription_tier'],
                user['stripe_subscription_id']
            ))
            
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': 'Subscription cancelled successfully',
                'cancel_at_period_end': subscription.cancel_at_period_end,
                'current_period_end': subscription.current_period_end
            })
            
        finally:
            conn.close()
        
    except stripe.error.StripeError as e:
        logger.error(f"Stripe error: {e}")
        return jsonify({'error': f'Payment error: {str(e)}'}), 400
    except Exception as e:
        return handle_api_error(e, "Failed to cancel subscription")


@billing_bp.route('/payment-methods', methods=['GET'])
@jwt_required()
def get_payment_methods():
    """Get user's payment methods"""
    try:
        current_user_id = int(get_jwt_identity())
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        try:
            cur = conn.cursor()
            
            # Get user's Stripe customer ID
            cur.execute("SELECT stripe_customer_id FROM users WHERE id = %s", (current_user_id,))
            user = cur.fetchone()
            
            if not user or not user['stripe_customer_id']:
                return jsonify({'payment_methods': []})
            
            # Get payment methods from Stripe
            payment_methods = stripe.PaymentMethod.list(
                customer=user['stripe_customer_id'],
                type='card'
            )
            
            return jsonify({
                'payment_methods': [
                    {
                        'id': pm.id,
                        'type': pm.type,
                        'card': {
                            'brand': pm.card.brand,
                            'last4': pm.card.last4,
                            'exp_month': pm.card.exp_month,
                            'exp_year': pm.card.exp_year
                        }
                    } for pm in payment_methods.data
                ]
            })
            
        finally:
            conn.close()
        
    except stripe.error.StripeError as e:
        logger.error(f"Stripe error: {e}")
        return jsonify({'error': f'Payment error: {str(e)}'}), 400
    except Exception as e:
        return handle_api_error(e, "Failed to get payment methods")


@billing_bp.route('/invoices', methods=['GET'])
@jwt_required()
def get_invoices():
    """Get user's billing invoices"""
    try:
        current_user_id = int(get_jwt_identity())
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        try:
            cur = conn.cursor()
            
            # Get user's Stripe customer ID
            cur.execute("SELECT stripe_customer_id FROM users WHERE id = %s", (current_user_id,))
            user = cur.fetchone()
            
            if not user or not user['stripe_customer_id']:
                return jsonify({'invoices': []})
            
            # Get invoices from Stripe
            invoices = stripe.Invoice.list(
                customer=user['stripe_customer_id'],
                limit=20
            )
            
            return jsonify({
                'invoices': [
                    {
                        'id': invoice.id,
                        'amount_paid': invoice.amount_paid / 100,  # Convert from cents
                        'amount_due': invoice.amount_due / 100,
                        'currency': invoice.currency,
                        'status': invoice.status,
                        'created': invoice.created,
                        'due_date': invoice.due_date,
                        'invoice_pdf': invoice.invoice_pdf,
                        'hosted_invoice_url': invoice.hosted_invoice_url
                    } for invoice in invoices.data
                ]
            })
            
        finally:
            conn.close()
        
    except stripe.error.StripeError as e:
        logger.error(f"Stripe error: {e}")
        return jsonify({'error': f'Payment error: {str(e)}'}), 400
    except Exception as e:
        return handle_api_error(e, "Failed to get invoices")


@billing_bp.route('/webhook', methods=['POST'])
def stripe_webhook():
    """Handle Stripe webhooks"""
    try:
        payload = request.get_data()
        sig_header = request.environ.get('HTTP_STRIPE_SIGNATURE')
        endpoint_secret = os.environ.get('STRIPE_WEBHOOK_SECRET')
        
        if not endpoint_secret:
            logger.error("Stripe webhook secret not configured")
            return jsonify({'error': 'Webhook not configured'}), 400
        
        try:
            event = stripe.Webhook.construct_event(payload, sig_header, endpoint_secret)
        except ValueError:
            logger.error("Invalid payload in Stripe webhook")
            return jsonify({'error': 'Invalid payload'}), 400
        except stripe.error.SignatureVerificationError:
            logger.error("Invalid signature in Stripe webhook")
            return jsonify({'error': 'Invalid signature'}), 400
        
        # Handle the event
        if event['type'] == 'invoice.payment_succeeded':
            _handle_payment_succeeded(event['data']['object'])
        elif event['type'] == 'invoice.payment_failed':
            _handle_payment_failed(event['data']['object'])
        elif event['type'] == 'customer.subscription.updated':
            _handle_subscription_updated(event['data']['object'])
        elif event['type'] == 'customer.subscription.deleted':
            _handle_subscription_deleted(event['data']['object'])
        else:
            logger.info(f"Unhandled Stripe webhook event: {event['type']}")
        
        return jsonify({'success': True})
        
    except Exception as e:
        logger.error(f"Stripe webhook error: {e}")
        return jsonify({'error': 'Webhook processing failed'}), 500


def _handle_payment_succeeded(invoice):
    """Handle successful payment"""
    try:
        customer_id = invoice['customer']
        subscription_id = invoice['subscription']
        
        conn = get_db_connection()
        if not conn:
            return
        
        cur = conn.cursor()
        
        # Find user by Stripe customer ID
        cur.execute("""
            SELECT id, subscription_tier FROM users 
            WHERE stripe_customer_id = %s
        """, (customer_id,))
        
        user = cur.fetchone()
        if not user:
            logger.error(f"User not found for Stripe customer {customer_id}")
            return
        
        # Update subscription status
        cur.execute("""
            UPDATE users 
            SET subscription_status = 'active', payment_failed_at = NULL
            WHERE id = %s
        """, (user['id'],))
        
        # Log payment event
        cur.execute("""
            INSERT INTO subscription_events (user_id, event_type, to_plan, amount, currency, stripe_subscription_id)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            user['id'],
            'payment_succeeded',
            user['subscription_tier'],
            invoice['amount_paid'] / 100,
            invoice['currency'],
            subscription_id
        ))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Payment succeeded for user {user['id']}")
        
    except Exception as e:
        logger.error(f"Error handling payment succeeded: {e}")


def _handle_payment_failed(invoice):
    """Handle failed payment"""
    try:
        customer_id = invoice['customer']
        
        conn = get_db_connection()
        if not conn:
            return
        
        cur = conn.cursor()
        
        # Find user by Stripe customer ID
        cur.execute("""
            SELECT id, subscription_tier FROM users 
            WHERE stripe_customer_id = %s
        """, (customer_id,))
        
        user = cur.fetchone()
        if not user:
            return
        
        # Update subscription status
        cur.execute("""
            UPDATE users 
            SET subscription_status = 'past_due', payment_failed_at = CURRENT_TIMESTAMP
            WHERE id = %s
        """, (user['id'],))
        
        # Log payment failure event
        cur.execute("""
            INSERT INTO subscription_events (user_id, event_type, from_plan, stripe_subscription_id)
            VALUES (%s, %s, %s, %s)
        """, (
            user['id'],
            'payment_failed',
            user['subscription_tier'],
            invoice['subscription']
        ))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Payment failed for user {user['id']}")
        
    except Exception as e:
        logger.error(f"Error handling payment failed: {e}")


def _handle_subscription_updated(subscription):
    """Handle subscription updates"""
    try:
        customer_id = subscription['customer']
        
        conn = get_db_connection()
        if not conn:
            return
        
        cur = conn.cursor()
        
        # Find user by Stripe customer ID
        cur.execute("""
            SELECT id FROM users WHERE stripe_customer_id = %s
        """, (customer_id,))
        
        user = cur.fetchone()
        if not user:
            return
        
        # Update subscription status
        cur.execute("""
            UPDATE users 
            SET subscription_status = %s
            WHERE id = %s
        """, (subscription['status'], user['id']))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Subscription updated for user {user['id']}: {subscription['status']}")
        
    except Exception as e:
        logger.error(f"Error handling subscription updated: {e}")


def _handle_subscription_deleted(subscription):
    """Handle subscription deletion"""
    try:
        customer_id = subscription['customer']
        
        conn = get_db_connection()
        if not conn:
            return
        
        cur = conn.cursor()
        
        # Find user by Stripe customer ID
        cur.execute("""
            SELECT id, subscription_tier FROM users 
            WHERE stripe_customer_id = %s
        """, (customer_id,))
        
        user = cur.fetchone()
        if not user:
            return
        
        # Downgrade to free plan
        cur.execute("""
            UPDATE users 
            SET subscription_tier = 'free', 
                subscription_status = 'cancelled',
                stripe_subscription_id = NULL
            WHERE id = %s
        """, (user['id'],))
        
        # Log cancellation event
        cur.execute("""
            INSERT INTO subscription_events (user_id, event_type, from_plan, to_plan)
            VALUES (%s, %s, %s, %s)
        """, (
            user['id'],
            'subscription_deleted',
            user['subscription_tier'],
            'free'
        ))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Subscription deleted for user {user['id']}")
        
    except Exception as e:
        logger.error(f"Error handling subscription deleted: {e}")

