import re
from flask import Blueprint, request, jsonify
from google.oauth2.credentials import Credentials
from auth.gmail_auth import GmailAuth
from auth.outlook_auth import OutlookAuth
from models.outlook_users import OutlookToken
from models.gmail_users import GmailToken
from models.icloud_users import ICloudToken
import requests
from infra.db import SessionLocal
import logging
from datetime import datetime, timedelta
from sqlalchemy.exc import IntegrityError

logger = logging.getLogger(__name__)

token_bp = Blueprint('token', __name__)
gmail_auth = GmailAuth()


@token_bp.route('/validate_token', methods=['POST'])
def validate_token():
    data = request.get_json() or {}
    logger.info(f"Validate token request: {data}")
    service = data.get('service')
    token = data.get('access_token') or data.get('accessToken')

    if not service or not token:
        return jsonify({'error': 'Required fields missing'}), 400

    if service == 'gmail':
        creds = Credentials(
            token=token,
            token_uri='https://oauth2.googleapis.com/token',
            client_id='1094752044540-frr3h6fohvaf35vqatr3ncco7284t9mj.apps.googleusercontent.com',
            scopes=['https://www.googleapis.com/auth/gmail.modify']
        )
        return jsonify({'valid': creds.valid}), 200

    elif service == 'outlook':
        resp = requests.get(
            'https://graph.microsoft.com/v1.0/me',
            headers={'Authorization': f'Bearer {token}'}
        )
        return jsonify({'valid': resp.status_code == 200}), 200

    return jsonify({'error': 'Unsupported service'}), 400

@token_bp.route('/api/update_tokens', methods=['POST'])
def update_tokens():
    data = request.get_json() or {}
    logger.info(f"Received update_tokens request: {data}")
    service = data.get('service')
    fcm_token = data.get('fcm_token')
    access_token = data.get('accessToken')
    refresh_token = data.get('refreshToken')
    client_state = data.get('clientState') or data.get('client_state')
    email_address = data.get('email_address')

    if not service or not fcm_token or not access_token:
        return jsonify({'error': 'Required fields (service, fcm_token, accessToken) are missing'}), 400
    if service == 'gmail' and not all([refresh_token, email_address]):
        return jsonify({'error': 'refreshToken and email_address are required for Gmail'}), 400
    if service == 'outlook' and not all([refresh_token, client_state]):
        return jsonify({'error': 'refreshToken and client_state are required for Outlook'}), 400
    
    if service == 'gmail':
            email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
            if not email_pattern.match(email_address):
                return jsonify({'error': 'Invalid email_address format'}), 400
    try:
        if service == 'gmail':
            gmail_auth = GmailAuth()  # 인스턴스 생성
            sub = gmail_auth.watch(fcm_token, access_token, refresh_token, email_address)
            with SessionLocal() as db:
                token = db.query(GmailToken).filter_by(fcm_token=fcm_token).first()
                if not token:
                    return jsonify({'error': 'Token not found after update'}), 500
                logger.info(f"Returning email_address: {token.email_address}")
                return jsonify({'status': 'gmail_subscribed', 'email_address': token.email_address}), 200

        elif service == 'outlook':
            outlook_auth = OutlookAuth(
                client_id=request.headers.get('X-Outlook-Client-Id'),
            )
            email_address = outlook_auth.get_user_email(access_token)
            logger.info(f"update token email_address: {email_address}")

            with SessionLocal() as db:
                existing = db.query(OutlookToken).filter_by(client_state=client_state).first()
                if existing:
                    logger.info(f"Updating token for client_state: {client_state}")
                    existing.fcm_token = fcm_token
                    existing.access_token = access_token
                    existing.refresh_token = refresh_token
                    existing.email_address = email_address
                    existing.access_token_exp = datetime.utcnow() + timedelta(minutes=1)
                else:
                    logger.info(f"Inserting new token for email: {email_address}, client_state: {client_state}")
                    new_token = OutlookToken(
                        fcm_token=fcm_token,
                        access_token=access_token,
                        refresh_token=refresh_token,
                        email_address=email_address,
                        client_state=client_state,
                        subscription_id=None,
                        subscription_exp=datetime.utcnow() + timedelta(minutes=1),
                        access_token_exp=datetime.utcnow() + timedelta(minutes=1)
                    )
                    db.add(new_token)
                db.commit()

            return jsonify({'status': 'outlook_tokens_updated', 'email_address': email_address}), 200

        elif service == 'icloud':
            try:
                from jose import jwt
                APPLE_KEYS_URL = 'https://appleid.apple.com/auth/keys'
                apple_keys = requests.get(APPLE_KEYS_URL).json()['keys']
                identity_token = access_token
                header = jwt.get_unverified_header(identity_token)
                key = next((k for k in apple_keys if k['kid'] == header['kid']), None)

                if key is None:
                    return jsonify({'error': 'Apple public key not found'}), 400

                public_key = {
                    'kty': key['kty'],
                    'kid': key['kid'],
                    'use': key['use'],
                    'n': key['n'],
                    'e': key['e'],
                }

                decoded = jwt.decode(
                    identity_token,
                    public_key,
                    algorithms=key['alg'],
                    audience='com.secure.mailPushApp',
                    issuer='https://appleid.apple.com'
                )

                apple_sub = decoded.get('sub')
                email_address = decoded.get('email') or f"{apple_sub}@icloud.apple"

                with SessionLocal() as db:
                    existing = db.query(ICloudToken).filter_by(sub=apple_sub).first()
                    if existing:
                        logger.info(f"Updating iCloudToken for sub: {apple_sub}")
                        existing.email_address = email_address
                        existing.fcm_token = fcm_token
                        existing.access_token = access_token
                        existing.updated_at = datetime.utcnow()
                    else:
                        logger.info(f"Inserting new iCloudToken for sub: {apple_sub}")
                        new_token = ICloudToken(
                            sub=apple_sub,
                            email_address=email_address,
                            fcm_token=fcm_token,
                            access_token=access_token,
                            created_at=datetime.utcnow(),
                            updated_at=datetime.utcnow()
                        )
                        db.add(new_token)
                    db.commit()

                logger.info(f"✅ Apple login email: {email_address}")
                return jsonify({
                    'status': 'icloud_identity_verified',
                    'email_address': email_address
                }), 200

            except jwt.ExpiredSignatureError:
                return jsonify({'error': 'Apple identity token expired'}), 401
            except jwt.JWTError as e:
                logger.error(f"Apple token decode error: {e}")
                return jsonify({'error': 'Invalid Apple identity token'}), 400
            except Exception as e:
                logger.error(f"Unhandled Apple login error: {e}", exc_info=True)
                return jsonify({'error': 'Internal server error'}), 500

        else:
            return jsonify({'error': 'Unsupported service'}), 400

    except IntegrityError as e:
        logger.error(f"IntegrityError while updating token: {str(e)}")
        return jsonify({'error': 'Database constraint violation'}), 500
    except Exception as e:
        logger.error(f"Failed to update token: {str(e)}", exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500

