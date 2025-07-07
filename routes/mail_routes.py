from flask import Blueprint, request, jsonify
from models.gmail_mail import GmailEmail
from models.outlook_mail import OutlookEmail  # 각각의 SQLAlchemy 모델
from infra.db import SessionLocal
import re

email_bp = Blueprint('email', __name__)

@email_bp.route('/api/emails', methods=['GET'])
def get_emails():
    email_address = request.args.get('email_address')
    service = request.args.get('service')
    print(f'Received request for service: {service}, email_address: {email_address}')
    if service not in ['gmail', 'outlook']:
        return jsonify({'error': 'Invalid service type'}), 400    
    if not email_address:
        return jsonify({'error': 'Missing email_address parameter'}), 400
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email_address):
        return jsonify({'error': 'Invalid email_address format'}), 400
    
    with SessionLocal() as db:
        if service == 'gmail':
            emails = db.query(GmailEmail).filter(GmailEmail.email_address == email_address)\
                                        .order_by(GmailEmail.received_at.desc()).all()
            if not emails:
                print(f'No emails found for {email_address} in gmail_emails')
        else:
            emails = db.query(OutlookEmail).filter(OutlookEmail.email_address == email_address)\
                                          .order_by(OutlookEmail.received_at.desc()).all()
            if not emails:
                print(f'No emails found for {email_address} in outlook_emails')

        print(f'Fetched {len(emails)} emails for {email_address}')
        return jsonify([
            {
                "id": email.id,
                "email_address": email.email_address if service == 'gmail' else email.email_address,
                "sender": email.sender,
                "subject": email.subject,
                "body": email.body,
                "received_at": email.received_at.isoformat(),
                "read": email.read,
            }
            for email in emails
        ])
