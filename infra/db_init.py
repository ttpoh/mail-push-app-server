from sqlalchemy import inspect
from infra.db import Base, engine
from models.gmail_users import GmailToken
from models.gmail_mail import GmailEmail
from models.outlook_users import OutlookToken
from models.outlook_mail import OutlookEmail

def initialize_database():
    print("Checking and creating tables if needed...")

    inspector = inspect(engine)
    existing_tables = inspector.get_table_names()

    with engine.connect() as conn:
        if 'gmail_users' not in existing_tables:
            print("Creating gmail_users table...")
            GmailToken.__table__.create(bind=conn, checkfirst=True)
            print("gmail_users table created.")
        else:
            print("gmail_tokens table already exists.")
        
        if 'gmail_emails' not in existing_tables:
            print("Creating gmail_emails table...")
            GmailEmail.__table__.create(bind=conn, checkfirst=True)
            print("gmail_emails table created.")
        else:
            print("gmail_emails table already exists.")

        if 'outlook_users' not in existing_tables:
            print("Creating outlook_users table...")
            OutlookToken.__table__.create(bind=conn, checkfirst=True)
            print("outlook_users table created.")
        else:
            print("outlook_users table already exists.")

        if 'outlook_emails' not in existing_tables:
            print("Creating outlook_emails table...")
            OutlookEmail.__table__.create(bind=conn, checkfirst=True)
            print("outlook_emails table created.")
        else:
            print("outlook_emails table already exists.")

    print("Database initialization complete.")
