from sqlalchemy import inspect
from infra.db import Base, engine
from models.gmail_users import GmailToken
from models.gmail_mail import GmailEmail
from models.gmail_rules import MailRule, RuleCondition, ConditionKeyword
from models.outlook_users import OutlookToken
from models.outlook_mail import OutlookEmail
from models.icloud_users import ICloudToken
from models.alarm_setting import AlarmSettings
from models.push_dedupe import PushDedupe

def initialize_database():
    print("Checking and creating tables if needed...")

    inspector = inspect(engine)
    existing_tables = inspector.get_table_names()

    with engine.connect() as conn:
        if 'icloud_tokens' not in existing_tables:
            print("Creating icloud_tokens table...")
            ICloudToken.__table__.create(bind=conn, checkfirst=True)
            print("icloud_tokens table created.")
        else:
            print("gmail_tokens table already exists.")
        if 'gmail_users' not in existing_tables:
            print("Creating gmail_users table...")
            GmailToken.__table__.create(bind=conn, checkfirst=True)
            print("gmail_users table created.")
        else:
            print("gmail_tokens table already exists.")
        if 'gmail_rules' not in existing_tables:
            print("Creating gmail_rules table...")
            MailRule.__table__.create(bind=conn, checkfirst=True)
            RuleCondition.__table__.create(bind=conn, checkfirst=True)
            ConditionKeyword.__table__.create(bind=conn, checkfirst=True)
            print("gmail_rules table created.")
        else:
            print("gmail_rules table already exists.")
        
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

        if 'alarm_setting' not in existing_tables:
            print("Creating alarm_setting table...")
            AlarmSettings.__table__.create(bind=conn, checkfirst=True)
            print("alarm_setting table created.")
        else:
            print("alarm_setting table already exists.")

        if 'push_dedupe' not in existing_tables:
            print("Creating push_dedupe table...")
            PushDedupe.__table__.create(bind=conn, checkfirst=True)
            print("push_dedupe table created.")
        else:
            print("push_dedupe table already exists.")

    print("Database initialization complete.")
