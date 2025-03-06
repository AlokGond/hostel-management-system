from flask import Flask
from app import app, db, User, Hostel, Room, RoomRequest, Notification
from app import Complaint, ComplaintComment, ComplaintAttachment
from app import Payment, Leave, MealPlan, MealPreference
from app import Visitor, MaintenanceRecord, InventoryItem
from app import ActivityLog, Announcement
from werkzeug.security import generate_password_hash
from datetime import datetime
import logging
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def init_db():
    logger.info("Starting database initialization...")
    
    try:
        # Create all tables
        logger.info("Creating database tables...")
        db.create_all()
        logger.info("Database tables created successfully")
        
        # Create admin user if it doesn't exist
        admin = User.query.filter_by(email='admin@example.com').first()
        if not admin:
            logger.info("Creating admin user...")
            try:
                admin = User(
                    email='admin@example.com',
                    password=generate_password_hash('admin123'),
                    is_admin=True,
                    first_name='Admin',
                    last_name='User',
                    father_name='Admin Father',
                    mother_name='Admin Mother',
                    date_of_birth=datetime.strptime('1990-01-01', '%Y-%m-%d'),
                    gender='Other',
                    phone='1234567890',
                    address='Admin Address',
                    city='Admin City',
                    state='Admin State',
                    pincode='123456',
                    course='Admin',
                    batch_year=2023,
                    emergency_contact='1234567890',
                    emergency_contact_name='Emergency Contact',
                    emergency_contact_relation='Relation'
                )
                db.session.add(admin)
                db.session.commit()
                logger.info("Admin user created successfully!")
            except Exception as e:
                logger.error(f"Error creating admin user: {str(e)}")
                db.session.rollback()
        else:
            logger.info("Admin user already exists")
            
        # Log database URL type for debugging (without revealing full connection string)
        if os.environ.get('DATABASE_URL'):
            db_type = 'postgresql' if 'postgresql' in os.environ.get('DATABASE_URL') else 'unknown'
            logger.info(f"Using database type: {db_type}")
        
        logger.info("Database initialization completed successfully!")
        return True
    except Exception as e:
        logger.error(f"Database initialization error: {str(e)}", exc_info=True)
        return False

if __name__ == '__main__':
    with app.app_context():
        success = init_db()
        if not success:
            logger.error("Database initialization failed!")
            exit(1)
