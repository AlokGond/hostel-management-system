from app import app, db, User
from werkzeug.security import generate_password_hash
from datetime import datetime
import logging
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def setup_database():
    """
    Set up the database, create tables, and initialize admin user
    """
    try:
        logger.info("Starting database setup...")
        with app.app_context():
            # Log database configuration
            db_url = os.environ.get('DATABASE_URL', '')
            if db_url.startswith('postgres://'):
                db_url = db_url.replace('postgres://', 'postgresql://', 1)
            db_type = 'postgresql' if 'postgresql' in db_url else 'sqlite'
            logger.info(f"Using database type: {db_type}")
            
            # Create all tables
            logger.info("Creating database tables...")
            db.drop_all()  # Drop existing tables to ensure clean state
            db.create_all()
            logger.info("Database tables created successfully")
            
            # Create admin user
            logger.info("Checking for admin user...")
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
                    raise
            else:
                logger.info("Admin user already exists")
            
            logger.info("Database setup completed successfully!")
            return True
            
    except Exception as e:
        logger.error(f"Database setup error: {str(e)}", exc_info=True)
        return False

if __name__ == '__main__':
    success = setup_database()
    if not success:
        logger.error("Database setup failed!")
        exit(1)
