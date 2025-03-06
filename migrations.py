from flask_migrate import Migrate, upgrade, init, migrate
from app import app, db
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

migrate = Migrate(app, db)

def init_migrations():
    try:
        logger.info("Initializing database migrations...")
        with app.app_context():
            # Create all tables directly first
            db.create_all()
            logger.info("Created all database tables")
            
            # Initialize migrations if they don't exist
            try:
                init()
                logger.info("Initialized migrations directory")
            except:
                logger.info("Migrations directory already exists")
            
            # Create initial migration
            try:
                migrate()
                logger.info("Created initial migration")
            except:
                logger.info("Migration may already exist")
            
            # Upgrade to latest
            upgrade()
            logger.info("Upgraded database to latest migration")
            
            return True
    except Exception as e:
        logger.error(f"Error in database migration: {str(e)}")
        return False

if __name__ == '__main__':
    success = init_migrations()
    if not success:
        logger.error("Migration failed!")
        exit(1)
