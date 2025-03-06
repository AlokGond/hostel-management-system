"""
Render Deployment Diagnostic Tool
This script checks various aspects of your Render deployment environment
and PostgreSQL connection to help troubleshoot deployment issues.
Run this file on Render via: python render_check.py
"""

import os
import sys
import logging
import platform
import psycopg2
from sqlalchemy import create_engine, inspect
from datetime import datetime

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("render-diagnostics")

def check_environment():
    """Check environment variables and system information"""
    logger.info("=== ENVIRONMENT DIAGNOSTICS ===")
    logger.info(f"Python version: {platform.python_version()}")
    logger.info(f"Platform: {platform.platform()}")
    logger.info(f"Current directory: {os.getcwd()}")
    
    # Check for critical environment variables
    env_vars = [
        'DATABASE_URL', 
        'FLASK_ENV', 
        'SECRET_KEY'
    ]
    
    for var in env_vars:
        if os.environ.get(var):
            if var == 'DATABASE_URL':
                sanitized = os.environ.get(var).split('@')[0].split(':')[0] + ':***@***'
                logger.info(f"{var} is set (sanitized): {sanitized}")
            elif var == 'SECRET_KEY':
                logger.info(f"{var} is set (value hidden)")
            else:
                logger.info(f"{var}: {os.environ.get(var)}")
        else:
            logger.error(f"{var} is NOT set!")

def check_database_connection():
    """Test PostgreSQL database connection"""
    logger.info("\n=== DATABASE CONNECTION DIAGNOSTICS ===")
    
    database_url = os.environ.get('DATABASE_URL')
    if not database_url:
        logger.error("DATABASE_URL environment variable is not set!")
        return False
    
    # Check if we need to convert postgres:// to postgresql://
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
        logger.info("Converted postgres:// to postgresql:// in connection string")
    
    try:
        # Test connection using psycopg2 (low-level)
        logger.info("Testing connection with psycopg2...")
        conn = psycopg2.connect(database_url)
        cursor = conn.cursor()
        cursor.execute("SELECT version();")
        db_version = cursor.fetchone()
        logger.info(f"Connected to PostgreSQL: {db_version[0]}")
        cursor.close()
        conn.close()
        
        # Test connection using SQLAlchemy
        logger.info("Testing connection with SQLAlchemy...")
        engine = create_engine(database_url)
        inspector = inspect(engine)
        tables = inspector.get_table_names()
        logger.info(f"Successfully queried database. Found {len(tables)} tables:")
        logger.info(", ".join(tables) if tables else "No tables found")
        
        return True
    except Exception as e:
        logger.error(f"Database connection error: {str(e)}")
        return False

def check_file_permissions():
    """Check file and directory permissions"""
    logger.info("\n=== FILE SYSTEM DIAGNOSTICS ===")
    
    # Check if important files exist
    critical_files = [
        'app.py', 
        'init_db.py', 
        'Procfile', 
        'requirements.txt'
    ]
    
    for file in critical_files:
        if os.path.exists(file):
            logger.info(f"{file} exists and is readable")
        else:
            logger.error(f"{file} is missing or not readable!")
    
    # Check directories
    dirs_to_check = [
        'templates',
        'static',
        os.path.join('static', 'uploads')
    ]
    
    for directory in dirs_to_check:
        if os.path.exists(directory):
            if os.path.isdir(directory):
                if os.access(directory, os.W_OK):
                    logger.info(f"{directory} directory exists and is writable")
                else:
                    logger.warning(f"{directory} directory exists but is not writable")
            else:
                logger.error(f"{directory} exists but is not a directory!")
        else:
            logger.warning(f"{directory} directory does not exist")

if __name__ == "__main__":
    logger.info(f"=== RENDER DEPLOYMENT DIAGNOSTICS ===")
    logger.info(f"Run date/time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    check_environment()
    check_file_permissions()
    db_connection_success = check_database_connection()
    
    logger.info("\n=== DIAGNOSTICS SUMMARY ===")
    if db_connection_success:
        logger.info("✅ Database connection successful")
    else:
        logger.error("❌ Database connection FAILED")
    
    logger.info("Diagnostics complete. Check the output above for detailed information.")
