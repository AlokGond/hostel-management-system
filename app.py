from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import os
from flask_migrate import Migrate
import json
import pyotp
from functools import wraps
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Database configuration - MUST come before SECRET_KEY
if os.environ.get('FLASK_ENV') == 'production':
    database_url = os.environ.get('DATABASE_URL', '')
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    logger.info(f"Using production database: {database_url}")
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///hostel.db'
    logger.info("Using development database: sqlite:///hostel.db")

# Other configurations
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', '4x7PJz9Ks2mWvNqY3bFhRtUe')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['FLASK_ENV'] = os.environ.get('FLASK_ENV', 'development')

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Role-based access control
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Access denied. Admin privileges required.', 'danger')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    father_name = db.Column(db.String(100), nullable=False)
    mother_name = db.Column(db.String(100), nullable=False)
    date_of_birth = db.Column(db.Date, nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    phone = db.Column(db.String(15), nullable=False)
    address = db.Column(db.Text, nullable=False)
    city = db.Column(db.String(50), nullable=False)
    state = db.Column(db.String(50), nullable=False)
    pincode = db.Column(db.String(10), nullable=False)
    course = db.Column(db.String(50), nullable=False)
    batch_year = db.Column(db.Integer, nullable=False)
    blood_group = db.Column(db.String(5))
    emergency_contact = db.Column(db.String(15), nullable=False)
    emergency_contact_name = db.Column(db.String(100), nullable=False)
    emergency_contact_relation = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    profile_photo = db.Column(db.String(200))
    two_factor_secret = db.Column(db.String(32))
    is_two_factor_enabled = db.Column(db.Boolean, default=False)
    last_login = db.Column(db.DateTime)
    failed_login_attempts = db.Column(db.Integer, default=0)
    account_locked_until = db.Column(db.DateTime)

    # Relationships
    requests = db.relationship('RoomRequest', backref='user', lazy=True)
    complaints = db.relationship('Complaint', backref='user', lazy=True)
    notifications = db.relationship('Notification', backref='user', lazy=True)
    payments = db.relationship('Payment', backref='user', lazy=True)
    leaves = db.relationship('Leave', backref='user', lazy=True)
    meal_preferences = db.relationship('MealPreference', backref='user', lazy=True)

# Hostel Model
class Hostel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    address = db.Column(db.String(200))
    warden_name = db.Column(db.String(100))
    warden_phone = db.Column(db.String(20))
    rooms = db.relationship('Room', backref='hostel', lazy=True)
    announcements = db.relationship('Announcement', backref='hostel', lazy=True)
    room_types = db.Column(db.String(100))
    has_ac = db.Column(db.Boolean, default=False)
    has_attached_bathroom = db.Column(db.Boolean, default=False)

# Room Model
class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_number = db.Column(db.String(10), unique=True, nullable=False)
    capacity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    is_available = db.Column(db.Boolean, default=True)
    bathroom_type = db.Column(db.String(20), nullable=False)
    hostel_id = db.Column(db.Integer, db.ForeignKey('hostel.id'), nullable=False)
    floor = db.Column(db.Integer)
    room_type = db.Column(db.String(50))
    amenities = db.Column(db.String(500))
    last_maintenance = db.Column(db.DateTime)
    last_cleaned = db.Column(db.DateTime)
    maintenance_records = db.relationship('MaintenanceRecord', backref='room', lazy=True)
    inventory_items = db.relationship('InventoryItem', backref='room', lazy=True)
    requests = db.relationship('RoomRequest', backref='room', lazy=True)

# Room Request Model
class RoomRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=False)
    hostel_id = db.Column(db.Integer, db.ForeignKey('hostel.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')
    date_requested = db.Column(db.DateTime, default=datetime.utcnow)
    preferred_duration = db.Column(db.String(50))
    special_requirements = db.Column(db.Text)
    admin_remarks = db.Column(db.Text)

# Notification Model
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(50))  # e.g., 'request', 'maintenance', 'announcement'
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Complaint Model
class Complaint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    complaint_type = db.Column(db.String(50), nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(50))
    status = db.Column(db.String(20), default='new')
    priority = db.Column(db.String(20), default='medium')
    is_private = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    resolved_at = db.Column(db.DateTime)
    admin_response = db.Column(db.Text)
    comments = db.relationship('ComplaintComment', backref='complaint', lazy=True, cascade='all, delete-orphan')
    attachments = db.relationship('ComplaintAttachment', backref='complaint', lazy=True, cascade='all, delete-orphan')

# Complaint Comment Model
class ComplaintComment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    complaint_id = db.Column(db.Integer, db.ForeignKey('complaint.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    text = db.Column(db.Text, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Complaint Attachment Model
class ComplaintAttachment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    complaint_id = db.Column(db.Integer, db.ForeignKey('complaint.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

# Payment Model
class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    payment_type = db.Column(db.String(50), nullable=False)
    payment_date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pending')
    transaction_id = db.Column(db.String(100))
    receipt_number = db.Column(db.String(50))
    payment_method = db.Column(db.String(50))

# Leave Application Model
class Leave(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime, nullable=False)
    reason = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='pending')
    contact_number = db.Column(db.String(20))
    address_during_leave = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Mess Management Models
class MealPlan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    day = db.Column(db.String(10), nullable=False)
    breakfast = db.Column(db.Text)
    lunch = db.Column(db.Text)
    dinner = db.Column(db.Text)
    special_menu = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class MealPreference(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    preference_type = db.Column(db.String(50))  # e.g., 'vegetarian', 'non-vegetarian'
    allergies = db.Column(db.Text)
    special_requirements = db.Column(db.Text)

# Visitor Management Model
class Visitor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    purpose = db.Column(db.String(200), nullable=False)
    visit_date = db.Column(db.DateTime, default=datetime.utcnow)
    check_in = db.Column(db.DateTime)
    check_out = db.Column(db.DateTime)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    id_proof_type = db.Column(db.String(50))
    id_proof_number = db.Column(db.String(50))
    status = db.Column(db.String(20), default='pending')

# Maintenance Records
class MaintenanceRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    reported_date = db.Column(db.DateTime, default=datetime.utcnow)
    resolved_date = db.Column(db.DateTime)
    cost = db.Column(db.Float)
    status = db.Column(db.String(20), default='pending')
    assigned_to = db.Column(db.String(100))
    priority = db.Column(db.String(20), default='medium')

# Inventory Management
class InventoryItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=False)
    item_name = db.Column(db.String(100), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    condition = db.Column(db.String(50))
    last_checked = db.Column(db.DateTime)
    notes = db.Column(db.Text)

# Announcement Model
class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    hostel_id = db.Column(db.Integer, db.ForeignKey('hostel.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)
    priority = db.Column(db.String(20), default='normal')
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))

# Activity Log Model
class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.String(200))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Custom Jinja2 filters
@app.template_filter('datetime')
def format_datetime(value):
    if value is None:
        return ""
    return value.strftime('%Y-%m-%d %H:%M')

@app.template_filter('timeago')
def timeago(value):
    if value is None:
        return ""
    now = datetime.utcnow()
    diff = now - value
    
    if diff.days > 365:
        years = diff.days // 365
        return f"{years}y ago"
    elif diff.days > 30:
        months = diff.days // 30
        return f"{months}mo ago"
    elif diff.days > 0:
        return f"{diff.days}d ago"
    elif diff.seconds > 3600:
        hours = diff.seconds // 3600
        return f"{hours}h ago"
    elif diff.seconds > 60:
        minutes = diff.seconds // 60
        return f"{minutes}m ago"
    else:
        return "just now"

@app.route('/')
def home():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('student_dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('student_dashboard'))

    if request.method == 'POST':
        try:
            email = request.form.get('email')
            password = request.form.get('password')
            
            logger.debug(f"Login attempt for email: {email}")
            
            user = User.query.filter_by(email=email).first()
            if not user:
                logger.warning(f"No user found with email: {email}")
                flash('Invalid email or password', 'danger')
                return redirect(url_for('login'))
            
            if not check_password_hash(user.password, password):
                logger.warning(f"Invalid password for user: {email}")
                flash('Invalid email or password', 'danger')
                return redirect(url_for('login'))
            
            login_user(user)
            logger.info(f"User logged in successfully: {email}")
            
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('student_dashboard'))
            
        except Exception as e:
            logger.error(f"Login error: {str(e)}", exc_info=True)
            flash('An error occurred during login. Please try again.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'user_id_for_2fa' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id_for_2fa'])
    if not user:
        session.pop('user_id_for_2fa', None)
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        token = request.form.get('token')
        totp = pyotp.TOTP(user.two_factor_secret)
        
        if totp.verify(token):
            # Clean up the session
            session.pop('user_id_for_2fa', None)
            
            # Log the user in
            login_user(user)
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            # Log activity
            log_activity(user.id, 'Logged in with 2FA', 
                         details=f"Login from IP: {request.remote_addr}",
                         ip_address=request.remote_addr,
                         user_agent=request.user_agent.string)
            
            flash('Two-factor authentication successful!', 'success')
            
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            
            return redirect(url_for('home'))
        else:
            flash('Invalid verification code', 'danger')
    
    return render_template('verify_2fa.html')

@app.route('/settings/security', methods=['GET', 'POST'])
@login_required
def security_settings():
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'enable_2fa':
            # Generate a new secret key for TOTP
            secret = pyotp.random_base32()
            current_user.two_factor_secret = secret
            current_user.is_two_factor_enabled = False  # Will be enabled after verification
            db.session.commit()
            
            # Generate provisioning URI for QR code
            totp = pyotp.TOTP(secret)
            provisioning_url = totp.provisioning_uri(
                name=current_user.email,
                issuer_name="BBSBEC Hostel"
            )
            
            return render_template('security_settings.html', 
                                   secret=secret, 
                                   provisioning_url=provisioning_url,
                                   qr_setup=True)
        
        elif action == 'verify_2fa':
            # Verify the TOTP code
            totp = pyotp.TOTP(current_user.two_factor_secret)
            user_token = request.form.get('token')
            
            if totp.verify(user_token):
                current_user.is_two_factor_enabled = True
                db.session.commit()
                flash('Two-factor authentication has been enabled', 'success')
                
                # Log the activity
                log_activity(current_user.id, 'Enabled two-factor authentication')
                
                return redirect(url_for('security_settings'))
            else:
                flash('Invalid verification code', 'danger')
                return redirect(url_for('security_settings'))
        
        elif action == 'disable_2fa':
            current_user.is_two_factor_enabled = False
            db.session.commit()
            flash('Two-factor authentication has been disabled', 'warning')
            
            # Log the activity
            log_activity(current_user.id, 'Disabled two-factor authentication')
            
            return redirect(url_for('security_settings'))
        
        elif action == 'change_password':
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
            
            # Verify current password
            if not check_password_hash(current_user.password, current_password):
                flash('Current password is incorrect', 'danger')
                return redirect(url_for('security_settings'))
            
            # Verify new password meets requirements
            if len(new_password) < 8:
                flash('Password must be at least 8 characters long', 'danger')
                return redirect(url_for('security_settings'))
            
            # Verify passwords match
            if new_password != confirm_password:
                flash('New passwords do not match', 'danger')
                return redirect(url_for('security_settings'))
            
            # Update password
            current_user.password = generate_password_hash(new_password)
            db.session.commit()
            flash('Password has been updated successfully', 'success')
            
            # Log the activity
            log_activity(current_user.id, 'Changed password')
            
            return redirect(url_for('security_settings'))
    
    return render_template('security_settings.html')

def log_activity(user_id, action, details=None, ip_address=None, user_agent=None):
    """Helper function to log user activity"""
    log_entry = ActivityLog(
        user_id=user_id,
        action=action,
        details=details,
        ip_address=ip_address,
        user_agent=user_agent
    )
    db.session.add(log_entry)
    db.session.commit()

@app.route('/activity-log')
@login_required
def activity_log():
    """View user's activity log"""
    if current_user.is_admin:
        # Admins can see all logs or filter by user
        user_id = request.args.get('user_id', type=int)
        if user_id:
            logs = ActivityLog.query.filter_by(user_id=user_id).order_by(ActivityLog.timestamp.desc()).all()
            user = User.query.get_or_404(user_id)
            return render_template('activity_log.html', logs=logs, user=user)
        else:
            logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(100).all()
            return render_template('activity_log.html', logs=logs)
    else:
        # Regular users can only see their own logs
        logs = ActivityLog.query.filter_by(user_id=current_user.id).order_by(ActivityLog.timestamp.desc()).all()
        return render_template('activity_log.html', logs=logs, user=current_user)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
        
    if request.method == 'POST':
        try:
            # Basic validation
            if request.form['password'] != request.form['confirm_password']:
                flash('Passwords do not match', 'error')
                return redirect(url_for('register'))
            
            # Check if email already exists
            if User.query.filter_by(email=request.form['email']).first():
                flash('Email already registered', 'error')
                return redirect(url_for('register'))
            
            # Convert date string to Python date object
            dob = datetime.strptime(request.form['date_of_birth'], '%Y-%m-%d').date()
            
            # Create new user with all fields
            new_user = User(
                email=request.form['email'],
                password=generate_password_hash(request.form['password']),
                first_name=request.form['first_name'],
                last_name=request.form['last_name'],
                father_name=request.form['father_name'],
                mother_name=request.form['mother_name'],
                date_of_birth=dob,
                gender=request.form['gender'],
                phone=request.form['phone'],
                address=request.form['address'],
                city=request.form['city'],
                state=request.form['state'],
                pincode=request.form['pincode'],
                course=request.form['course'],
                batch_year=int(request.form['batch_year']),
                blood_group=request.form.get('blood_group'),  # Optional field
                emergency_contact=request.form['emergency_contact'],
                emergency_contact_name=request.form['emergency_contact_name'],
                emergency_contact_relation=request.form['emergency_contact_relation'],
                is_admin=False
            )
            
            db.session.add(new_user)
            db.session.commit()
            
            # Create welcome notification
            notification = Notification(
                user_id=new_user.id,
                title='Welcome to Hostel Management System',
                message='Your account has been created successfully. You can now request a room.',
                type='info',
                is_read=False,
                created_at=datetime.now()
            )
            db.session.add(notification)
            
            # Create notification for admin
            admin_users = User.query.filter_by(is_admin=True).all()
            for admin in admin_users:
                admin_notification = Notification(
                    user_id=admin.id,
                    title='New Student Registration',
                    message=f'New student {new_user.first_name} {new_user.last_name} has registered.',
                    type='info',
                    is_read=False,
                    created_at=datetime.now()
                )
                db.session.add(admin_notification)
            
            db.session.commit()
            
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            flash('An error occurred during registration. Please try again.', 'error')
            print(f"Registration error: {str(e)}")
            return redirect(url_for('register'))
    
    return render_template('register.html')

@app.route('/student/dashboard')
@login_required
def student_dashboard():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    requests = RoomRequest.query.filter_by(user_id=current_user.id).all()
    return render_template('student_dashboard.html', requests=requests)

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        return redirect(url_for('student_dashboard'))
    requests = RoomRequest.query.all()
    total_users = User.query.filter_by(is_admin=False).count()  # Count non-admin users
    return render_template('admin_dashboard.html', requests=requests, Room=Room, RoomRequest=RoomRequest, total_users=total_users)

@app.route('/manage_students')
@login_required
@admin_required
def manage_students():
    # Get all non-admin users with their room requests
    students = User.query.filter_by(is_admin=False).all()
    return render_template('manage_students.html', students=students)

@app.route('/admin/student/update/<int:user_id>', methods=['POST'])
@login_required
def update_student(user_id):
    if not current_user.is_admin:
        return redirect(url_for('home'))
    
    student = User.query.get_or_404(user_id)
    email = request.form.get('email')
    new_password = request.form.get('new_password')
    action = request.form.get('action')

    if action == 'delete':
        # Delete associated room requests first
        RoomRequest.query.filter_by(user_id=user_id).delete()
        db.session.delete(student)
        flash('Student account deleted successfully')
    else:
        # Update student details
        if email and email != student.email:
            if User.query.filter_by(email=email).first() and email != student.email:
                flash('Email already exists')
                return redirect(url_for('manage_students'))
            student.email = email
        
        if new_password:
            student.password = generate_password_hash(new_password)
        
        flash('Student details updated successfully')

    db.session.commit()
    return redirect(url_for('manage_students'))

@app.route('/request_room', methods=['GET', 'POST'])
@login_required
def request_room():
    if request.method == 'POST':
        hostel_id = request.form.get('hostel_id')
        room_id = request.form.get('room_id')
        
        if not hostel_id or not room_id:
            flash('Please select both hostel and room', 'error')
            return redirect(url_for('request_room'))
            
        # Create room request
        room_request = RoomRequest(
            user_id=current_user.id,
            room_id=room_id,
            hostel_id=hostel_id,
            status='pending'
        )
        db.session.add(room_request)
        
        # Create notification for admin
        admin_notification = Notification(
            user_id=1,  # Assuming admin has user_id 1
            title='New Room Request',
            message=f'Student {current_user.username} has requested room {room_id} in hostel {hostel_id}',
            type='info',
            is_read=False,
            created_at=datetime.now()
        )
        db.session.add(admin_notification)
        db.session.commit()
        
        flash('Room request submitted successfully', 'success')
        return redirect(url_for('student_dashboard'))
    return render_template('request_room.html')

@app.route('/approve_request/<int:request_id>', methods=['POST'])
@login_required
@admin_required
def approve_request(request_id):
    room_request = RoomRequest.query.get_or_404(request_id)
    
    # Check if request is already processed
    if room_request.status != 'pending':
        flash('This request has already been processed', 'warning')
        return redirect(url_for('admin_dashboard'))
    
    # Check if room is still available
    room = Room.query.get(room_request.room_id)
    if not room.is_available:
        flash('Room is no longer available', 'error')
        return redirect(url_for('admin_dashboard'))
    
    # Update request and room status
    room_request.status = 'approved'
    room.is_available = False
    
    # Create notification for student
    student_notification = Notification(
        user_id=room_request.user_id,
        title='Room Request Approved',
        message=f'Your room request for room {room.room_number} in hostel {room.hostel.name} has been approved',
        type='success',
        is_read=False,
        created_at=datetime.now()
    )
    db.session.add(student_notification)
    db.session.commit()
    
    flash('Room request approved successfully', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/reject_request/<int:request_id>', methods=['POST'])
@login_required
@admin_required
def reject_request(request_id):
    room_request = RoomRequest.query.get_or_404(request_id)
    
    # Check if request is already processed
    if room_request.status != 'pending':
        flash('This request has already been processed', 'warning')
        return redirect(url_for('admin_dashboard'))
    
    # Update request status
    room_request.status = 'rejected'
    
    # Create notification for student
    student_notification = Notification(
        user_id=room_request.user_id,
        title='Room Request Rejected',
        message='Your room request has been rejected. Please contact the administration for more information.',
        type='danger',
        is_read=False,
        created_at=datetime.now()
    )
    db.session.add(student_notification)
    db.session.commit()
    
    flash('Room request rejected successfully', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/rooms')
@login_required
def manage_rooms():
    if not current_user.is_admin:
        return redirect(url_for('home'))
    hostels = Hostel.query.all()
    rooms = Room.query.all()
    return render_template('admin/manage_rooms.html', rooms=rooms, hostels=hostels)

@app.route('/admin/room/update/<int:room_id>', methods=['POST'])
@login_required
@admin_required
def update_room(room_id):
    if not current_user.is_admin:
        return redirect(url_for('home'))
    
    room = Room.query.get_or_404(room_id)
    room_number = request.form.get('room_number')
    capacity = request.form.get('capacity')
    price = request.form.get('price')
    is_available = request.form.get('is_available') == 'true'
    bathroom_type = request.form.get('bathroom_type')
    
    # Update room details
    if room_number and room_number != room.room_number:
        if Room.query.filter_by(room_number=room_number).first() and room_number != room.room_number:
            flash('Room number already exists')
            return redirect(url_for('manage_rooms'))
        room.room_number = room_number
    
    if capacity:
        room.capacity = int(capacity)
    if price:
        room.price = float(price)
    if bathroom_type:
        room.bathroom_type = bathroom_type
    room.is_available = is_available
    
    db.session.commit()
    flash('Room updated successfully')
    return redirect(url_for('manage_rooms'))

@app.route('/admin/room/add', methods=['POST'])
@login_required
@admin_required
def add_room():
    if not current_user.is_admin:
        return redirect(url_for('home'))
    
    room_number = request.form.get('room_number')
    capacity = int(request.form.get('capacity'))
    price = float(request.form.get('price'))
    hostel_id = int(request.form.get('hostel_id'))
    bathroom_type = request.form.get('bathroom_type')
    
    if Room.query.filter_by(room_number=room_number).first():
        flash('Room number already exists')
        return redirect(url_for('manage_rooms'))
        
    new_room = Room(
        room_number=room_number,
        capacity=capacity,
        price=price,
        is_available=True,
        bathroom_type=bathroom_type,
        hostel_id=hostel_id
    )
    db.session.add(new_room)
    db.session.commit()
    flash('New room added successfully')
    return redirect(url_for('manage_rooms'))

@app.route('/admin/room/delete/<int:room_id>', methods=['POST'])
@login_required
@admin_required
def delete_room(room_id):
    if not current_user.is_admin:
        return redirect(url_for('home'))
    
    room = Room.query.get_or_404(room_id)
    
    # Check if the room has any active or approved requests
    active_requests = RoomRequest.query.filter_by(room_id=room_id).filter(
        (RoomRequest.status == 'approved') | (RoomRequest.status == 'pending')
    ).first()
    
    if active_requests:
        flash('Cannot delete room with active or approved requests', 'danger')
        return redirect(url_for('manage_rooms'))
    
    # Safe to delete
    db.session.delete(room)
    db.session.commit()
    flash('Room deleted successfully', 'success')
    return redirect(url_for('manage_rooms'))

@app.route('/admin/requests')
@login_required
def manage_requests():
    if not current_user.is_admin:
        return redirect(url_for('home'))
    pending_requests = RoomRequest.query.filter_by(status='pending').all()
    approved_requests = RoomRequest.query.filter_by(status='approved').all()
    return render_template('manage_requests.html', pending_requests=pending_requests, approved_requests=approved_requests)

@app.route('/admin/request/update/<int:request_id>', methods=['POST'])
@login_required
def update_request(request_id):
    if not current_user.is_admin:
        return redirect(url_for('home'))
    
    room_request = RoomRequest.query.get_or_404(request_id)
    action = request.form.get('action')
    
    if action == 'approve':
        room_request.status = 'approved'
        room_request.room.is_available = False
        flash('Request approved successfully')
    elif action == 'reject':
        room_request.status = 'rejected'
        flash('Request rejected successfully')
    elif action == 'delete':
        db.session.delete(room_request)
        flash('Request deleted successfully')
    
    db.session.commit()
    return redirect(url_for('manage_requests'))

@app.route('/admin/hostels')
@admin_required
def admin_hostels():
    hostels = Hostel.query.all()
    for hostel in hostels:
        hostel.room_types = json.loads(hostel.room_types or '[]')
    return render_template('admin/manage_hostels.html', hostels=hostels)

@app.route('/admin/hostel/add', methods=['POST'])
@admin_required
def api_add_hostel():
    room_types = request.form.getlist('room_types')
    hostel = Hostel(
        name=request.form.get('name'),
        description=request.form.get('description'),
        room_types=json.dumps(room_types),
        has_ac=bool(request.form.get('has_ac')),
        has_attached_bathroom=bool(request.form.get('has_attached_bathroom'))
    )
    
    db.session.add(hostel)
    db.session.commit()
    flash('Hostel added successfully', 'success')
    return redirect(url_for('admin_hostels'))

@app.route('/admin/hostel/update/<int:hostel_id>', methods=['POST'])
@admin_required
def update_hostel(hostel_id):
    hostel = Hostel.query.get_or_404(hostel_id)
    
    hostel.name = request.form.get('name')
    hostel.description = request.form.get('description')
    
    # Update room types
    room_types = request.form.getlist('room_types')
    hostel.room_types = json.dumps(room_types)
    
    # Update facilities
    hostel.has_ac = bool(request.form.get('has_ac'))
    hostel.has_attached_bathroom = bool(request.form.get('has_attached_bathroom'))
    
    db.session.commit()
    flash('Hostel updated successfully', 'success')
    return redirect(url_for('admin_hostels'))

@app.route('/admin/hostel/delete/<int:hostel_id>', methods=['POST'])
@admin_required
def admin_delete_hostel(hostel_id):
    hostel = Hostel.query.get_or_404(hostel_id)
    
    # Check if hostel has any rooms
    if Room.query.filter_by(hostel_id=hostel_id).first():
        flash('Cannot delete hostel with existing rooms. Please delete all rooms first.', 'danger')
        return redirect(url_for('admin_hostels'))
    
    db.session.delete(hostel)
    db.session.commit()
    flash('Hostel deleted successfully', 'success')
    return redirect(url_for('admin_hostels'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        user = User.query.get(current_user.id)
        
        # Handle profile photo upload
        if 'profile_photo' in request.files:
            file = request.files['profile_photo']
            if file and file.filename and allowed_file(file.filename):
                if not os.path.exists(app.config['UPLOAD_FOLDER']):
                    os.makedirs(app.config['UPLOAD_FOLDER'])
                
                # Delete old profile photo if it exists
                if user.profile_photo:
                    old_photo_path = os.path.join(app.config['UPLOAD_FOLDER'], user.profile_photo)
                    if os.path.exists(old_photo_path):
                        os.remove(old_photo_path)
                
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                user.profile_photo = filename

        # Update user information
        user.first_name = request.form.get('first_name')
        user.last_name = request.form.get('last_name')
        user.phone = request.form.get('phone')
        user.address = request.form.get('address')

        # Handle password change
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if current_password and new_password and confirm_password:
            if not check_password_hash(user.password, current_password):
                flash('Current password is incorrect', 'danger')
                return redirect(url_for('profile'))
            
            if new_password != confirm_password:
                flash('New passwords do not match', 'danger')
                return redirect(url_for('profile'))
            
            user.password = generate_password_hash(new_password)
            flash('Password updated successfully', 'success')

        db.session.commit()
        flash('Profile updated successfully', 'success')
        return redirect(url_for('profile'))

    return render_template('profile.html')

@app.route('/change-password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    if not check_password_hash(current_user.password, current_password):
        flash('Current password is incorrect')
        return redirect(url_for('profile'))
    
    if new_password != confirm_password:
        flash('New passwords do not match')
        return redirect(url_for('profile'))
    
    current_user.password = generate_password_hash(new_password)
    db.session.commit()
    flash('Password changed successfully')
    return redirect(url_for('profile'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/complaints', methods=['GET', 'POST'])
@login_required
def complaints():
    edit_complaint = None
    
    # Check if we're editing a complaint
    if request.args.get('edit'):
        complaint_id = request.args.get('edit')
        edit_complaint = Complaint.query.filter_by(id=complaint_id, user_id=current_user.id).first_or_404()
    
    # Handle form submissions
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'submit':
            # Create new complaint
            new_complaint = Complaint(
                user_id=current_user.id,
                complaint_type=request.form.get('complaint_type'),
                subject=request.form.get('subject'),
                description=request.form.get('description'),
                location=request.form.get('location'),
                is_private=request.form.get('is_private') == 'true',
                status='new'
            )
            db.session.add(new_complaint)
            
            # Handle file attachments logic here if implemented
            
            db.session.commit()
            log_activity(current_user.id, 'complaint_submitted', f"Submitted complaint: {new_complaint.subject}")
            flash('Your complaint has been submitted successfully.', 'success')
            return redirect(url_for('complaints'))
            
        elif action == 'update':
            complaint_id = request.form.get('complaint_id')
            complaint = Complaint.query.filter_by(id=complaint_id, user_id=current_user.id).first_or_404()
            
            if complaint.status == 'new':  # Only allow editing of new complaints
                complaint.complaint_type = request.form.get('complaint_type')
                complaint.subject = request.form.get('subject')
                complaint.description = request.form.get('description')
                complaint.location = request.form.get('location')
                complaint.is_private = request.form.get('is_private') == 'true'
                
                # Handle attachment updates here if implemented
                
                db.session.commit()
                log_activity(current_user.id, 'complaint_updated', f"Updated complaint: {complaint.subject}")
                flash('Your complaint has been updated successfully.', 'success')
            else:
                flash('You can only edit complaints that are in "New" status.', 'warning')
            
            return redirect(url_for('complaints'))
            
        elif action == 'withdraw':
            complaint_id = request.form.get('complaint_id')
            complaint = Complaint.query.filter_by(id=complaint_id, user_id=current_user.id).first_or_404()
            
            if complaint.status == 'new':  # Only allow withdrawal of new complaints
                # Instead of deleting, mark as withdrawn/closed
                complaint.status = 'closed'
                db.session.commit()
                log_activity(current_user.id, 'complaint_withdrawn', f"Withdrew complaint: {complaint.subject}")
                flash('Your complaint has been withdrawn.', 'success')
            else:
                flash('You can only withdraw complaints that are in "New" status.', 'warning')
            
            return redirect(url_for('complaints'))
            
        elif action == 'close':
            complaint_id = request.form.get('complaint_id')
            complaint = Complaint.query.filter_by(id=complaint_id, user_id=current_user.id).first_or_404()
            
            if complaint.status == 'resolved':  # Only allow closing of resolved complaints
                complaint.status = 'closed'
                db.session.commit()
                log_activity(current_user.id, 'complaint_closed', f"Closed complaint: {complaint.subject}")
                flash('Your complaint has been marked as closed.', 'success')
            else:
                flash('You can only close complaints that are in "Resolved" status.', 'warning')
            
            return redirect(url_for('complaints'))
    
    # For GET requests, show list of user's complaints
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    # Apply filters if provided
    complaint_type = request.args.get('type')
    status = request.args.get('status')
    priority = request.args.get('priority')
    search = request.args.get('search')
    
    query = Complaint.query.filter_by(user_id=current_user.id)
    
    if complaint_type:
        query = query.filter_by(complaint_type=complaint_type)
    if status:
        query = query.filter_by(status=status)
    if priority:
        query = query.filter_by(priority=priority)
    if search:
        query = query.filter(
            (Complaint.subject.ilike(f'%{search}%')) | 
            (Complaint.description.ilike(f'%{search}%'))
        )
    
    pagination = query.order_by(Complaint.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    complaints = pagination.items
    
    return render_template('complaints.html', 
                          complaints=complaints, 
                          edit_complaint=edit_complaint,
                          total_pages=pagination.pages,
                          current_page=page)

@app.route('/complaint/<int:id>', methods=['GET', 'POST'])
@login_required
def complaint_details(id):
    complaint = Complaint.query.filter_by(id=id).first_or_404()
    
    # Check if user has permission to view this complaint
    if complaint.user_id != current_user.id and not current_user.is_admin:
        if complaint.is_private:
            flash('You do not have permission to view this complaint.', 'danger')
            return redirect(url_for('complaints'))
    
    # Handle comments on the complaint if implemented
    if request.method == 'POST':
        # Process any comment or update logic here
        pass
    
    return render_template('complaint_details.html', complaint=complaint)

@app.route('/admin/complaints', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_complaints():
    if request.method == 'POST':
        action = request.form.get('action')
        complaint_id = request.form.get('complaint_id')
        complaint = Complaint.query.get_or_404(complaint_id)
        
        if action == 'update_status':
            new_status = request.form.get('status')
            complaint.status = new_status
            
            if new_status == 'resolved':
                complaint.resolved_at = datetime.utcnow()
                
                # Create notification for the user
                notification = Notification(
                    user_id=complaint.user_id,
                    title="Complaint Resolved",
                    message=f"Your complaint ({complaint.subject}) has been resolved. Please check and mark it as closed if you are satisfied.",
                    type="complaint_update"
                )
                db.session.add(notification)
            
            # Add admin response if provided
            admin_response = request.form.get('admin_response')
            if admin_response:
                complaint.admin_response = admin_response
            
            log_activity(current_user.id, 'complaint_status_updated', 
                         f"Updated complaint #{complaint.id} status to {new_status}")
            db.session.commit()
            flash(f'Complaint status updated to {new_status}.', 'success')
        
        return redirect(url_for('admin_complaints'))
    
    # For GET requests, show list of all complaints with filter options
    page = request.args.get('page', 1, type=int)
    per_page = 15
    
    # Apply filters if provided
    complaint_type = request.args.get('type')
    status = request.args.get('status')
    priority = request.args.get('priority')
    search = request.args.get('search')
    
    query = Complaint.query
    
    if complaint_type:
        query = query.filter_by(complaint_type=complaint_type)
    if status:
        query = query.filter_by(status=status)
    if priority:
        query = query.filter_by(priority=priority)
    if search:
        query = query.filter(
            (Complaint.subject.ilike(f'%{search}%')) | 
            (Complaint.description.ilike(f'%{search}%'))
        )
    
    pagination = query.order_by(Complaint.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    complaints = pagination.items
    
    # Get all users for the complaints
    user_ids = [complaint.user_id for complaint in complaints]
    users = User.query.filter(User.id.in_(user_ids)).all()
    users_dict = {user.id: user for user in users}
    
    # Get complaint statistics
    stats = {
        'total': Complaint.query.count(),
        'new': Complaint.query.filter_by(status='new').count(),
        'in_progress': Complaint.query.filter_by(status='in_progress').count(),
        'resolved': Complaint.query.filter_by(status='resolved').count(),
        'closed': Complaint.query.filter_by(status='closed').count()
    }
    
    return render_template('admin/complaints.html', 
                          complaints=complaints, 
                          total_pages=pagination.pages,
                          current_page=page,
                          users=users_dict,
                          stats=stats)

@app.route('/admin/complaint/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_complaint_details(id):
    complaint = Complaint.query.get_or_404(id)
    user = User.query.get(complaint.user_id)
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'update_status':
            new_status = request.form.get('status')
            complaint.status = new_status
            
            if new_status == 'resolved' and not complaint.resolved_at:
                complaint.resolved_at = datetime.utcnow()
            
            admin_response = request.form.get('admin_response')
            if admin_response:
                complaint.admin_response = admin_response
                
                # Create notification for the user
                notification = Notification(
                    user_id=complaint.user_id,
                    title="Complaint Status Updated",
                    message=f"Your complaint ({complaint.subject}) status has been updated to {new_status}.",
                    type="complaint_update"
                )
                db.session.add(notification)
            
            log_activity(current_user.id, 'complaint_status_updated', 
                         f"Updated complaint #{complaint.id} status to {new_status}")
        
        elif action == 'add_comment':
            comment_text = request.form.get('comment')
            if comment_text:
                new_comment = ComplaintComment(
                    complaint_id=complaint.id,
                    text=comment_text,
                    is_admin=True,
                    user_id=current_user.id
                )
                db.session.add(new_comment)
                
                # Notify the user
                notification = Notification(
                    user_id=complaint.user_id,
                    title="New Comment on Your Complaint",
                    message=f"An administrator has added a comment to your complaint '{complaint.subject}'.",
                    type="complaint_comment"
                )
                db.session.add(notification)
                
                log_activity(current_user.id, 'complaint_comment_added', 
                             f"Added comment to complaint #{complaint.id}")
        
        db.session.commit()
        flash('Complaint updated successfully', 'success')
        return redirect(url_for('admin_complaint_details', id=id))
    
    # Find similar complaints
    similar_complaints = Complaint.query.filter(
        Complaint.complaint_type == complaint.complaint_type,
        Complaint.id != complaint.id
    ).order_by(Complaint.created_at.desc()).limit(5).all()
    
    return render_template('admin/complaint_details.html', 
                          complaint=complaint, 
                          user=user,
                          similar_complaints=similar_complaints)

@app.route('/complaint/<int:id>/comment', methods=['POST'])
@login_required
def add_complaint_comment(id):
    complaint = Complaint.query.get_or_404(id)
    
    # Only allow the complaint owner or admin to add comments
    if complaint.user_id != current_user.id and not current_user.is_admin:
        flash('You do not have permission to comment on this complaint', 'danger')
        return redirect(url_for('complaints'))
    
    comment_text = request.form.get('comment')
    if comment_text:
        new_comment = ComplaintComment(
            complaint_id=complaint.id,
            text=comment_text,
            is_admin=current_user.is_admin,
            user_id=current_user.id
        )
        db.session.add(new_comment)
        
        # If student adds comment, notify admin
        if not current_user.is_admin:
            # Find admin users to notify
            admins = User.query.filter_by(is_admin=True).all()
            for admin in admins:
                notification = Notification(
                    user_id=admin.id,
                    title="New Comment on Complaint",
                    message=f"A student has added a comment to complaint #{complaint.id} - '{complaint.subject}'.",
                    type="complaint_comment"
                )
                db.session.add(notification)
        
        db.session.commit()
        flash('Comment added successfully', 'success')
    
    return redirect(url_for('complaint_details', id=id))

@app.route('/admin/settings')
@admin_required
def settings():
    return render_template('admin/settings.html')

@app.route('/our-rooms')
def our_rooms():
    rooms = Room.query.filter_by(is_available=True).all()
    return render_template('our_rooms.html', rooms=rooms)

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/admin/add_hostel', methods=['POST'])
@admin_required
def add_hostel():
    room_types = request.form.getlist('room_types')
    hostel = Hostel(
        name=request.form.get('name'),
        description=request.form.get('description'),
        room_types=json.dumps(room_types),
        has_ac=bool(request.form.get('has_ac')),
        has_attached_bathroom=bool(request.form.get('has_attached_bathroom'))
    )
    
    db.session.add(hostel)
    db.session.commit()
    flash('Hostel added successfully!', 'success')
    return redirect(url_for('admin_hostels'))

@app.route('/admin/delete_hostel/<int:id>', methods=['DELETE'])
@admin_required
def api_delete_hostel(id):
    hostel = Hostel.query.get_or_404(id)
    db.session.delete(hostel)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/notifications/unread', methods=['GET'])
@login_required
def get_unread_notifications():
    notifications = Notification.query.filter_by(
        user_id=current_user.id,
        is_read=False
    ).order_by(Notification.created_at.desc()).all()
    
    return jsonify({
        'notifications': [{
            'id': n.id,
            'title': n.title,
            'message': n.message,
            'type': n.type,
            'timestamp': n.created_at.isoformat()
        } for n in notifications]
    })

@app.route('/api/notifications/<int:notification_id>/read', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    notification = Notification.query.get_or_404(notification_id)
    if notification.user_id != current_user.id:
        abort(403)
    
    notification.is_read = True
    db.session.commit()
    return jsonify({'success': True})

def create_notification(user_id, title, message, type='info'):
    notification = Notification(
        user_id=user_id,
        title=title,
        message=message,
        type=type
    )
    db.session.add(notification)
    db.session.commit()
    return notification

@app.route('/api/maintenance/<int:record_id>/update', methods=['POST'])
@login_required
@admin_required
def update_maintenance(record_id):
    record = MaintenanceRecord.query.get_or_404(record_id)
    data = request.get_json()
    
    record.status = data.get('status', record.status)
    record.resolved_date = datetime.utcnow() if data.get('status') == 'resolved' else None
    db.session.commit()
    
    # Create notification for room's current occupants
    room_requests = RoomRequest.query.filter_by(room_id=record.room_id, status='approved').all()
    for req in room_requests:
        create_notification(
            req.user_id,
            'Maintenance Update',
            f'Maintenance status for your room has been updated to: {record.status}',
            'info'
        )
    
    return jsonify({'success': True})

@app.route('/api/announcements/create', methods=['POST'])
@login_required
@admin_required
def create_announcement():
    data = request.get_json()
    
    announcement = Announcement(
        title=data['title'],
        content=data['content'],
        hostel_id=data.get('hostel_id'),
        priority=data.get('priority', 'normal'),
        created_by=current_user.id
    )
    db.session.add(announcement)
    db.session.commit()
    
    # Create notifications for all users or hostel-specific users
    query = User.query
    if announcement.hostel_id:
        room_requests = RoomRequest.query.filter_by(hostel_id=announcement.hostel_id, status='approved').all()
        user_ids = [req.user_id for req in room_requests]
        query = query.filter(User.id.in_(user_ids))
    
    for user in query.all():
        create_notification(
            user.id,
            f'New Announcement: {announcement.title}',
            announcement.content,
            'announcement'
        )
    
    return jsonify({'success': True})

@app.route('/delete_student/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_student(user_id):
    student = User.query.get_or_404(user_id)
    
    # Don't allow deleting admin users
    if student.is_admin:
        flash('Cannot delete admin users', 'error')
        return redirect(url_for('manage_students'))
    
    # Cancel any pending room requests
    pending_requests = RoomRequest.query.filter_by(user_id=user_id, status='pending').all()
    for request in pending_requests:
        db.session.delete(request)
    
    # Free up any assigned rooms
    approved_requests = RoomRequest.query.filter_by(user_id=user_id, status='approved').all()
    for request in approved_requests:
        room = Room.query.get(request.room_id)
        if room:
            room.is_available = True
        db.session.delete(request)
    
    # Delete the user's complaints
    Complaint.query.filter_by(user_id=user_id).delete()
    
    # Delete the user's notifications
    Notification.query.filter_by(user_id=user_id).delete()
    
    # Finally delete the user
    db.session.delete(student)
    db.session.commit()
    
    flash(f'Student {student.first_name} {student.last_name} has been deleted', 'success')
    return redirect(url_for('manage_students'))

@app.route('/retrieve_room/<int:request_id>', methods=['POST'])
@login_required
@admin_required
def retrieve_room(request_id):
    room_request = RoomRequest.query.get_or_404(request_id)
    
    # Get room and student info for notification
    room = Room.query.get(room_request.room_id)
    student = User.query.get(room_request.user_id)
    
    # Mark room as available
    room.is_available = True
    
    # Update request status to 'retrieved'
    room_request.status = 'retrieved'
    
    # Create notification for student
    notification = Notification(
        user_id=room_request.user_id,
        title='Room Retrieved',
        message=f'Your room ({room.room_number} in {room.hostel.name}) has been retrieved by the administration.',
        type='warning',
        is_read=False,
        created_at=datetime.now()
    )
    db.session.add(notification)
    db.session.commit()
    
    flash(f'Room retrieved successfully from {student.first_name} {student.last_name}', 'success')
    return redirect(url_for('manage_students'))

if __name__ == '__main__':
    print("Starting Flask server...")
    with app.app_context():
        try:
            logger.info("Creating database tables...")
            # Create all tables
            db.create_all()
            
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
            
            logger.info("Database initialization completed!")
        except Exception as e:
            logger.error(f"Database initialization error: {str(e)}", exc_info=True)
            raise
    
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
