from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_mail import Mail, Message  # Added for Email
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from datetime import datetime
from functools import wraps
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
import smtplib
from email.message import EmailMessage
from sqlalchemy import or_

app = Flask(__name__)

# ===== CONFIGURATION =====
app.config['SECRET_KEY'] = 'svvss-college-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///svvss_college.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024

# ===== EMAIL CONFIGURATION (ADDED FOR REAL EMAIL) =====
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = ' syscomindia@gmail.com' # Your Email
# !!! PASTE YOUR 16-CHARACTER GOOGLE APP PASSWORD HERE !!!
app.config['MAIL_PASSWORD'] = 'rbxn rffd ivbk gywd' 
app.config['MAIL_DEFAULT_SENDER'] = ' syscomindia@gmail.com'

# Other password reset config
app.config['SECURITY_PASSWORD_SALT'] = 'svvss-password-salt-change-in-production'

# Optional configs (from original)
app.config['ADMIN_EMAIL'] = os.environ.get('ADMIN_EMAIL')
app.config['FORCE_RESET_RECIPIENT'] = os.environ.get('FORCE_RESET_RECIPIENT')
app.config['DEV_ALLOW_RUNTIME_OVERRIDE'] = os.environ.get('DEV_ALLOW_RUNTIME_OVERRIDE', '0') == '1'
app.config['ADMIN_API_SECRET'] = os.environ.get('ADMIN_API_SECRET')
app.config['DEV_SHOW_RESET_LINK'] = os.environ.get('DEV_SHOW_RESET_LINK', '0') == '1'

ALLOWED_EXTENSIONS = {'pdf', 'jpg', 'jpeg', 'png', 'doc', 'docx'}

# Create upload folders
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'gallery'), exist_ok=True)

# Initialize Extensions
db = SQLAlchemy(app)
CORS(app)
mail = Mail(app)  # Initialize Flask Mail

# ===== DATABASE MODELS =====

class Admin(db.Model):
    __tablename__ = 'admins'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        self.password = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password, password)


class Document(db.Model):
    __tablename__ = 'documents'
    
    id = db.Column(db.Integer, primary_key=True)
    title_marathi = db.Column(db.String(255), nullable=False)
    title_english = db.Column(db.String(255), nullable=False)
    description_marathi = db.Column(db.Text)
    description_english = db.Column(db.Text)
    file_path = db.Column(db.String(500), nullable=False)
    file_type = db.Column(db.String(50))
    category = db.Column(db.String(100))
    icon = db.Column(db.String(100), default='fas fa-file')
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    updated_date = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'title_marathi': self.title_marathi,
            'title_english': self.title_english,
            'description_marathi': self.description_marathi,
            'description_english': self.description_english,
            'file_path': self.file_path.replace('\\','/') if self.file_path else None,
            'file_type': self.file_type,
            'category': self.category,
            'icon': self.icon,
            'upload_date': self.upload_date.strftime('%d-%m-%Y %H:%M'),
            'is_active': self.is_active
        }


class Staff(db.Model):
    __tablename__ = 'staff'
    
    id = db.Column(db.Integer, primary_key=True)
    name_marathi = db.Column(db.String(255), nullable=False)
    name_english = db.Column(db.String(255), nullable=False)
    role_marathi = db.Column(db.String(255), nullable=False)
    role_english = db.Column(db.String(255), nullable=False)
    photo_path = db.Column(db.String(500))
    email = db.Column(db.String(120))
    phone = db.Column(db.String(20))
    qualification = db.Column(db.Text)
    experience = db.Column(db.String(100))
    department = db.Column(db.String(100))
    order = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name_marathi': self.name_marathi,
            'name_english': self.name_english,
            'role_marathi': self.role_marathi,
            'role_english': self.role_english,
            'photo_path': self.photo_path.replace('\\','/') if self.photo_path else None,
            'email': self.email,
            'phone': self.phone,
            'qualification': self.qualification,
            'experience': self.experience,
            'department': self.department,
            'order': self.order,
            'is_active': self.is_active
        }


class GalleryImage(db.Model):
    __tablename__ = 'gallery_images'

    id = db.Column(db.Integer, primary_key=True)
    file_path = db.Column(db.String(500), nullable=False)
    caption = db.Column(db.String(255))
    is_active = db.Column(db.Boolean, default=True)
    order = db.Column(db.Integer, default=0)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'file_path': self.file_path.replace('\\','/'),
            'caption': self.caption,
            'is_active': self.is_active,
            'order': self.order,
            'uploaded_at': self.uploaded_at.strftime('%d-%m-%Y %H:%M')
        }


class ContactMessage(db.Model):
    __tablename__ = 'contact_messages'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(20))
    subject = db.Column(db.String(255), nullable=False)
    message = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ===== AUTHENTICATION DECORATORS =====

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# ===== PASSWORD RESET HELPERS =====

def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])

def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
    except SignatureExpired:
        return None  # token expired
    except BadSignature:
        return None  # invalid token
    return email

def send_reset_email(to_email, token):
    reset_link = url_for('admin_reset', token=token, _external=True)
    
    # Create HTML Email using Flask-Mail
    try:
        msg = Message(
            subject="SVVSS College - Password Reset Request",
            recipients=[to_email]
        )
        msg.html = f"""
        <html>
          <body>
            <h3>Hello,</h3>
            <p>We received a request to reset your admin password. Click the link below to reset it:</p>
            <p><a href="{reset_link}" style="background-color:#8b0000; color:white; padding:10px 20px; text-decoration:none; border-radius:5px;">Reset your password</a></p>
            <p>If you didn't request this, you can ignore this message.</p>
            <p><small>This link expires in 1 hour.</small></p>
            <p>Thanks,<br/>SVVSS College Team</p>
          </body>
        </html>
        """
        mail.send(msg)
        app.logger.info("Password reset email sent to %s", to_email)
        return True, reset_link, None
    except Exception as e:
        app.logger.error("Failed to send email to %s — %s", to_email, str(e))
        # Fallback: print link to console
        print("Password reset link (dev):", reset_link)
        return False, reset_link, str(e)


# ===== FRONTEND ROUTES =====

@app.route('/')
def index():
    """Main website page"""
    return render_template('index.html')


@app.route('/api/staff')
def get_staff():
    """API endpoint to get all active staff"""
    staff_list = Staff.query.filter_by(is_active=True).order_by(Staff.order).all()
    return jsonify([staff.to_dict() for staff in staff_list])


@app.route('/api/documents')
def get_documents():
    """API endpoint to get all active documents"""
    category = request.args.get('category')
    query = Document.query.filter_by(is_active=True)
    
    if category:
        query = query.filter_by(category=category)
    
    documents = query.order_by(Document.upload_date.desc()).all()
    return jsonify([doc.to_dict() for doc in documents])


@app.route('/api/contact', methods=['POST'])
def submit_contact():
    """Submit contact form"""
    try:
        data = request.json
        
        message = ContactMessage(
            name=data.get('name'),
            email=data.get('email'),
            phone=data.get('phone'),
            subject=data.get('subject'),
            message=data.get('message')
        )
        
        db.session.add(message)
        db.session.commit()
        
        return jsonify({'status': 'success', 'message': 'Message sent successfully'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 400


# ===== ADMIN ROUTES (LOGIN & PASSWORD RESET) =====

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Admin login page"""
    if request.method == 'POST':
        data = request.json
        print('data',data)
        admin = Admin.query.filter_by(username=data.get('username')).first()
        password = Admin.query.filter_by(username=data.get('password')).first()
        print('admin',admin)
        print("password",password)
        
        if admin and admin.check_password(data.get('password')):
            session['admin_id'] = admin.id
            session['admin_username'] = admin.username
            return jsonify({'status': 'success', 'message': 'Login successful'}), 200
        
        return jsonify({'status': 'error', 'message': 'Invalid credentials'}), 401
    
    if 'admin_id' in session:
        return redirect(url_for('admin_dashboard'))
    
    # Render your specific HTML file
    return render_template('admin_login.html')


@app.route('/admin/forgot', methods=['GET', 'POST'])
def admin_forgot():
    """Request password reset via username or email."""
    if request.method == 'POST':
        data = request.json
        identifier = (data.get('username') or data.get('identifier') or '').strip()
        if not identifier:
            return jsonify({'status': 'error', 'message': 'Username or email is required'}), 400

        # Find admin by username OR email
        admin = Admin.query.filter(or_(Admin.username == identifier, Admin.email == identifier)).first()
        if admin:
            # Prefer using the admin's email in the token
            token = generate_confirmation_token(admin.email if admin.email else admin.username)
            # Override recipient if configured (for testing)
            recipient = app.config.get('FORCE_RESET_RECIPIENT') or app.config.get('ADMIN_EMAIL') or admin.email
            
            sent, link, err = send_reset_email(recipient, token)
            app.logger.info("Password reset requested for admin id=%s username=%s email=%s sent=%s", admin.id, admin.username, admin.email, sent)
            
            # In dev mode or when configured to show link, return it for convenience
            if app.debug or app.config.get('DEV_SHOW_RESET_LINK') or not sent:
                resp = {'status': 'success', 'message': 'If that username/email is registered, a reset link has been sent to the associated email address.', 'reset_link': link, 'recipient': recipient}
                if not sent:
                    resp['warning'] = 'Email delivery failed; check SMTP settings. The reset link is included for convenience.'
                return jsonify(resp), 200
            return jsonify({'status': 'success', 'message': 'If that username/email is registered, a reset link has been sent to the associated email address.'}), 200

        # Generic response to avoid user enumeration
        return jsonify({'status': 'success', 'message': 'If that username/email is registered, a reset link has been sent to the associated email address.'}), 200

    return render_template('admin_forgot.html')


@app.route('/admin/test-email', methods=['POST'])
@login_required
def admin_test_email():
    """Send a test email to verify SMTP settings (admin only)"""
    data = request.json or {}
    to_email = data.get('email') or app.config.get('FORCE_RESET_RECIPIENT') or app.config.get('ADMIN_EMAIL')
    if not to_email:
        return jsonify({'status': 'error', 'message': 'Email is required (or set FORCE_RESET_RECIPIENT/ADMIN_EMAIL)'}), 400
    token = generate_confirmation_token(to_email)
    sent, link, err = send_reset_email(to_email, token)
    if sent:
        return jsonify({'status': 'success', 'message': 'Email sent', 'link': link, 'recipient': to_email}), 200
    else:
        return jsonify({'status': 'error', 'message': 'Failed to send email', 'error': err, 'link': link, 'recipient': to_email}), 500


@app.route('/dev/force-recipient', methods=['GET', 'POST'])
def dev_force_recipient():
    if not (app.debug or app.config.get('DEV_ALLOW_RUNTIME_OVERRIDE')):
        return jsonify({'status': 'error', 'message': 'Runtime override not enabled'}), 403

    if request.method == 'GET':
        return jsonify({'status': 'success', 'recipient': app.config.get('FORCE_RESET_RECIPIENT')}), 200

    data = request.json or {}
    secret = data.get('secret')
    cfg_secret = app.config.get('ADMIN_API_SECRET')
    if cfg_secret and secret != cfg_secret:
        return jsonify({'status': 'error', 'message': 'Invalid secret'}), 401

    email = (data.get('email') or '').strip()
    if not email:
        return jsonify({'status': 'error', 'message': 'Email is required'}), 400

    app.config['FORCE_RESET_RECIPIENT'] = email
    app.logger.info('Dev override: FORCE_RESET_RECIPIENT set to %s', email)
    return jsonify({'status': 'success', 'recipient': email}), 200


@app.route('/dev/send-test-email', methods=['POST'])
def dev_send_test_email():
    if not (app.debug or app.config.get('DEV_ALLOW_RUNTIME_OVERRIDE')):
        return jsonify({'status': 'error', 'message': 'Runtime override not enabled'}), 403

    data = request.json or {}
    secret = data.get('secret')
    cfg_secret = app.config.get('ADMIN_API_SECRET')
    if cfg_secret and secret != cfg_secret:
        return jsonify({'status': 'error', 'message': 'Invalid secret'}), 401

    to_email = (data.get('email') or app.config.get('FORCE_RESET_RECIPIENT') or app.config.get('ADMIN_EMAIL'))
    if not to_email:
        return jsonify({'status': 'error', 'message': 'No recipient configured (set email in payload, or FORCE_RESET_RECIPIENT or ADMIN_EMAIL)'}), 400

    token = generate_confirmation_token(to_email)
    sent, link, err = send_reset_email(to_email, token)
    if sent:
        return jsonify({'status': 'success', 'message': 'Test email sent', 'link': link, 'recipient': to_email}), 200
    else:
        return jsonify({'status': 'error', 'message': 'Failed to send test email', 'error': err, 'link': link, 'recipient': to_email}), 500


@app.route('/admin/reset/<token>', methods=['GET', 'POST'])
def admin_reset(token):
    """Password reset using token"""
    identifier = confirm_token(token)
    
    if request.method == 'POST':
        data = request.json
        password = data.get('password')
        
        # find admin by username OR email to be flexible
        admin = Admin.query.filter(or_(Admin.username == identifier, Admin.email == identifier)).first()
        if admin:
            admin.set_password(password)
            db.session.commit()
            return jsonify({'status': 'success', 'message': 'Password has been reset. You can now login.'}), 200
        return jsonify({'status': 'error', 'message': 'User not found'}), 404

    if not identifier:
        return render_template('admin_reset.html', invalid=True)

    return render_template('admin_reset.html', token=token, identifier=identifier, invalid=False)


@app.route('/admin/logout')
def admin_logout():
    """Admin logout"""
    session.clear()
    return redirect(url_for('admin_login'))


@app.route('/admin')
@login_required
def admin_dashboard():
    """Admin dashboard"""
    total_docs = Document.query.count()
    total_staff = Staff.query.count()
    total_messages = ContactMessage.query.filter_by(is_read=False).count()
    
    stats = {
        'total_documents': total_docs,
        'total_staff': total_staff,
        'unread_messages': total_messages
    }
    
    return render_template('admin.html', stats=stats)


# ===== DOCUMENT MANAGEMENT =====

@app.route('/api/admin/documents', methods=['GET'])
@login_required
def admin_get_documents():
    """Get all documents for admin"""
    documents = Document.query.order_by(Document.upload_date.desc()).all()
    return jsonify([doc.to_dict() for doc in documents])


@app.route('/api/admin/documents', methods=['POST'])
@login_required
def admin_create_document():
    """Create new document"""
    try:
        title_marathi = request.form.get('title_marathi')
        title_english = request.form.get('title_english')
        description_marathi = request.form.get('description_marathi')
        description_english = request.form.get('description_english')
        category = request.form.get('category')
        icon = request.form.get('icon', 'fas fa-file')
        
        file_path = None
        if 'file' in request.files:
            file = request.files['file']
            if file and allowed_file(file.filename):
                filename = secure_filename(f"{int(datetime.utcnow().timestamp())}_{file.filename}")
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
        
        document = Document(
            title_marathi=title_marathi,
            title_english=title_english,
            description_marathi=description_marathi,
            description_english=description_english,
            file_path=file_path,
            file_type=file_path.rsplit('.', 1)[1].lower() if file_path else None,
            category=category,
            icon=icon
        )
        
        db.session.add(document)
        db.session.commit()
        
        return jsonify({'status': 'success', 'document': document.to_dict()}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 400


@app.route('/api/admin/documents/<int:doc_id>', methods=['PUT'])
@login_required
def admin_update_document(doc_id):
    """Update document (supports form-data and optional file upload)"""
    try:
        document = Document.query.get_or_404(doc_id)
        data = request.form if request.form else (request.json or {})

        # metadata updates
        document.title_marathi = data.get('title_marathi', document.title_marathi)
        document.title_english = data.get('title_english', document.title_english)
        document.description_marathi = data.get('description_marathi', document.description_marathi)
        document.description_english = data.get('description_english', document.description_english)
        document.category = data.get('category', document.category)
        document.icon = data.get('icon', document.icon)
        if 'is_active' in data:
            val = data.get('is_active')
            document.is_active = str(val).lower() in ('true', '1', 'on', 'yes')

        # file replacement (optional)
        if 'file' in request.files:
            file = request.files['file']
            if file and allowed_file(file.filename):
                # remove old file if exists
                if document.file_path and os.path.exists(document.file_path):
                    try:
                        os.remove(document.file_path)
                    except Exception:
                        pass
                filename = secure_filename(f"{int(datetime.utcnow().timestamp())}_{file.filename}")
                save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(save_path)
                document.file_path = save_path
                document.file_type = save_path.rsplit('.', 1)[1].lower() if save_path else None

        db.session.commit()

        return jsonify({'status': 'success', 'document': document.to_dict()}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 400


@app.route('/api/admin/documents/<int:doc_id>', methods=['DELETE'])
@login_required
def admin_delete_document(doc_id):
    """Delete document"""
    try:
        document = Document.query.get_or_404(doc_id)
        
        if document.file_path and os.path.exists(document.file_path):
            os.remove(document.file_path)
        
        db.session.delete(document)
        db.session.commit()
        
        return jsonify({'status': 'success', 'message': 'Document deleted'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 400


# ===== STAFF MANAGEMENT =====

@app.route('/api/admin/staff', methods=['GET'])
@login_required
def admin_get_staff():
    """Get all staff"""
    staff_list = Staff.query.order_by(Staff.order).all()
    return jsonify([member.to_dict() for member in staff_list])


@app.route('/api/admin/staff', methods=['POST'])
@login_required
def admin_create_staff():
    """Create new staff member (supports file upload)"""
    try:
        # support form-data (file upload) or json
        data = request.form if request.form else (request.json or {})

        photo_path = None
        if 'file' in request.files:
            file = request.files['file']
            if file and allowed_file(file.filename):
                filename = secure_filename(f"{int(datetime.utcnow().timestamp())}_{file.filename}")
                save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(save_path)
                photo_path = save_path

        staff = Staff(
            name_marathi=data.get('name_marathi'),
            name_english=data.get('name_english'),
            role_marathi=data.get('role_marathi'),
            role_english=data.get('role_english'),
            email=data.get('email'),
            phone=data.get('phone'),
            qualification=data.get('qualification'),
            experience=data.get('experience'),
            department=data.get('department'),
            order=int(data.get('order', 0))
        )

        if photo_path:
            staff.photo_path = photo_path

        db.session.add(staff)
        db.session.commit()

        return jsonify({'status': 'success', 'staff': staff.to_dict()}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 400


@app.route('/api/admin/staff/<int:staff_id>', methods=['PUT'])
@login_required
def admin_update_staff(staff_id):
    """Update staff member (supports file upload)"""
    try:
        staff = Staff.query.get_or_404(staff_id)
        data = request.form if request.form else (request.json or {})

        staff.name_marathi = data.get('name_marathi', staff.name_marathi)
        staff.name_english = data.get('name_english', staff.name_english)
        staff.role_marathi = data.get('role_marathi', staff.role_marathi)
        staff.role_english = data.get('role_english', staff.role_english)
        staff.email = data.get('email', staff.email)
        staff.phone = data.get('phone', staff.phone)
        staff.qualification = data.get('qualification', staff.qualification)
        staff.experience = data.get('experience', staff.experience)
        staff.department = data.get('department', staff.department)
        staff.order = int(data.get('order', staff.order))
        staff.is_active = data.get('is_active', staff.is_active)

        # handle photo update
        if 'file' in request.files:
            file = request.files['file']
            if file and allowed_file(file.filename):
                # remove old file if exists
                if staff.photo_path and os.path.exists(staff.photo_path):
                    try:
                        os.remove(staff.photo_path)
                    except Exception:
                        pass
                filename = secure_filename(f"{int(datetime.utcnow().timestamp())}_{file.filename}")
                save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(save_path)
                staff.photo_path = save_path

        db.session.commit()

        return jsonify({'status': 'success', 'staff': staff.to_dict()}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 400


@app.route('/api/admin/staff/<int:staff_id>', methods=['DELETE'])
@login_required
def admin_delete_staff(staff_id):
    """Delete staff member and associated photo"""
    try:
        staff = Staff.query.get_or_404(staff_id)
        # delete photo file if exists
        if staff.photo_path and os.path.exists(staff.photo_path):
            try:
                os.remove(staff.photo_path)
            except Exception:
                pass
        db.session.delete(staff)
        db.session.commit()

        return jsonify({'status': 'success', 'message': 'Staff deleted'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 400


# ===== GALLERY MANAGEMENT =====

@app.route('/api/gallery', methods=['GET'])
def get_gallery_public():
    """Public gallery images"""
    images = GalleryImage.query.filter_by(is_active=True).order_by(GalleryImage.order).all()
    return jsonify([img.to_dict() for img in images])


@app.route('/api/admin/gallery', methods=['GET'])
@login_required
def admin_get_gallery():
    """Admin: list all gallery images"""
    images = GalleryImage.query.order_by(GalleryImage.order.desc()).all()
    return jsonify([img.to_dict() for img in images])


@app.route('/api/admin/gallery', methods=['POST'])
@login_required
def admin_upload_gallery():
    """Upload one or more gallery images"""
    try:
        # ensure gallery folder exists
        gallery_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'gallery')
        os.makedirs(gallery_folder, exist_ok=True)

        files = request.files.getlist('files') if 'files' in request.files else ([request.files.get('file')] if 'file' in request.files else [])
        captions = request.form.getlist('captions') if 'captions' in request.form else []

        if not files or all(f is None for f in files):
            print('Gallery upload: no files received')
            return jsonify({'status': 'error', 'message': 'No files uploaded'}), 400

        print('Gallery upload: received files ->', [f.filename for f in files if f])

        saved = []

        for idx, file in enumerate(files):
            if not file:
                continue
            if file and allowed_file(file.filename):
                filename = secure_filename(f"{int(datetime.utcnow().timestamp())}_{idx}_{file.filename}")
                save_path = os.path.join(gallery_folder, filename)
                file.save(save_path)

                caption = captions[idx] if idx < len(captions) else None
                # store web-friendly path relative to uploads folder: uploads/gallery/filename
                img = GalleryImage(file_path=os.path.join(app.config['UPLOAD_FOLDER'], 'gallery', filename), caption=caption)
                db.session.add(img)
                saved.append(img)
            else:
                print('Gallery upload: skipped file (invalid extension) ->', file.filename)

        if not saved:
            return jsonify({'status': 'error', 'message': 'No valid image files uploaded (check extensions)'}), 400

        db.session.commit()
        print('Gallery upload: saved', len(saved), 'images')
        return jsonify({'status': 'success', 'uploaded': [s.to_dict() for s in saved]}), 201
    except Exception as e:
        db.session.rollback()
        print('Gallery upload error:', str(e))
        return jsonify({'status': 'error', 'message': str(e)}), 400


@app.route('/api/admin/gallery/<int:img_id>', methods=['DELETE'])
@login_required
def admin_delete_gallery(img_id):
    """Delete a gallery image and its file"""
    try:
        img = GalleryImage.query.get_or_404(img_id)
        if img.file_path and os.path.exists(img.file_path):
            try:
                os.remove(img.file_path)
            except Exception:
                pass
        db.session.delete(img)
        db.session.commit()
        return jsonify({'status': 'success'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 400


# ===== REPLACE ENDPOINTS =====

@app.route('/api/admin/documents/<int:doc_id>/replace', methods=['POST'])
@login_required
def admin_replace_document(doc_id):
    """Replace the file of a document with a new uploaded file"""
    try:
        document = Document.query.get_or_404(doc_id)
        if 'file' not in request.files:
            return jsonify({'status': 'error', 'message': 'No file uploaded'}), 400
        file = request.files['file']
        if not file or not allowed_file(file.filename):
            return jsonify({'status': 'error', 'message': 'Invalid file'}), 400

        # remove old file
        if document.file_path and os.path.exists(document.file_path):
            try:
                os.remove(document.file_path)
            except Exception:
                pass

        filename = secure_filename(f"{int(datetime.utcnow().timestamp())}_{file.filename}")
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(save_path)

        document.file_path = save_path
        document.file_type = save_path.rsplit('.', 1)[1].lower() if save_path else None
        db.session.commit()
        return jsonify({'status': 'success', 'document': document.to_dict()}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 400


@app.route('/api/admin/gallery/<int:img_id>/replace', methods=['POST'])
@login_required
def admin_replace_gallery(img_id):
    """Replace a gallery image file (and caption)"""
    try:
        img = GalleryImage.query.get_or_404(img_id)
        if 'file' not in request.files:
            return jsonify({'status': 'error', 'message': 'No file uploaded'}), 400
        file = request.files['file']
        if not file or not allowed_file(file.filename):
            return jsonify({'status': 'error', 'message': 'Invalid file'}), 400

        # remove old file
        if img.file_path and os.path.exists(img.file_path):
            try:
                os.remove(img.file_path)
            except Exception:
                pass

        gallery_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'gallery')
        os.makedirs(gallery_folder, exist_ok=True)
        filename = secure_filename(f"{int(datetime.utcnow().timestamp())}_{file.filename}")
        save_path = os.path.join(gallery_folder, filename)
        file.save(save_path)

        img.file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'gallery', filename)
        caption = request.form.get('caption')
        if caption is not None:
            img.caption = caption
        db.session.commit()
        return jsonify({'status': 'success', 'image': img.to_dict()}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 400


# ===== MESSAGE MANAGEMENT =====

@app.route('/api/admin/messages', methods=['GET'])
@login_required
def admin_get_messages():
    """Get all contact messages"""
    messages = ContactMessage.query.order_by(ContactMessage.created_at.desc()).all()
    return jsonify([{
        'id': msg.id,
        'name': msg.name,
        'email': msg.email,
        'phone': msg.phone,
        'subject': msg.subject,
        'message': msg.message,
        'is_read': msg.is_read,
        'created_at': msg.created_at.strftime('%d-%m-%Y %H:%M')
    } for msg in messages])


@app.route('/api/admin/messages/<int:msg_id>/read', methods=['PUT'])
@login_required
def mark_message_read(msg_id):
    """Mark message as read"""
    try:
        message = ContactMessage.query.get_or_404(msg_id)
        message.is_read = True
        db.session.commit()
        
        return jsonify({'status': 'success'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 400


@app.route('/api/admin/messages/<int:msg_id>', methods=['DELETE'])
@login_required
def delete_message(msg_id):
    """Delete message"""
    try:
        message = ContactMessage.query.get_or_404(msg_id)
        db.session.delete(message)
        db.session.commit()
        
        return jsonify({'status': 'success'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 400

# ===== STATIC FILE SERVING =====

@app.route('/images/<path:filename>')
def serve_image(filename):
    """Serve images folder files"""
    return send_from_directory('images', filename)


@app.route('/uploads/<path:filename>')
def serve_upload(filename):
    """Serve uploaded files"""
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


# ===== ERROR HANDLERS =====

@app.errorhandler(404)
def not_found(error):
    return jsonify({'status': 'error', 'message': 'Not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return jsonify({'status': 'error', 'message': 'Internal server error'}), 500


# ===== DATABASE INITIALIZATION =====

def init_db():
    """Initialize database and create tables"""
    with app.app_context():
        db.create_all()
        
        # Create default admin if not exists
        if not Admin.query.filter_by(username='admin').first():
            admin = Admin(
                username='admin',
                email='admin@svvss.college'
            )
            admin.set_password('admin@123')
            db.session.add(admin)
            db.session.commit()
            print("✅ Admin created: username=admin, password=admin@123")
            print("✅ Database initialized successfully!")

        # If ADMIN_EMAIL is set in environment/config, update the default admin's email
        if app.config.get('ADMIN_EMAIL'):
            admin = Admin.query.filter_by(username='admin').first()
            if admin:
                old_email = admin.email
                admin.email = app.config.get('ADMIN_EMAIL')
                db.session.commit()
                print(f"🔁 Admin email overridden from {old_email} to {admin.email} via ADMIN_EMAIL env var")

        # Log SMTP configuration
        mail_info = f"MAIL_SERVER={app.config.get('MAIL_SERVER')} MAIL_PORT={app.config.get('MAIL_PORT')}"
        app.logger.info("Mail config: %s", mail_info)
        print("Mail config:", mail_info)


if __name__ == '__main__':
    init_db()
    print("\n" + "="*60)
    print("🚀 SVVSS College Admin System")
    print("="*60)
    print("📱 Website: http://localhost:5000")
    print("🔐 Admin Panel: http://localhost:5000/admin/login")
    print("👤 Username: admin")
    print("🔑 Password: admin@123")
    print("="*60 + "\n")
    # app.run(debug=True, host='0.0.0.0', port=5000)
    app.run(host="0.0.0.0", port=5000)