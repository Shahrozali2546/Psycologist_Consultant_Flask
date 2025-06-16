from flask import Flask, render_template, request, redirect, session, url_for, flash
from werkzeug.security import check_password_hash,  generate_password_hash
import uuid


import os
from werkzeug.utils import secure_filename
import datetime
from datetime import datetime, timedelta

from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer


# from google.oauth2 import service_account
# from googleapiclient.discovery import build
import mysql.connector
from contextlib import closing
import pymysql
from pymysql.cursors import DictCursor
from mysql.connector.cursor import MySQLCursorDict
RESERVATION_TIMEOUT = timedelta(minutes=10)
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from datetime import datetime, timezone
now = datetime.now(timezone.utc)
now = datetime.utcnow()

load_dotenv()

app = Flask(__name__)

app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'static', 'uploads')

UPLOAD_FOLDER = 'static/uploads'

# Use environment variables
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("SQLALCHEMY_DATABASE_URI")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.getenv("SECRET_KEY")

db = SQLAlchemy(app)

def get_db_connection():
    config = {
        'host': os.getenv("DB_HOST"),
        'user': os.getenv("DB_USER"),
        'password': os.getenv("DB_PASSWORD"),
        'database': os.getenv("DB_NAME"),
    }
    conn = mysql.connector.connect(**config)
    return conn

with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s", ('admin',))
        if cursor.fetchone() is None:
            hashed_password = generate_password_hash('Admin123@')
            cursor.execute('''
                INSERT INTO users (username, password, name, email, status, is_admin)
                VALUES (%s, %s, %s, %s, %s, %s)
            ''', ('admin', hashed_password, 'Admin', 'admin@example.com', 'active', 1))
            conn.commit()


app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')
app.config['MAIL_SECRET_KEY'] = os.getenv('MAIL_SECRET_KEY')

mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['MAIL_SECRET_KEY'] or 'mysecretkey')


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/area-of-expertise/anxiety')
def anxiety_page():
    return render_template('anxiety.html')


@app.route('/area-of-expertise/depression')
def depression_page():
    return render_template('depression.html')


@app.route('/area-of-expertise/relationship')
def relationship_page():
    return render_template('relationship.html')


@app.route('/area-of-expertise/stress')
def stress_page():
    return render_template('stress.html')


@app.route('/area-of-expertise/addiction')
def addiction_page():
    return render_template('addiction.html')


@app.route('/area-of-expertise/ocd')
def ocd_page():
    return render_template('ocd.html')


@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/blog')
def blog():
    user_id = session.get('user_id')
    is_admin = session.get('is_admin', False)

    with get_db_connection() as conn:
        with conn.cursor(dictionary=True) as c:
            c.execute("SELECT b.*, u.username as author FROM blogs b JOIN users u ON b.user_id = u.id")
            blogs = c.fetchall()

    return render_template('Blogs/blog.html', blogs=blogs, current_user_id=user_id, is_admin=is_admin)

@app.route('/view/<int:id>')
def view(id):
    with get_db_connection() as conn:
        c = conn.cursor(dictionary=True) 
        c.execute("SELECT * FROM blogs WHERE id=%s", (id,))
        blog = c.fetchone()  
    return render_template('Blogs/view.html', blog=blog)

@app.route('/doctor/create', methods=['GET', 'POST'])
def doctor_create():
    if not session.get('is_doctor'):
        flash('Access denied. Only doctors can create blogs.', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        author = request.form['author']
        image = request.files['image']

        approved = 0  # Needs admin approval
        filename = secure_filename(image.filename)
        image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        user_id = session['user_id']

        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('''INSERT INTO blogs (title, content, author, role, image, approved, user_id)
                         VALUES (%s, %s, %s, %s, %s, %s, %s)''',
                      (title, content, author, 'doctor', filename, approved, user_id))
            conn.commit()

        flash('Blog submitted for admin approval.', 'info')
        return redirect(url_for('blog'))

    return render_template('Blogs/doctor_create.html')

@app.route('/admin/create', methods=['GET', 'POST'])
def admin_create():
    if not session.get('is_admin'):
        flash('Access denied. Only admins can create blogs.', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        author = request.form['author']
        image = request.files['image']

        approved = 1  # Auto-approved
        filename = secure_filename(image.filename)
        image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        user_id = session['user_id']

        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('''INSERT INTO blogs (title, content, author, role, image, approved, user_id)
                         VALUES (%s, %s, %s, %s, %s, %s, %s)''',
                      (title, content, author, 'admin', filename, approved, user_id))
            conn.commit()

        flash('Blog posted successfully.', 'success')
        return redirect(url_for('blog'))

    return render_template('Blogs/admin_create.html')

@app.route('/admin/approve')
def approve_list():
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM blogs WHERE approved=0")
        blogs = c.fetchall()
    return render_template('Blogs/approve.html', blogs=blogs)

@app.route('/approve/<int:id>')
def approve(id):
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("UPDATE blogs SET approved=1 WHERE id=%s", (id,))
        conn.commit()
    return redirect(url_for('approve_list'))

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
def edit(id):
    user_id = session.get('user_id')
    is_admin = session.get('is_admin', False)

    if not user_id:
        flash("Please login to edit blog.", "danger")
        return redirect(url_for('patient_login'))

    with get_db_connection() as conn:
        with conn.cursor(dictionary=True) as c:
            # Fetch the blog to edit
            c.execute("SELECT * FROM blogs WHERE id=%s", (id,))
            blog = c.fetchone()

            # Check ownership or admin access
            if not blog or (blog['user_id'] != user_id and not is_admin):
                flash("Access denied. You can only edit your own blogs.", "danger")
                return redirect(url_for('blog'))

            if request.method == 'POST':
                title = request.form['title']
                content = request.form['content']
                image = request.files.get('image')

                if image and image.filename != '':
                    filename = secure_filename(image.filename)
                    image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    image.save(image_path)

                    # Update with image
                    c.execute("""
                        UPDATE blogs
                        SET title=%s, content=%s, image=%s, approved=0
                        WHERE id=%s
                    """, (title, content, filename, id))
                else:
                    # Update without image
                    c.execute("""
                        UPDATE blogs
                        SET title=%s, content=%s, approved=0
                        WHERE id=%s
                    """, (title, content, id))

                conn.commit()
                flash("Blog updated successfully! Awaiting admin approval.", "info")
                return redirect(url_for('blog'))

    return render_template('Blogs/edit.html', blog=blog)

@app.route('/delete/<int:id>')
def delete(id):
    user_id = session.get('user_id')
    is_admin = session.get('is_admin', False)

    if not user_id:
        flash("Please login to delete blog.", "danger")
        return redirect(url_for('patient_login'))

    with get_db_connection() as conn:
        with conn.cursor(dictionary=True) as c:
            c.execute("SELECT * FROM blogs WHERE id=%s", (id,))
            blog = c.fetchone()

            # Check ownership or admin access
            if not blog or (blog['user_id'] != user_id and not is_admin):
                flash("Access denied. You can only delete your own blogs.", "danger")
                return redirect(url_for('blog'))

            c.execute("DELETE FROM blogs WHERE id=%s", (id,))
            conn.commit()

    flash("Blog deleted successfully!", "success")
    return redirect(url_for('blog'))

@app.route('/doctor/signup', methods=['GET', 'POST'])
def doctor_signup():
    if request.method == 'POST':
        data = {
            'name': request.form['name'],
            'username': request.form['username'],
            'doc_email': request.form['doc_email'],
            'password': generate_password_hash(request.form['password']),
            'qualification': request.form['qualification'],
            'university': request.form['university'],
            'whatsapp': request.form['whatsapp'],
            'cnic': request.form['cnic'],
            'email': request.form.get('email', None)
        }

        with get_db_connection() as conn:
            try:
                c = conn.cursor()
                c.execute('''INSERT INTO users
                    (username, password, name, qualification, university, whatsapp, cnic, doc_email, status, is_admin, is_doctor)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)''',
                    (data['username'], data['password'], data['name'], data['qualification'], data['university'],
                     data['whatsapp'], data['cnic'], data['doc_email'], 'pending', 0, 1))
                conn.commit()
                return "Doctor registered successfully."
            except mysql.connector.IntegrityError:
                return "Username already exists."

    return render_template('doctor_registration/doctor_signup.html')

@app.route('/doctor/login', methods=['GET', 'POST'])
def doctor_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT id, password, status, is_doctor FROM users WHERE username=%s AND is_admin=0", (username,))
            user = cur.fetchone()

            if user:
                user_id, hashed_pw, status, is_doctor = user
                if check_password_hash(hashed_pw, password):
                    if status != 'active':
                        return "Account not active yet."
                    if is_doctor:
                        session['user_id'] = user_id
                        session['is_doctor'] = True
                        session['role'] = 'doctor'
                        return redirect('/doctor/dashboard')
                    else:
                        return "Not a doctor account."
                else:
                    return "Incorrect password."
            else:
                return "User not found."

    return render_template('doctor_registration/doctor_login.html')

@app.route('/patient/signup', methods=['GET', 'POST'])
def patient_signup():
    if request.method == 'POST':
        name = request.form['name']
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm = request.form['confirm_password']

        if password != confirm:
            return "Passwords do not match."

        hashed_password = generate_password_hash(password)

        with get_db_connection() as conn:
            try:
                cursor = conn.cursor()      
                cursor.execute('''INSERT INTO users (username, password, name, email, status, is_admin) VALUES (%s, %s, %s, %s, %s, %s)''',
                   (username, hashed_password, name, email, 'active', 0))
                conn.commit()
                cursor.close()
                return redirect('/patient/login')
            except mysql.connector.IntegrityError:
                return "Username already exists."

    return render_template('patient_registration/patient_signup.html')

@app.route('/patient/login', methods=['GET', 'POST'])
def patient_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT id, password, status, is_doctor FROM users WHERE username=%s AND is_admin=0", (username,))
            user = cur.fetchone()

            if user:
                user_id, hashed_pw, status, is_doctor = user

                # Block doctor accounts from logging in here
                if is_doctor:
                    return "Invalid Credentials."

                if not check_password_hash(hashed_pw, password):
                    return "Incorrect password."

                if status != 'active':
                    return "Your account is not active."

                session['user_id'] = user_id
                session['role'] = 'patient'
                return redirect('/dashboard')
            else:
                return "Invalid credentials"

    return render_template('patient_registration/patient_login.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except Exception:
        return "The reset link is invalid or expired."

    if request.method == 'POST':
        password = request.form['password']
        confirm = request.form['confirm']

        if password != confirm:
            return "Passwords do not match."

        hashed = generate_password_hash(password)

        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute("UPDATE users SET password = %s WHERE email = %s OR doc_email = %s",
                        (hashed, email, email))
            conn.commit()
            return "Your password has been updated successfully. You may now login."

    return render_template('patient_registration/reset_password.html')


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT id FROM users WHERE email = %s OR doc_email = %s", (email, email))
            user = cur.fetchone()

            if user:
                token = serializer.dumps(email, salt='password-reset-salt')
                reset_url = url_for('reset_password', token=token, _external=True)

                msg = Message('Password Reset Request',
                              recipients=[email])
                msg.body = f"Click the link to reset your password: {reset_url}"
                mail.send(msg)

                return "A password reset link has been sent to your email."
            else:
                return "No account found with that email."

    return render_template('patient_registration/forgot_password.html')


@app.route('/dashboard')
def dashboard():
    if not session.get('user_id'):
        return redirect('/patient/login')

    user_id = session['user_id']
    user_role = session.get('role')
    appointments = []

    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)  # Ensures rows are returned as dicts

        if user_role == 'patient':
            cursor.execute("""
                SELECT a.date, a.time, a.status, a.payment_status, a.payment_info, u.name AS doctor_name
                FROM appointments a
                JOIN users u ON a.doctor_id = u.id
                WHERE a.patient_id = %s
                ORDER BY a.date DESC, a.time DESC
            """, (user_id,))
            appointments = cursor.fetchall()

    return render_template('dashboard.html', appointments=appointments)


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT id, password, is_admin, status FROM users WHERE username=%s", (username,))
            user = c.fetchone()

        if user and user[2] == 1:  # is_admin == 1
            stored_password = user[1]
            status = user[3]
            if status != 'active':
                error = "Admin account not active."
            elif check_password_hash(stored_password, password):
                session['user_id'] = user[0]
                session['is_admin'] = True
                return redirect('/admin/dashboard')
            else:
                error = "Invalid password."
        else:
            error = "Invalid admin username."

    return render_template('admin_login/admin_login.html', error=error)


@app.route('/admin/change-password', methods=['GET', 'POST'])
def admin_change_password():
    if not session.get('is_admin'):
        return redirect('/admin/login')

    error = None
    success = None

    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        new_username = request.form.get('username')

        admin_id = session.get('user_id')

        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT username, password FROM users WHERE id = %s AND is_admin = 1", (admin_id,))
            admin = cursor.fetchone()

            if not admin:
                error = "Admin user not found."
            elif not check_password_hash(admin[1], old_password):
                error = "Old password is incorrect."
            elif new_password != confirm_password:
                error = "New passwords do not match."
            else:
                hashed_password = generate_password_hash(new_password)
                if new_username:
                    cursor.execute("UPDATE users SET password=%s, username=%s WHERE id=%s", (hashed_password, new_username, admin_id))
                else:
                    cursor.execute("UPDATE users SET password=%s WHERE id=%s", (hashed_password, admin_id))
                conn.commit()
                success = "Password updated successfully."

    return render_template('admin_dashboard/change_password.html', error=error, success=success)



# Admin dashboard
@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('is_admin'):
        return redirect('/admin/login')

    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)

        # Doctors list
        cursor.execute("""SELECT id, name, username, email, doc_email, status, qualification, whatsapp, cnic, university 
                          FROM users WHERE is_doctor=1""")
        doctors = cursor.fetchall()

        # Patients list
        cursor.execute("""SELECT id, name, username, status ,email
                          FROM users 
                          WHERE is_doctor=0 AND is_admin=0""")
        patients = cursor.fetchall()

        # Reviews list with doctor and patient name
        cursor.execute("""
            SELECT r.id, r.rating, r.comment, r.created_at,
                   d.name AS doctor_name, p.name AS patient_name
            FROM reviews r
            JOIN users d ON r.doctor_id = d.id
            JOIN users p ON r.patient_id = p.id
            ORDER BY r.created_at DESC
        """)
        reviews = cursor.fetchall()

    return render_template(
        'admin_dashboard/admin_dashboard.html',
        doctors=doctors,
        patients=patients,
        reviews=reviews
    )

@app.route('/admin/delete_review/<int:review_id>', methods=['POST'])
def delete_review(review_id):
    if not session.get('is_admin'):
        return redirect('/admin/login')

    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM reviews WHERE id = %s", (review_id,))
            conn.commit()

    flash("Review deleted successfully.")
    return redirect(url_for('admin_dashboard'))



@app.route('/admin/appointment')
def admin_appointment():
    if not session.get('is_admin'):
        return redirect('/admin/login')

    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT a.id, a.patient_name, a.contact, a.booked_at, s.date, s.start_time, s.end_time, u.name AS doctor_name
            FROM appointments a
            JOIN availability s ON a.slot_id = s.id
            JOIN users u ON s.doctor_id = u.id
            ORDER BY a.booked_at DESC
        """)
        appointments = cursor.fetchall()

    return render_template('admin_dashboard/view_Appointment_admin.html', appointments=appointments)


# Approve doctor
@app.route('/admin/approve/<int:doctor_id>')
def approve_doctor(doctor_id):
    if not session.get('is_admin'):
        return redirect('/admin/login')

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET status='active' WHERE id=%s", (doctor_id,))
        conn.commit()
    return redirect('/admin/dashboard')


# Deactivate doctor
@app.route('/admin/deactivate/<int:doctor_id>')
def deactivate_doctor(doctor_id):
    if not session.get('is_admin'):
        return redirect('/admin/login')

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET status='pending' WHERE id=%s", (doctor_id,))
        conn.commit()
    return redirect('/admin/dashboard')


@app.route('/admin/approve_patient/<int:user_id>')
def approve_patient(user_id):
    if not session.get('is_admin'):
        return redirect('/admin/login')

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET status='active' WHERE id=%s", (user_id,))
        conn.commit()
    return redirect('/admin/dashboard')


@app.route('/admin/deactivate_patient/<int:user_id>')
def deactivate_patient(user_id):
    if not session.get('is_admin'):
        return redirect('/admin/login')

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET status='inactive' WHERE id=%s", (user_id,))
        conn.commit()
    return redirect('/admin/dashboard')



@app.route('/doctor')
def doctor():
    with get_db_connection() as conn:
        with conn.cursor(dictionary=True) as c:
            c.execute("""
                SELECT 
                    u.id,
                    u.name,
                    u.specialization,
                    u.image,
                    u.experience,
                    u.fees,
                    COUNT(r.id) AS review_count,
                    ROUND(AVG(r.rating), 1) AS avg_satisfaction,
                    ROUND((AVG(r.rating) / 5) * 100, 0) AS satisfaction_percent
                FROM users u
                LEFT JOIN reviews r ON u.id = r.doctor_id
                WHERE u.is_doctor = 1 AND u.status = 'active'
                GROUP BY u.id
            """)
            doctors = c.fetchall()
    return render_template('doctor.html', doctors=doctors)


@app.route('/doctor/<int:doc_id>', methods=['GET', 'POST'])
def doctor_detail(doc_id):
    user_id = session.get('user_id')
    is_doctor = session.get('is_doctor')

    selected_date = None
    filtered_slots = []
    availability_summary = {}

    with get_db_connection() as conn:
        with conn.cursor(dictionary=True) as c:
            # Doctor info & stats
            c.execute("""
                SELECT 
                    u.id, u.name, u.specialization, u.image, u.description,
                    u.experience, u.university,u.fees,
                    COUNT(r.id) AS review_count,
                    ROUND(AVG(r.rating), 1) AS avg_satisfaction,
                    ROUND((AVG(r.rating) / 5) * 100, 0) AS satisfaction_percent
                FROM users u
                LEFT JOIN reviews r ON u.id = r.doctor_id
                WHERE u.id = %s AND u.is_doctor = 1 AND u.status = 'active'
                GROUP BY u.id
            """, (doc_id,))
            doctor = c.fetchone()
            if not doctor:
                return "Doctor not found", 404

            # Review submission
            if request.method == 'POST' and 'rating' in request.form:
                if not user_id:
                    flash("You must be logged in to submit a review.", "warning")
                    return redirect(url_for('patient_login'))

                if user_id == doc_id:
                    flash("You cannot review yourself.", "danger")
                    return redirect(url_for('doctor_detail', doc_id=doc_id))

                try:
                    rating = int(request.form['rating'])
                    if rating < 1 or rating > 5:
                        raise ValueError()
                except:
                    flash("Invalid rating provided.", "danger")
                    return redirect(url_for('doctor_detail', doc_id=doc_id))

                comment = request.form.get('comment', '').strip()
                if not comment:
                    flash("Please provide a comment.", "warning")
                    return redirect(url_for('doctor_detail', doc_id=doc_id))

                c.execute("""
                    INSERT INTO reviews (doctor_id, patient_id, rating, comment, created_at)
                    VALUES (%s, %s, %s, %s, NOW())
                """, (doc_id, user_id, rating, comment))
                conn.commit()
                flash("Review submitted successfully!", "success")
                return redirect(url_for('doctor_detail', doc_id=doc_id))

            # Fetch reviews
            c.execute("""
                SELECT r.*, u.name AS patient_name
                FROM reviews r
                JOIN users u ON r.patient_id = u.id
                WHERE r.doctor_id = %s
                ORDER BY r.created_at DESC
            """, (doc_id,))
            reviews = c.fetchall()

            # Cleanup expired reservations
            now = datetime.utcnow()
            expire_time = now - RESERVATION_TIMEOUT
            c.execute("""
                UPDATE availability
                SET reserved_by = NULL, reserved_at = NULL
                WHERE reserved_at < %s
            """, (expire_time,))
            conn.commit()

            # Get all availability slots
            c.execute("""
                SELECT id, date, start_time, end_time, booked
                FROM availability
                WHERE doctor_id=%s AND TIMESTAMP(date, start_time) >= %s
            """, (doc_id, now))
            all_slots = c.fetchall()

            # Build availability summary
            for slot in all_slots:
                date = str(slot['date'])
                day = datetime.strptime(date, "%Y-%m-%d").strftime('%A')
                start = str(slot['start_time'])
                end = str(slot['end_time'])
                key = (date, day)
                availability_summary.setdefault(key, []).append((start, end, slot['id'], slot['booked']))

            # If a date is selected, filter free slots
            if request.method == 'POST' and 'date' in request.form:
                selected_date = request.form.get('date')
                for (date, _), times in availability_summary.items():
                    if date == selected_date:
                        filtered_slots = [(start, end, slot_id) for (start, end, slot_id, booked) in times if booked == 0]
                        break


    return render_template('doctor_detail.html',doctor=doctor,reviews=reviews,doctor_id=doc_id,
        availability_summary=availability_summary,selected_date=selected_date,filtered_slots=filtered_slots,
        current_user_id=user_id)


@app.route('/admin/review/delete/<int:review_id>', methods=['POST'])
def admin_delete_review(review_id):
    # Check admin session
    if not session.get('is_admin'):
        return "Unauthorized", 403

    with get_db_connection() as conn:
        with conn.cursor() as c:
            c.execute("DELETE FROM reviews WHERE id=%s", (review_id,))
            conn.commit()

    flash("Review deleted successfully.", "success")
    return redirect(request.referrer or url_for('doctor'))


@app.template_filter('to_12hour')
def to_12hour(time_str):
    dt = datetime.strptime(time_str, "%H:%M")
    return dt.strftime("%I:%M %p").lstrip('0')



@app.route('/video-call/<int:doc_id>', methods=["GET", "POST"])
def video_call(doc_id):
    user_id = session.get('user_id')
    selected_date = None
    filtered_slots = []
    availability_summary = {}

    with get_db_connection() as conn:
        with conn.cursor(dictionary=True) as c:
            # Get doctor info
            c.execute("SELECT id, name, fees FROM users WHERE id = %s AND is_doctor = 1", (doc_id,))
            doctor = c.fetchone()
            if not doctor:
                return "Doctor not found", 404

            now = datetime.utcnow()
            expire_time = now - RESERVATION_TIMEOUT

            # Clean expired reservations
            c.execute("""
                UPDATE availability
                SET reserved_by = NULL, reserved_at = NULL
                WHERE reserved_at < %s
            """, (expire_time,))
            conn.commit()

            # Get availability
            c.execute("""
                SELECT id, date, start_time, end_time, booked
                FROM availability
                WHERE doctor_id=%s AND (TIMESTAMP(date, start_time) >= %s)
            """, (doc_id, now))
            all_slots = c.fetchall()

            for slot in all_slots:
                day = datetime.strptime(str(slot['date']), "%Y-%m-%d").strftime('%A')
                start = str(slot['start_time'])
                end = str(slot['end_time'])
                key = (slot['date'], day)
                availability_summary.setdefault(key, []).append((start, end, slot['id'], slot['booked']))

    if request.method == "POST":
        selected_date = request.form.get('date')
        for (date, _), times in availability_summary.items():
            if date == selected_date:
                filtered_slots = [ (start, end, slot_id) for (start, end, slot_id, booked) in times if booked == 0 ]
                break

    return render_template(
        'video_call.html',doctor=doctor,availability_summary=availability_summary,selected_date=selected_date,
        filtered_slots=filtered_slots,doctor_id=doc_id,current_user_id=user_id)


@app.route('/book/<int:slot_id>', methods=['POST'])
def book_appointment(slot_id):
    user_id = session.get('user_id')
    if not user_id:
        return redirect('/patient/login')

    patient_name = request.form.get('patient_name')
    contact = request.form.get('contact')
    now = datetime.utcnow()

    with get_db_connection() as conn:
        with conn.cursor(dictionary=True) as c:
            # Free expired reservations
            expire_time = now - RESERVATION_TIMEOUT
            c.execute("""
                UPDATE availability
                SET reserved_by = NULL, reserved_at = NULL
                WHERE reserved_at < %s
            """, (expire_time,))
            conn.commit()

            # Check if slot is valid and not reserved by others
            c.execute("""
                SELECT booked, reserved_by, reserved_at, doctor_id
                FROM availability
                WHERE id = %s
            """, (slot_id,))
            slot = c.fetchone()

            if not slot or slot['booked']:
                flash("Slot not available", "danger")
                return redirect(url_for('video_call', doc_id=slot.get('doctor_id', 0)))

            if slot['reserved_by'] and slot['reserved_by'] != user_id:
                if slot['reserved_at'] and slot['reserved_at'] > now - RESERVATION_TIMEOUT:
                    flash("Slot is reserved by another user. Try again later.", "warning")
                    return redirect(url_for('video_call', doc_id=slot['doctor_id']))

            # Reserve slot
            c.execute("""
                UPDATE availability
                SET reserved_by = %s, reserved_at = %s
                WHERE id = %s
            """, (user_id, now, slot_id))
            conn.commit()

            # Store appointment details in session for payment
            session['booking_info'] = {
                'slot_id': slot_id,
                'doctor_id': slot['doctor_id'],
                'patient_name': patient_name,
                'contact': contact
            }

    return redirect(url_for('payment', slot_id=slot_id))


@app.route('/payment/<int:slot_id>', methods=['GET', 'POST'])
def payment(slot_id):
    user_id = session.get('user_id')
    user_role = session.get('user_role')  # assuming this is set in login

    if not user_id:
        return redirect('/patient/login')  # Or universal login

    booking_info = session.get('booking_info')
    if not booking_info or booking_info.get('slot_id') != slot_id:
        flash("Invalid booking session. Please try again.", "danger")
        return redirect('/')

    if request.method == 'POST':
        payment_success = True  # Simulated

        if payment_success:
            now = datetime.utcnow()

            with get_db_connection() as conn:
                with conn.cursor(dictionary=True) as c:
                    c.execute("SELECT * FROM availability WHERE id=%s", (slot_id,))
                    slot = c.fetchone()

                    # Get patient_id from session or booking_info (if doctor is booking on behalf)
                    patient_id = booking_info.get('patient_id') or user_id

                    if slot and slot['booked'] == 0 and slot['reserved_by'] == user_id:
                        # Save appointment
                        c.execute("""
                            INSERT INTO appointments (
                                slot_id, patient_id, doctor_id,
                                date, time,
                                patient_name, contact,
                                booked_at, status, payment_status
                            )
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """, (
                            slot_id, patient_id, slot['doctor_id'],
                            slot['date'], slot['start_time'],
                            booking_info.get('patient_name', ''),
                            booking_info.get('contact', ''),
                            now.strftime('%Y-%m-%d %H:%M:%S'),
                            'active', 'paid'
                        ))

                        # Update availability
                        c.execute("""
                            UPDATE availability
                            SET 
                                booked = 1,
                                booked_by = %s,
                                reserved_by = NULL,
                                reserved_at = NULL,
                                payment_status = 'paid'
                            WHERE id = %s
                        """, (user_id, slot_id))

                        conn.commit()
                        session.pop('booking_info', None)

                        flash("Appointment booked successfully!", "success")
                        return redirect(url_for('video_call', doc_id=slot['doctor_id']))
                    else:
                        flash("Slot not available or not reserved by you.", "danger")
                        return redirect(url_for('video_call', doc_id=slot.get('doctor_id', 0)))
        else:
            flash("Payment failed. Please try again.", "danger")

    return render_template('payment.html', slot_id=slot_id)


@app.route('/edit_slot/<int:slot_id>', methods=['GET', 'POST'])
def edit_slot(slot_id):
    with get_db_connection() as conn, closing(conn.cursor(pymysql.cursors.DictCursor)) as c:
        if request.method == 'POST':
            date = request.form['date']
            start_time = request.form['start_time']
            end_time = request.form['end_time']
            c.execute("UPDATE availability SET date=%s, start_time=%s, end_time=%s WHERE id=%s",
                      (date, start_time, end_time, slot_id))
            conn.commit()
            return redirect('/doctor/dashboard')

        c.execute("SELECT id, date, start_time, end_time FROM availability WHERE id=%s", (slot_id,))
        slot = c.fetchone()
        if not slot:
            return "Slot not found", 404
        return render_template('doctor_dashboard/edit_slot.html', slot=slot)

@app.route('/delete_slot/<int:slot_id>')
def delete_slot(slot_id):
    with get_db_connection() as conn, closing(conn.cursor()) as c:
        c.execute("DELETE FROM availability WHERE id=%s AND booked=0", (slot_id,))
        conn.commit()
    return redirect('/doctor/dashboard')

@app.route('/doctor/dashboard', methods=['GET', 'POST'])
def doctor_dashboard():
    if not session.get('is_doctor'):
        return redirect('/doctor/login')

    doctor_id = session.get('user_id')

    with get_db_connection() as conn:
        with conn.cursor(dictionary=True) as c:
            # Fetch doctor info
            c.execute("SELECT * FROM users WHERE id = %s", (doctor_id,))
            doctor = c.fetchone()

            if not doctor:
                flash("Doctor not found.")
                return redirect('/doctor/login')

            if request.method == 'POST':
                form_type = request.form.get('form_type')

                if form_type == 'update_profile':
                    # Update profile
                    name = request.form.get('name') or doctor['name']
                    specialization = request.form.get('specialization') or doctor['specialization']
                    experience = int(request.form.get('experience') or doctor['experience'])
                    description = request.form.get('description') or doctor['description']
                    fees = request.form.get('fees') or doctor['fees']

                    if not name.strip():
                        flash("Name cannot be empty.")
                    else:
                        image_file = request.files.get('image')
                        image_filename = doctor['image']

                        if image_file and image_file.filename:
                            filename = secure_filename(image_file.filename)
                            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                            image_file.save(image_path)
                            image_filename = filename

                        c.execute("""
                            UPDATE users
                            SET name=%s, specialization=%s, description=%s, experience=%s, fees=%s, image=%s WHERE id=%s
                        """, (name, specialization, description,experience, fees,image_filename, doctor_id))
                        conn.commit()
                        flash("Profile updated successfully!")

                        # Re-fetch updated doctor info
                        c.execute("SELECT * FROM users WHERE id = %s", (doctor_id,))
                        doctor = c.fetchone()

            # Fetch doctor's reviews to show in dashboard
            c.execute("""
                SELECT r.*, u.name AS patient_name
                FROM reviews r
                JOIN users u ON r.patient_id = u.id
                WHERE r.doctor_id = %s
                ORDER BY r.created_at DESC
            """, (doctor_id,))
            reviews = c.fetchall()

    return render_template('doctor_dashboard/doctor_dashboard.html', doctor=doctor, reviews=reviews)



@app.route('/doctor/slots/add', methods=['GET', 'POST'])
def add_slot():
    if not session.get('is_doctor'):
        return redirect('/doctor/login')

    doctor_id = session.get('user_id')

    if request.method == 'POST':
        date = request.form.get('date')
        start_time = request.form.get('start_time')
        end_time = request.form.get('end_time')

        with get_db_connection() as conn:
            with conn.cursor() as c:
                try:
                    start_dt = datetime.strptime(f"{date} {start_time}", "%Y-%m-%d %H:%M")
                    end_dt = datetime.strptime(f"{date} {end_time}", "%Y-%m-%d %H:%M")

                    if start_dt >= end_dt:
                        flash("Start time must be before end time.")
                    else:
                        count = 0
                        while start_dt + timedelta(minutes=30) <= end_dt:
                            slot_start = start_dt.strftime("%H:%M")
                            slot_end = (start_dt + timedelta(minutes=30)).strftime("%H:%M")

                            c.execute("""
                                INSERT INTO availability (doctor_id, date, start_time, end_time, booked, booked_by, payment_status)
                                VALUES (%s, %s, %s, %s, 0, NULL, 'unpaid')
                            """, (doctor_id, date, slot_start, slot_end))

                            start_dt += timedelta(minutes=30)
                            count += 1

                        conn.commit()
                        flash(f"Added {count} slots successfully!")
                except Exception as e:
                    flash(f"Error adding slots: {e}")

    return render_template('doctor_dashboard/add_slot.html')


@app.route('/doctor/slots/view', methods=['GET', 'POST'])
def doctor_slot_view():
    if not session.get('is_doctor'):
        return redirect('/doctor/login')
    
    doctor_id = session.get('user_id')

    with get_db_connection() as conn:
        with conn.cursor(dictionary=True) as c:
            c.execute("""
                SELECT id, date, start_time, end_time, booked, booked_by, payment_status
                FROM availability
                WHERE doctor_id = %s ORDER BY date, start_time
            """, (doctor_id,))
            slots = c.fetchall()

    return render_template('doctor_dashboard/view_slots.html', slots=slots)


@app.route('/doctor/appointment')
def doctor_appointment():
    if not session.get('is_doctor'):
        return redirect('/doctor/login')

    doctor_id = session.get('user_id')  # Get current logged-in doctor ID

    with get_db_connection() as conn:
        with conn.cursor(dictionary=True) as c:
            c.execute("""
                SELECT 
                    a.id,
                    a.patient_name,
                    a.contact,
                    a.booked_at,
                    a.status,
                    a.payment_status,
                    a.payment_info,
                    s.date,
                    CONCAT(s.start_time, ' - ', s.end_time) AS time,
                    u.name AS doctor_name
                FROM appointments a
                JOIN availability s ON a.slot_id = s.id
                JOIN users u ON s.doctor_id = u.id
                WHERE u.id = %s
                ORDER BY a.booked_at DESC
            """, (doctor_id,))
            appointments = c.fetchall()

    return render_template('doctor_dashboard/view_appointment.html', appointments=appointments)



@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)
