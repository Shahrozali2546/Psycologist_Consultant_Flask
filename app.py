from flask import Flask, render_template, request, redirect, session, url_for, flash
from werkzeug.security import check_password_hash,  generate_password_hash
import uuid


import os
from werkzeug.utils import secure_filename
import datetime
from datetime import datetime, timedelta

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



@app.route('/')
def index():
    return render_template('index.html')

@app.route('/blog')
def blog():
    with get_db_connection() as conn:
        c = conn.cursor(dictionary=True)
        c.execute("SELECT * FROM blogs WHERE approved=1 ORDER BY created_at DESC")
        blogs = c.fetchall()

    user_id = session.get('user_id')  # Logged in user id ya None

    return render_template('Blogs/blog.html', blogs=blogs, current_user_id=user_id)


# View full blog
@app.route('/view/<int:id>')
def view(id):
    with get_db_connection() as conn:
        c = conn.cursor()
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
    if not user_id:
        flash("Please login to edit blog.", "danger")
        return redirect(url_for('patient_login'))

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM blogs WHERE id=%s", (id,))
        blog = c.fetchone()

        # Example blog tuple structure assumption:
        # blog = (id, title, content, author, role, image, approved, user_id)
        # Index of user_id is 7 (starting at 0)
        if not blog or blog[7] != user_id:
            flash("Access denied. You can only edit your own blogs.", "danger")
            return redirect(url_for('blog'))

        if request.method == 'POST':
            title = request.form['title']
            content = request.form['content']
            c.execute("UPDATE blogs SET title=%s, content=%s WHERE id=%s", (title, content, id))
            conn.commit()
            flash("Blog updated successfully!", "success")
            return redirect(url_for('blog'))

    return render_template('Blogs/edit.html', blog=blog)


@app.route('/delete/<int:id>')
def delete(id):
    user_id = session.get('user_id')
    if not user_id:
        flash("Please login to delete blog.", "danger")
        return redirect(url_for('patient_login'))

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM blogs WHERE id=%s", (id,))
        blog = c.fetchone()

        # Check ownership same as edit
        if not blog or blog[7] != user_id:
            flash("Access denied. You can only delete your own blogs.", "danger")
            return redirect(url_for('blog'))

        c.execute("DELETE FROM blogs WHERE id=%s", (id,))
        conn.commit()
        flash("Blog deleted.", "success")

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


@app.route('/dashboard')
def dashboard():
    if not session.get('user_id'):
        return redirect('/patient/login')

    user_id = session['user_id']
    user_role = session.get('role')
    appointments = []

    with get_db_connection() as conn:
        if user_role == 'patient':
            c = conn.cursor()
            c.execute("""
                SELECT a.date, a.time, a.status, a.payment_status, a.payment_info, u.name AS doctor_name
                FROM appointments a
                JOIN users u ON a.doctor_id = u.id
                WHERE a.patient_id = %s
                ORDER BY a.date DESC, a.time DESC
            """, (user_id,))
            appointments = c.fetchall()

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


# Admin dashboard
@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('is_admin'):
        return redirect('/admin/login')
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("""SELECT id, name, username, email, doc_email, status, qualification, whatsapp, cnic, university 
            FROM users WHERE is_doctor=1""")
        doctors = cursor.fetchall()

        cursor.execute("""
            SELECT id, name, username, status ,email
            FROM users 
            WHERE is_doctor=0 AND is_admin=0
        """)
        patients = cursor.fetchall()

    return render_template('admin_dashboard/admin_dashboard.html', doctors=doctors, patients=patients)


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


# Doctor Detail Page with Slots
@app.route('/doctor/<int:doc_id>')
def doctor_detail(doc_id):
    with get_db_connection() as conn:
        with conn.cursor(dictionary=True) as c:
            c.execute("SELECT id, name, specialization, image, description FROM users WHERE id=%s", (doc_id,))
            doctor = c.fetchone()
    if not doctor:
        return "Doctor not found", 404
    return render_template('doctor_detail.html', doctor=doctor)

@app.route('/video-call/<int:doc_id>')
def video_call(doc_id):
    with get_db_connection() as conn:
        with conn.cursor(dictionary=True) as c:
            c.execute("SELECT id, date, start_time, end_time FROM availability WHERE doctor_id=%s AND booked=0", (doc_id,))
            slots = c.fetchall()

            availability_summary = {}
            for slot in slots:
                day = datetime.strptime(str(slot['date']), "%Y-%m-%d").strftime('%A')
                key = (slot['date'], day)
                availability_summary.setdefault(key, []).append((slot['start_time'], slot['end_time']))

    return render_template('video_call.html', slots=slots, doctor_id=doc_id, availability_summary=availability_summary)


@app.route('/book/<int:slot_id>', methods=['POST'])
def book_appointment(slot_id):
    user_id = session.get('user_id')
    if not user_id:
        return redirect('/patient/login')

    patient_name = request.form['patient_name']
    contact = request.form['contact']
    now = datetime.utcnow()

    with get_db_connection() as conn:
        with conn.cursor(dictionary=True) as c:
            expire_time = now - RESERVATION_TIMEOUT
            c.execute("UPDATE availability SET reserved_by=NULL, reserved_at=NULL WHERE reserved_at < %s", (expire_time,))

            c.execute("SELECT booked, reserved_by, reserved_at FROM availability WHERE id=%s", (slot_id,))
            slot = c.fetchone()

            if not slot:
                return "Slot not found", 404
            if slot['booked']:
                return "Slot already booked", 400
            if slot['reserved_by'] and slot['reserved_by'] != user_id:
                reserved_at = datetime.strptime(str(slot['reserved_at']), '%Y-%m-%d %H:%M:%S')
                if reserved_at > now - RESERVATION_TIMEOUT:
                    return "Slot is reserved by another user. Try again later.", 400
                else:
                    c.execute("UPDATE availability SET reserved_by=NULL, reserved_at=NULL WHERE id=%s", (slot_id,))
                    conn.commit()

            c.execute("UPDATE availability SET reserved_by=%s, reserved_at=%s WHERE id=%s",
                    (user_id, now.strftime('%Y-%m-%d %H:%M:%S'), slot_id))

            # Temporary appointment record
            c.execute("INSERT INTO appointments (slot_id, patient_name, contact) VALUES (%s, %s, %s)",
                    (slot_id, patient_name, contact))
            conn.commit()

    return redirect(url_for('payment', slot_id=slot_id))


@app.route('/payment/<int:slot_id>', methods=['GET', 'POST'])
def payment(slot_id):
    user_id = session.get('user_id')
    if not user_id:
        return redirect('/patient/login')

    if request.method == 'POST':
        payment_success = True  # Integrate payment gateway

        if payment_success:
            with get_db_connection() as conn:
                with conn.cursor(dictionary=True) as c:
                    c.execute("SELECT booked, reserved_by FROM availability WHERE id=%s", (slot_id,))
                    slot = c.fetchone()

                    if slot and slot['booked'] == 0 and slot['reserved_by'] == user_id:
                        c.execute("""
                            UPDATE availability
                            SET booked = 1, reserved_by = NULL, reserved_at = NULL, payment_status = 'paid'
                            WHERE id = %s
                        """, (slot_id,))
                        c.execute("""
                            INSERT INTO appointments (doctor_id, patient_id, date, time, status, payment_status)
                            SELECT doctor_id, %s, date, start_time, 'active', 'paid'
                            FROM availability WHERE id = %s
                        """, (user_id, slot_id))
                        conn.commit()
                        flash("Appointment booked successfully!", "success")
                        return redirect(url_for('doctor'))
                    else:
                        flash("Slot not available or not reserved by you.", "danger")
                        return redirect(url_for('doctor'))
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
        with conn.cursor(dictionary=True) as c:  # <-- add dictionary=True here
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
                    description = request.form.get('description') or doctor['description']

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
                            SET name=%s, specialization=%s, description=%s, image=%s WHERE id=%s
                        """, (name, specialization, description, image_filename, doctor_id))
                        conn.commit()
                        flash("Profile updated successfully!")

                        # Re-fetch updated doctor info
                        c.execute("SELECT * FROM users WHERE id = %s", (doctor_id,))
                        doctor = c.fetchone()

    return render_template('doctor_dashboard/doctor_dashboard.html', doctor=doctor)


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

    with get_db_connection() as conn:
        with conn.cursor(dictionary=True) as c:
            c.execute("""
                SELECT a.id, a.patient_name, a.contact, a.booked_at, s.date, s.start_time, s.end_time, u.name AS doctor_name
                FROM appointments a
                JOIN availability s ON a.slot_id = s.id
                JOIN users u ON s.doctor_id = u.id
                ORDER BY a.booked_at DESC
            """)
            appointments = c.fetchall()

    return render_template('doctor_dashboard/view_appointment.html', appointments=appointments)

@app.route('/doctor')
def doctor():
    with get_db_connection() as conn:
        with conn.cursor(dictionary=True) as c:  # this returns dict rows
            c.execute("SELECT id, name, specialization, image, description FROM users WHERE is_doctor=1")
            doctors = c.fetchall()
    return render_template('doctor.html', doctors=doctors)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)
