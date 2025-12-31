import os
from dotenv import load_dotenv

load_dotenv()
from datetime import datetime, date, timedelta
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import text # For migration commands

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'team-respect-secret-key-123')
# Initialize SocketIO
from flask_socketio import SocketIO, emit, join_room, leave_room
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# Database Configuration
# 1. Try DATABASE_URL first
database_url = os.environ.get('DATABASE_URL')

# 2. Fix postgres:// deprecation
if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

# Auto-enable SSL for PostgreSQL (required for Render external connections)
if database_url and database_url.startswith("postgresql://"):
    if "sslmode" not in database_url:
        separator = "&" if "?" in database_url else "?"
        database_url += f"{separator}sslmode=require"

# 3. If DATABASE_URL is not a valid connection string (e.g. it's a website link or missing), try components
# 3. If DATABASE_URL is not a valid connection string (e.g. it's a website link or missing), try components
if not database_url.startswith("postgresql://") and not database_url.startswith("sqlite"):
    db_host = os.environ.get('DB_HOST') # User needs to add this
    db_name = os.environ.get('database')
    db_user = os.environ.get('username')
    db_pass = os.environ.get('password')
    
    if db_host and db_name and db_user and db_pass:
        database_url = f"postgresql://{db_user}:{db_pass}@{db_host}/{db_name}"
    else:
        # Fallback to local sqlite if components are missing, to avoid crash
        raise RuntimeError("CRITICAL: DATABASE_URL not set and SQLite fallback is disabled.")
        # database_url = 'sqlite:///team_respect_v2.db'

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {'pool_pre_ping': True}

db = SQLAlchemy(app)

@app.context_processor
def inject_db_type():
    return dict(db_type='PostgreSQL')

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- Models ---

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(512), nullable=False)
    role = db.Column(db.String(20), default='User') # Admin or User
    role = db.Column(db.String(20), default='User') # Admin or User

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Member(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    joined_date = db.Column(db.DateTime, default=datetime.utcnow)

class Meeting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False, default=date.today)
    status = db.Column(db.String(20), default='Pending') # Pending, Approved
    note = db.Column(db.String(200), nullable=True)

class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    member_id = db.Column(db.Integer, db.ForeignKey('member.id'), nullable=False)
    meeting_id = db.Column(db.Integer, db.ForeignKey('meeting.id'), nullable=False)
    date = db.Column(db.Date, nullable=False) # Copied from meeting for easy querying
    status = db.Column(db.String(20), nullable=False) # Jooga, Maqan, Fasax

    member = db.relationship('Member', backref='attendance_records')
    meeting = db.relationship('Meeting', backref='attendances')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Routes ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('attendance'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        try:
            user = User.query.filter_by(username=username).first()
            
            if user and user.check_password(password):
                login_user(user)
                return redirect(url_for('attendance'))
            
            flash('Invalid username or password', 'error')
        
        except Exception as e:
            print(f"Login Error: {e}")
            flash('System Error: Database connection failed. Please try again.', 'error')
            
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    # If already logged in, go to dashboard
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not username or not password:
            flash('Please fill all fields', 'error')
            return render_template('register.html')
            
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('register.html')

        # Check if user exists
        if User.query.filter_by(username=username).first():
            flash('Username already taken', 'error')
        else:
            try:
                # Default role is User
                new_user = User(username=username, role='User')
                new_user.set_password(password)
                db.session.add(new_user)
                db.session.commit()
                flash('Account created! Please login.', 'success')
                return redirect(url_for('login'))
            except Exception as e:
                print(f"Register Error: {e}")
                flash('Error creating account', 'error')

    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/attendance')
@login_required
def attendance():
    # Find or create meeting for today (or selected date)
    selected_date_str = request.args.get('date', date.today().isoformat())
    selected_date = date.fromisoformat(selected_date_str)
    
    meeting = Meeting.query.filter_by(date=selected_date).first()
    
    # Auto-create pending meeting if looking at today and it doesn't exist
    if not meeting and selected_date == date.today():
        meeting = Meeting(date=selected_date)
        db.session.add(meeting)
        db.session.commit()
    
    members = Member.query.filter_by(is_active=True).all()
    attendance_map = {}
    
    if meeting:
        records = Attendance.query.filter_by(meeting_id=meeting.id).all()
        attendance_map = {r.member_id: r.status for r in records}
    
    return render_template('attendance.html', 
                           members=members, 
                           attendance_map=attendance_map, 
                           selected_date=selected_date,
                           meeting=meeting,
                           today=date.today())

@app.route('/history')
def history():
    meetings = Meeting.query.order_by(Meeting.date.desc()).all()
    return render_template('history.html', meetings=meetings)

@app.route('/api/mark_attendance', methods=['POST'])
@login_required
def mark_attendance():
    if current_user.role != 'Admin':
        return jsonify({'error': 'Unauthorized'}), 403

    data = request.json
    member_id = data.get('member_id')
    status = data.get('status')
    date_str = data.get('date')
    
    target_date = date.fromisoformat(date_str)
    meeting = Meeting.query.filter_by(date=target_date).first()
    
    if not meeting:
        # Should persist meeting if marking via API date picker
        meeting = Meeting(date=target_date)
        db.session.add(meeting)
        db.session.commit()
        
    record = Attendance.query.filter_by(member_id=member_id, meeting_id=meeting.id).first()
    
    if record:
        record.status = status
    else:
        new_record = Attendance(member_id=member_id, meeting_id=meeting.id, date=target_date, status=status)
        db.session.add(new_record)
        
    db.session.commit()
    return jsonify({'success': True, 'status': status})

@app.route('/api/members', methods=['POST'])
@login_required
def add_member():
    if current_user.role != 'Admin':
        return jsonify({'error': 'Unauthorized'}), 403
        
    data = request.json
    name = data.get('name')
    if not name:
        return jsonify({'error': 'Name required'}), 400
        
    new_member = Member(name=name)
    db.session.add(new_member)
    db.session.commit()
    return jsonify({'success': True, 'member': {'id': new_member.id, 'name': new_member.name}})

@app.route('/api/delete_member/<int:member_id>', methods=['POST'])
@login_required
def delete_member(member_id):
    if current_user.role != 'Admin':
        return jsonify({'error': 'Unauthorized'}), 403
    member = Member.query.get_or_404(member_id)
    member.is_active = False
    db.session.commit()
    return jsonify({'success': True})

@app.route('/meeting/<int:meeting_id>')
def meeting_detail(meeting_id):
    meeting = Meeting.query.get_or_404(meeting_id)
    records = Attendance.query.filter_by(meeting_id=meeting.id).all()
    return render_template('meeting_detail.html', meeting=meeting, records=records)

@app.route('/api/finish_meeting', methods=['POST'])
@login_required
def finish_meeting():
    data = request.json
    meeting_id = data.get('meeting_id')
    meeting = Meeting.query.get_or_404(meeting_id)
    meeting.status = 'Approved'
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/approve_meeting/<int:meeting_id>', methods=['POST'])
@login_required
def approve_meeting(meeting_id):
    if current_user.role != 'Admin':
        return jsonify({'error': 'Unauthorized'}), 403
    meeting = Meeting.query.get_or_404(meeting_id)
    meeting.status = 'Approved'
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/delete_meeting/<int:meeting_id>', methods=['POST'])
@login_required
def delete_meeting(meeting_id):
    if current_user.role != 'Admin':
        return jsonify({'error': 'Unauthorized'}), 403
    meeting = Meeting.query.get_or_404(meeting_id)
    # Delete associated attendance records first
    Attendance.query.filter_by(meeting_id=meeting.id).delete()
    db.session.delete(meeting)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/members')
def members():
    members_list = Member.query.filter_by(is_active=True).all()
    return render_template('members.html', members=members_list)

@app.route('/stats')
def stats():
    timeframe = request.args.get('timeframe', 'all')
    start_date = None
    
    today = date.today()
    if timeframe == '1m':
        start_date = today - timedelta(days=30)
    elif timeframe == '3m':
        start_date = today - timedelta(days=90)
    elif timeframe == '6m':
        start_date = today - timedelta(days=180)
    elif timeframe == '1y':
        start_date = today - timedelta(days=365)
        
    # Base query for aggregation
    members = Member.query.filter_by(is_active=True).all()
    stats_data = []
    
    for member in members:
        # Filter attendance by date if start_date is set
        query = Attendance.query.filter_by(member_id=member.id)
        if start_date:
            query = query.join(Meeting).filter(Meeting.date >= start_date)
            
        records = query.all()
        
        jooga = sum(1 for r in records if r.status == 'Jooga')
        maqan = sum(1 for r in records if r.status == 'Maqan')
        fasax = sum(1 for r in records if r.status == 'Fasax')
        total = jooga + maqan + fasax
        
        score = 0
        if total > 0:
            score = int((jooga / total) * 100)
            
        stats_data.append({
            'member': member,
            'jooga': jooga,
            'maqan': maqan,
            'fasax': fasax,
            'total': total,
            'score': score
        })
        
    # Sort by Score DESC
    stats_data.sort(key=lambda x: x['score'], reverse=True)
    
    return render_template('stats.html', stats=stats_data, timeframe=timeframe)

# --- User Management (Open for Testing) ---

# --- User Management (Protected) ---

@app.route('/users')
@login_required
def users_page():
    if current_user.role != 'Admin':
         return redirect(url_for('index'))
         
    users = User.query.order_by(User.username).all()
    return render_template('users.html', users=users)

@app.route('/api/users', methods=['POST'])
@login_required
def create_user_api():
    if current_user.role != 'Admin':
        return jsonify({'error': 'Unauthorized'}), 403

    data = request.json
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'User')

    if not username or not password:
        return jsonify({'error': 'Missing fields'}), 400
        
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Username taken'}), 400
        
    new_user = User(username=username, role=role)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/users/<int:user_id>/role', methods=['POST'])
@login_required
def update_user_role(user_id):
    if current_user.role != 'Admin':
        return jsonify({'error': 'Unauthorized'}), 403

    data = request.json
    new_role = data.get('role')
    
    user = User.query.get_or_404(user_id)
    user.role = new_role
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user_api(user_id):
    if current_user.role != 'Admin':
        return jsonify({'error': 'Unauthorized'}), 403

    user = User.query.get_or_404(user_id)
    db.session.delete(user)

    db.session.commit()
    return jsonify({'success': True})

# --- Game / Live Room Logic ---

# In-memory storage for active rooms
# Structure: { room_id: { 'host': username, 'viewers': set(), 'created_at': datetime } }
GAME_ROOMS = {}

@app.route('/game')
@login_required
def lobby():
    # Convert sets to counts for template rendering
    active_rooms = {}
    for rid, r in GAME_ROOMS.items():
        active_rooms[rid] = {
            'host': r['host'],
            'viewers': len(r['viewers']),
            'created_at': r['created_at']
        }
    return render_template('lobby.html', rooms=active_rooms)

@app.route('/game/create', methods=['POST'])
@login_required
def create_room():
    room_id = current_user.username 
    
    if room_id not in GAME_ROOMS:
        GAME_ROOMS[room_id] = {
            'host': current_user.username,
            'viewers': set(),
            'created_at': datetime.now()
        }
        # Notify lobby
        socketio.emit('update_lobby', {
            'room_id': room_id,
            'host': current_user.username,
            'viewers': 0,
            'action': 'add'
        }, room='lobby')
    
    return redirect(url_for('game_room', room_id=room_id))

@app.route('/game/<room_id>')
@login_required
def game_room(room_id):
    room = GAME_ROOMS.get(room_id)
    
    if not room:
        if room_id == current_user.username:
             GAME_ROOMS[room_id] = {
                'host': current_user.username,
                'viewers': set(),
                'created_at': datetime.now()
            }
             room = GAME_ROOMS[room_id]
             # Notify lobby
             socketio.emit('update_lobby', {
                'room_id': room_id,
                'host': current_user.username,
                'viewers': 0,
                'action': 'add'
             }, room='lobby')
        else:
            flash("Room does not exist or has ended.", "warning")
            return redirect(url_for('lobby'))
            
    is_host = (current_user.username == room['host'])
    
    # Pass a dict copy to template mainly for 'host' check
    room_data = {
        'host': room['host'],
        'viewers': len(room['viewers'])
    }
    
    return render_template('game.html', user=current_user, room=room_data, room_id=room_id, is_host=is_host)

# --- SocketIO Events ---
@socketio.on('connect')
def handle_connect():
    pass

@socketio.on('join_lobby')
def handle_join_lobby():
    join_room('lobby')

@socketio.on('join_game')
def handle_join_game(data):
    room_id = data.get('room_id')
    if not room_id:
        return
        
    join_room(room_id)
    
    is_host = False
    if room_id in GAME_ROOMS:
        GAME_ROOMS[room_id]['viewers'].add(current_user.username)
        is_host = (current_user.username == GAME_ROOMS[room_id]['host'])
        
        # Update lobby count
        socketio.emit('update_lobby', {
            'room_id': room_id,
            'viewers': len(GAME_ROOMS[room_id]['viewers']),
            'action': 'update'
        }, room='lobby')
        
    # Broadcast join
    emit('user_joined', {
        'username': current_user.username,
        'peerId': data.get('peerId'),
        'isHost': is_host,
        'isAudioOnly': data.get('isAudioOnly', False)
    }, room=room_id, include_self=False)

@socketio.on('request_join')
def handle_request_join(data):
    room_id = data.get('room_id')
    emit('new_join_request', {
        'username': current_user.username,
        'peerId': data.get('peerId'),
        'userId': current_user.id
    }, room=room_id)

@socketio.on('approve_request')
def handle_approve_request(data):
    room_id = data.get('room_id')
    emit('request_approved', {
        'approved': True,
        'targetPeerId': data.get('targetPeerId') 
    }, room=room_id)

@socketio.on('invite_user')
def handle_invite_user(data):
    room_id = data.get('room_id')
    emit('receive_invite', {
        'hostName': current_user.username
    }, room=room_id) 

@socketio.on('disconnect')
def handle_disconnect():
    # Find rooms where user is host
    to_remove = []
    username = current_user.username if current_user.is_authenticated else None
    
    if username:
        for rid, room in GAME_ROOMS.items():
            # If Host Disconnects -> Kill Room
            if room['host'] == username:
                to_remove.append(rid)
            # If Viewer Disconnects -> Remove from set
            elif username in room['viewers']:
                room['viewers'].remove(username)
                socketio.emit('update_lobby', {
                    'room_id': rid,
                    'viewers': len(room['viewers']),
                    'action': 'update'
                }, room='lobby')

    for rid in to_remove:
        del GAME_ROOMS[rid]
        socketio.emit('update_lobby', {
            'room_id': rid,
            'action': 'remove'
        }, room='lobby')

# Auto-fix: Ensure password_hash is long enough (Migration)
try:
    with app.app_context():
        # Check if running on Postgres to use ALTER TABLE
            if 'postgresql' in app.config['SQLALCHEMY_DATABASE_URI']:
                with db.engine.connect() as conn:
                    # 1. Fix password length
                    conn.execute(text('ALTER TABLE "user" ALTER COLUMN password_hash TYPE VARCHAR(512);'))
                    
                    # 2. Add role column if missing
                    try:
                        conn.execute(text('ALTER TABLE "user" ADD COLUMN role VARCHAR(20) DEFAULT \'User\';'))
                        print("Added role column.")
                    except Exception:
                        pass # Column likely exists
                        
                    conn.commit()
                    print("Schema migration checked.")
except Exception as e:
    print(f"Schema check skipped or failed (ignore if table doesn't exist): {e}")

with app.app_context():
    db.create_all()
    
    pass

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5001)

