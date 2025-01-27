from flask import Flask, request, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime
from flask_login import LoginManager, UserMixin, login_required, current_user, login_user, logout_user
from flask_bcrypt import Bcrypt
import os

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")

db_url = os.getenv("DB_URL")

app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_BINDS'] = {
    'events': db_url,
    'users': db_url,
    'edithistory': db_url,
    'total_points': db_url
}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['DEBUG'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt()

login_manager = LoginManager()
login_manager.init_app(app)

class TotalPoint(db.Model):
    __tablename__ = 'totalpoint'
    id = db.Column(db.Integer, primary_key=True)
    member_name = db.Column(db.String(50), nullable=False)
    brotherhood_points = db.Column(db.Float, default = 0)
    professionalism_points = db.Column(db.Float, default = 0)
    service_points = db.Column(db.Float, default = 0)
    general_points = db.Column(db.Float, default = 0)
    total_points = db.Column(db.Float, default = 0)
    def calculate_total(self):
        self.total_points = (self.brotherhood_points + self.service_points + self.professionalism_points + self.general_points)
    
class events(db.Model):
    __bind_key__ = 'events'
    __tablename__ = 'events'
    id = db.Column(db.Integer, primary_key=True)
    event_name = db.Column(db.String(100), nullable=False)
    event_type = db.Column(db.String(50), nullable=False)
    date = db.Column(db.Date, nullable=False)
    attendees = db.Column(db.Text)
    points_for_attending = db.Column(db.Float, nullable=False)
    points_for_not_attending = db.Column(db.Float, nullable=False)

class User(db.Model, UserMixin):
    __bind_key__ = 'users'
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default="viewer")
    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

class EditHistory(db.Model):
    __bind_key__ = 'edithistory'
    __tablename__ = 'edithistory'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.Column(db.String(50), nullable=False)
    action = db.Column(db.String(200), nullable=False)
    details = db.Column(db.Text, nullable=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def show_total_points():
    total_points = TotalPoint.query.order_by(TotalPoint.member_name.asc()).all()
    return render_template('total_points.html', total_points=total_points)

@app.route('/events')
def show_events():
    events_all = events.query.all()
    return render_template('events.html', event=events_all)

@app.route('/edit_event/<int:event_id>', methods=['GET', 'POST'])
@app.route('/add_event', methods=['GET', 'POST'])
def add_or_edit_event(event_id=None):
    event = None
    if event_id:
        event = events.query.get_or_404(event_id)
        old_attendees = event.attendees.split(",") if event.attendees else []
        old_event_type = event.event_type
        old_points_for_attending = event.points_for_attending
        old_points_for_not_attending = event.points_for_not_attending

    if request.method == 'POST':
        event_name = request.form['name_of_event']
        event_type = request.form['type_of_event']
        date = datetime.strptime(request.form['date_of_event'], '%Y-%m-%d')
        attendees = ",".join(request.form.getlist('attendees'))
        points_for_attending = float(request.form['points_for_attending'])
        points_for_not_attending = float(request.form['points_for_not_attending'])

        if points_for_not_attending > 0:
            flash("Points for Not Attending must be 0 or a negative value.", "error")
            return redirect(request.url)
        
        if event:
            old_event_details = {
                "event_name": event.event_name,
                "event_type": event.event_type,
                "attendees": old_attendees,
                "points_for_attending": old_points_for_attending,
                "points_for_not_attending": event.points_for_not_attending
            }

            for mem in old_attendees:
                total_point = TotalPoint.query.filter_by(member_name=mem).first()
                if total_point:
                    if old_event_type == "Brotherhood":
                        total_point.brotherhood_points -= old_points_for_attending
                    elif old_event_type == "Professionalism":
                        total_point.professionalism_points -= old_points_for_attending
                    elif old_event_type == "Service":
                        total_point.service_points -= old_points_for_attending
                    else:
                        total_point.general_points -= old_points_for_attending
                    total_point.calculate_total()
                    db.session.add(total_point)
            if old_points_for_not_attending != 0:
                all_members = {member.member_name for member in TotalPoint.query.order_by(TotalPoint.member_name.asc()).all()}
                old_attendees_set = set(old_attendees)
                old_non_attendees = all_members.difference(old_attendees_set)
                for mem in old_non_attendees:
                    total_point = TotalPoint.query.filter_by(member_name=mem).first()
                    if total_point:
                        if old_event_type == "Brotherhood":
                            total_point.brotherhood_points += abs(old_points_for_not_attending)
                        elif old_event_type == "Professionalism":
                            total_point.professionalism_points += abs(old_points_for_not_attending)
                        elif old_event_type == "Service":
                            total_point.service_points += abs(old_points_for_not_attending)
                        else:
                            total_point.general_points += abs(old_points_for_not_attending)
                        total_point.calculate_total()
                        db.session.add(total_point)


            event.event_name = request.form['name_of_event']
            event.event_type = request.form['type_of_event']
            event.date = datetime.strptime(request.form['date_of_event'], '%Y-%m-%d')
            event.attendees = ",".join(request.form.getlist('attendees'))
            event.points_for_attending = float(request.form['points_for_attending'])
            event.points_for_not_attending = float(request.form['points_for_not_attending'])

            new_event_details = {
            "event_name": event.event_name,
            "event_type": event.event_type,
            "attendees": request.form.getlist('attendees'),
            "points_for_attending": event.points_for_attending,
            "points_for_not_attending": event.points_for_not_attending
            }

            log = EditHistory(
                user=current_user.username,
                action="Edited Event",
                details=f"Old: {old_event_details}, New: {new_event_details}"
            )
            db.session.add(log)

        else:
            event_name = request.form['name_of_event']
            event_type = request.form['type_of_event']
            date = datetime.strptime(request.form['date_of_event'], '%Y-%m-%d')
            attendees = ",".join(request.form.getlist('attendees'))
            points_for_attending = float(request.form['points_for_attending'])
            points_for_not_attending = float(request.form['points_for_not_attending'])
            if points_for_not_attending > 0:
                flash("Points for Not Attending must be 0 or a negative value.", "error")
                return redirect(request.url)

            event = events(
                event_name=event_name,
                event_type=event_type,
                date=date,
                attendees=attendees,
                points_for_attending=points_for_attending,
                points_for_not_attending=points_for_not_attending, 
            )
            db.session.add(event)
            log = EditHistory(
                user=current_user.username,
                action="Added Event",
                details=f"Event: {event_name}, Type: {event_type}, Date: {date.strftime('%Y-%m-%d')}, "
                        f"Attendees: {request.form.getlist('attendees')}, "
                        f"Points Attending: {points_for_attending}, Points Not Attending: {points_for_not_attending}"
            )
            db.session.add(log)

        new_attendees = request.form.getlist('attendees')
        new_event_type = request.form['type_of_event']
        new_points_for_attending = float(request.form['points_for_attending'])

        for mem in new_attendees:
            total_point = TotalPoint.query.filter_by(member_name=mem).first()
            if total_point:
                if new_event_type == "Brotherhood":
                    total_point.brotherhood_points += new_points_for_attending
                elif new_event_type == "Professionalism":
                    total_point.professionalism_points += new_points_for_attending
                elif new_event_type == "Service":
                    total_point.service_points += new_points_for_attending
                else:
                    total_point.general_points += new_points_for_attending
                total_point.calculate_total()
                db.session.add(total_point)

        if points_for_not_attending != 0:
            all_members = {member.member_name for member in TotalPoint.query.order_by(TotalPoint.member_name.asc()).all()}
            attendees_set = set(new_attendees)
            non_attendees = all_members.difference(attendees_set)
            for mem in non_attendees:
                total_point = TotalPoint.query.filter_by(member_name=mem).first()
                if total_point:
                    if event_type == "Brotherhood":
                        total_point.brotherhood_points += points_for_not_attending
                    elif event_type == "Professionalism":
                        total_point.professionalism_points += points_for_not_attending
                    elif event_type == "Service":
                        total_point.service_points += points_for_not_attending
                    else:
                        total_point.general_points += points_for_not_attending
                    total_point.calculate_total()
                    db.session.add(total_point)

        db.session.commit()
        return redirect(url_for('show_events'))

    members_all = TotalPoint.query.order_by(TotalPoint.member_name.asc()).all()
    return render_template('form.html', event=event, members=members_all)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash("Logged in successfully!")
            return redirect(url_for('show_total_points'))
        flash("Invalid username or password.")
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    if current_user.role != "admin":
        return redirect(url_for('index'))

    edit_history = EditHistory.query.order_by(EditHistory.timestamp.desc()).all()
    members = TotalPoint.query.all()
    users = User.query.all()
    return render_template('admin_dashboard.html', edit_history=edit_history, members=members, users = users)

@app.route('/add_members', methods=['POST'])
@login_required
def add_members():
    if current_user.role != "admin":
        return redirect(url_for('index'))

    member_names = request.form['members']
    member_list = [name.strip() for name in member_names.split(',')]

    added_members = []
    for member_name in member_list:
        if member_name:
            new_member = TotalPoint(member_name=member_name)
            db.session.add(new_member)
            added_members.append(member_name)

    log = EditHistory(
        user=current_user.username,
        action="Added Members",
        details=f"Added members: {', '.join(added_members)}"
    )
    db.session.add(log)
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/reset_databases', methods=['POST'])
@login_required
def reset_databases():
    if current_user.role != "admin":
        return redirect(url_for('index'))

    User.query.filter(User.username != "vpcomms").delete(synchronize_session=False)
    db.session.query(TotalPoint).delete()
    db.session.query(events).delete()
    db.session.query(EditHistory).delete()
    log = EditHistory(
        user=current_user.username,
        action="Reset Databases",
        details="All data cleared."
    )
    db.session.add(log)

    db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/add_user', methods=['POST'])
@login_required
def add_user():
    if current_user.role != "admin":
        return redirect(url_for('index'))

    username = request.form['username']
    password = request.form['password']
    role = request.form['role']

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        flash(f"Username '{username}' is already taken.", "error")
        return redirect(url_for('admin_dashboard'))

    new_user = User(username=username, role=role)
    new_user.set_password(password)
    db.session.add(new_user)

    log = EditHistory(
        user=current_user.username,
        action="Added User",
        details=f"Added user: {username}, Role: {role}"
    )
    db.session.add(log)

    db.session.commit()
    flash(f"User '{username}' added successfully.", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/reset_points_and_events', methods=['POST'])
@login_required
def reset_points_and_events():
    if current_user.role != "admin":
        return redirect(url_for('index'))

    for member in TotalPoint.query.all():
        member.brotherhood_points = 0
        member.professionalism_points = 0
        member.service_points = 0
        member.general_points = 0
        member.total_points = 0
        db.session.add(member)

    db.session.query(events).delete()
    db.session.query(EditHistory).delete()

    log = EditHistory(
        user=current_user.username,
        action="Reset Points and Events",
        details="All points reset to 0, events and history cleared."
    )
    db.session.add(log)

    db.session.commit()

    flash("All points have been reset to 0, and events and history have been cleared.", "success")
    return redirect(url_for('admin_dashboard'))