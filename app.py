from flask import Flask, render_template, request, redirect, session, flash
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = "secret123"

# MongoDB Atlas
client = MongoClient("mongodb+srv://db_user:db_user@cluster1.ozjbowd.mongodb.net/")
db = client["cyber_project"]

users = db["users"]
records = db["records"]
logs = db["logs"]
alerts = db["alerts"]


MAX_ATTEMPTS = 5
BLOCK_TIME = 2  # minutes

def get_ip():
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr

def add_alert(alert_type, message, severity="medium"):
    alert_data = {
        "type": alert_type,
        "message": message,
        "severity": severity,
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    alerts.insert_one(alert_data)

    print("\n ===== ATTACK ALERT =====")
    print(f"Type     : {alert_type}")
    print(f"Severity : {severity}")
    print(f"Message  : {message}")
    print(f"Time     : {alert_data['time']}")
    print(" ========================\n")



def log_event(event, username=None, details=None):
    logs.insert_one({
        "event": event,
        "username": username,
        "ip": get_ip(),
        "details": details,
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })

# ---------------- HOME ----------------
@app.route('/')
def home():
    return render_template("index.html")

# ---------------- REGISTER ----------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        fullname = request.form['fullname']
        email = request.form['email']
        username = request.form['username']
        password = generate_password_hash(request.form['password'])

        if users.find_one({"username": username}):
            flash("Username already exists")
            return redirect('/register')

        users.insert_one({
            "fullname": fullname,
            "email": email,
            "username": username,
            "password": password
        })

        flash("Registration Successful")
        return redirect('/login')

    return render_template("register.html")

# ---------------- LOGIN ----------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        ip = get_ip()
        now = datetime.now()

        # ---------------- BLOCK CHECK ----------------
        blocked = alerts.find_one({
            "ip": ip,
            "type": "blocked",
            "block_until": {"$gt": now}
        })

        if blocked:
            flash("Too many attempts. Try later.")
            return redirect('/login')

        # ---------------- LOGIN CHECK ----------------
        user = users.find_one({"username": username})

        if user and check_password_hash(user['password'], password):

            logs.insert_one({
                "event": "login_success",
                "username": username,
                "ip": ip,
                "time": now
            })

            session['username'] = username
            return redirect('/dashboard')

        # ---------------- FAILED LOGIN ----------------
        logs.insert_one({
            "event": "login_failed",
            "username": username,
            "ip": ip,
            "time": now
        })

        # Count recent failures (last 2 minutes)
        time_window = now - timedelta(minutes=2)

        failures = logs.count_documents({
            "event": "login_failed",
            "ip": ip,
            "time": {"$gte": time_window}
        })

        # ---------------- DETECTION ----------------
        if failures >= MAX_ATTEMPTS:
            print(f"[ALERT] Brute force attack detected from IP: {ip}")
            block_until = now + timedelta(minutes=BLOCK_TIME)

            add_alert(
                "brute_force",
                f"Brute force detected from {ip} (Attempts: {failures})",
                "high"
                )

            alerts.insert_one({
                "type": "blocked",
                "ip": ip,
                "block_until": block_until
            })

            flash("Too many attempts. IP blocked.")
            return redirect('/login')

        flash("Invalid login")

    return render_template("login.html")

@app.before_request
def track_all_requests():
    if request.endpoint not in ['static']:
        log_event("page_visit", session.get('username'), request.path)

# ---------------- DASHBOARD ----------------
@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect('/login')

    all_records = list(records.find())
    return render_template("dashboard.html",
                           username=session['username'],
                           data=all_records)

# ---------------- ADD RECORD ----------------
@app.route('/add_record', methods=['GET', 'POST'])
def add_record():
    if 'username' not in session:
        return redirect('/login')

    if request.method == 'POST':
        rid = request.form['id']
        name = request.form['name']
        salary = request.form['salary']
        dept = request.form['dept']

        records.insert_one({
            "id": rid,
            "name": name,
            "salary": salary,
            "dept": dept,
            "owner": session['username'] #vulnerability
        })

        log_event(
            event="record_added",
            username=session['username'],
            details=f"Added record: {name}, Salary: {salary}, Dept: {dept}"
        )

        return redirect('/dashboard')

# ---------------- LOGOUT ----------------
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/alerts')
def view_alerts():
    if 'username' not in session:
        return redirect('/login')

    all_alerts = list(alerts.find().sort("_id", -1))
    print(all_alerts)
    return render_template("alerts.html", data=all_alerts)

@app.route('/record/<rid>')
def view_record(rid):
    if 'username' not in session:
        return redirect('/login')

    ip = request.remote_addr
    username = session['username']

    record = records.find_one({"id": rid})

    if not record:
        return "Record not found"

    # VULNERABILITY: no ownership check, Anyone can view any record by changing ID

    # forensic log
    logs.insert_one({
        "event": "record_access",
        "record_id": rid,
        "accessed_by": username,
        "owner": record.get("owner"),
        "ip": ip,
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })

    return render_template("view_record.html", record=record)

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)
    