from flask import Flask, render_template, request, redirect, session, flash
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.secret_key = "secret123"

# MongoDB Atlas
client = MongoClient("mongodb+srv://db_user:db_user@cluster1.ozjbowd.mongodb.net/")
db = client["cyber_project"]

users = db["users"]
records = db["records"]
logs = db["logs"]
alerts = db["alerts"]

def get_ip():
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr

def add_alert(alert_type, message, severity="medium"):
    alerts.insert_one({
        "type": alert_type,
        "message": message,
        "severity": severity,
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

        user = users.find_one({"username": username})

        if user and check_password_hash(user['password'], password):
            session['username'] = username

            logs.insert_one({
                "event": "login_success",
                "username": username,
                "ip": ip,
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })

            return redirect('/dashboard')

        # failed login
        logs.insert_one({
            "event": "login_failed",
            "username": username,
            "ip": ip,
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })

        recent_failures = logs.count_documents({
            "event": "login_failed",
            "ip": ip
        })

        if recent_failures >= 5:
            add_alert(
                "credential_attack",
                f"Multiple failed logins from {ip}",
                "high"
            )

        flash("Invalid Login")

    return render_template("login.html")

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
            "dept": dept
        })

        return redirect('/dashboard')

    return render_template("add_record.html")

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

if __name__ == '__main__':
    app.run(debug=True)