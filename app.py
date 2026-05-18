import os
import re
import traceback
from sqlalchemy import text, select
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.utils import secure_filename
import pandas as pd
from sqlalchemy import create_engine, Column, Integer, String, Text, MetaData, Table
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from collections import Counter

# -------------------------
# Load env
# -------------------------
load_dotenv()

# -------------------------
# Config
# -------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET","change-this-secret")
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16*1024*1024

# -------------------------
# DB
# -------------------------
# NOTE: Please ensure your MySQL server is running and database 'mini_project_db' exists.
DB_USER = os.getenv("DB_USER","root")
DB_PASSWORD = os.getenv("DB_PASSWORD","")
DB_HOST = os.getenv("DB_HOST","localhost")
DB_NAME = os.getenv("DB_NAME","mini_project_db")

if DB_PASSWORD.strip()=="":
    DB_URI = f"mysql+mysqlconnector://{DB_USER}@{DB_HOST}/{DB_NAME}"
else:
    DB_URI = f"mysql+mysqlconnector://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}"

engine = create_engine(DB_URI, echo=False, future=True)
metadata = MetaData()

# -------------------------
# Tables
# -------------------------
logs_table = Table(
    "firewall_logs", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("timestamp", String(64)),
    Column("src_ip", String(64)),
    Column("dst_ip", String(64)),
    Column("protocol", String(16)),
    Column("src_port", Integer),
    Column("dst_port", Integer),
    Column("action", String(16)),
    Column("raw", Text),
    Column("is_anomaly", Integer)
)

users_table = Table(
    "users", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("username", String(50), unique=True, nullable=False),
    Column("email", String(100), unique=True, nullable=False),
    Column("password", String(255), nullable=False)
)

# Create tables in the database
try:
    metadata.create_all(engine)
except Exception as e:
    print(f"Database Initialization Error: {e}")
    traceback.print_exc()

# -------------------------
# Log parser
# -------------------------
def parse_line(line):
    if not line.strip():
        return None
    try:
        ts_match = re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", line)
        timestamp = ts_match.group(0) if ts_match else datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        kv_pairs = re.findall(r"(\w+)=([\w\.\:\-]+)", line)
        log_dict = {k.lower(): v for k, v in kv_pairs}

        def safe_int(s):
            try:
                return int(s)
            except (ValueError, TypeError):
                return 0

        src_ip = log_dict.get("src_ip", "0.0.0.0")
        dst_ip = log_dict.get("dst_ip", "0.0.0.0")
        src_port = safe_int(log_dict.get("src_port", "0"))
        dst_port = safe_int(log_dict.get("dst_port", "0"))
        protocol = log_dict.get("protocol", "UNK")
        action = log_dict.get("action", "UNK").upper()

        return {
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "action": action,
            "raw": line.strip(),
            "is_anomaly": 0
        }
    except Exception as e:
        print(f"❌ Error parsing log line: '{line.strip()}' -> {e}")
        return None

# -------------------------
# Log fetching helper (Finalized)
# -------------------------
def get_logs_df():
    """Fetch all logs from the database as a reliable Pandas DataFrame."""
    try:
        # pd.read_sql_table is the most reliable method for loading tables
        df = pd.read_sql_table(logs_table.name, engine)

        if df.empty:
            print("DEBUG: get_logs_df returned an empty DataFrame.")
            return pd.DataFrame()

        # FIX 1: Ensure IP address column is explicitly a string type (critical for high traffic grouping)
        df['src_ip'] = df['src_ip'].astype(str).fillna('0.0.0.0')

        # Data types ko sahi karna
        for col in ['src_port', 'dst_port', 'is_anomaly']:
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0).astype(int)

        df['dst_ip'] = df['dst_ip'].fillna('0.0.0.0').astype(str)
        df['protocol'] = df['protocol'].fillna('UNK').astype(str)
        df['action'] = df['action'].fillna('UNK').astype(str).str.upper()
        df['timestamp'] = df['timestamp'].astype(str).fillna('N/A')
        
        print(f"DEBUG: Successfully loaded {len(df)} logs.")
        return df

    except Exception as e:
        print(f"❌ Critical Error fetching logs into DataFrame: {e}")
        traceback.print_exc()
        return pd.DataFrame()


# -------------------------
# Routes
# -------------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/dashboard")
def dashboard():
    if 'user_id' not in session:
        flash("Please login first!", "error")
        return redirect(url_for('login'))
    conn = engine.connect()
    recent_logs = []
    total = 0
    try:
        total = conn.execute(select(text("COUNT(*)")).select_from(logs_table)).scalar()
        if total is None:
            total = 0
        
        logs_query = logs_table.select().order_by(logs_table.c.id.desc()).limit(10)
        recent_logs_query = conn.execute(logs_query).mappings().all()
        
        for log in recent_logs_query:
            log_dict = dict(log)
            log_dict['src_port'] = int(log_dict.get('src_port', 0) or 0)
            log_dict['dst_port'] = int(log_dict.get('dst_port', 0) or 0)
            log_dict['is_anomaly'] = int(log_dict.get('is_anomaly', 0) or 0)
            log_dict['timestamp'] = str(log_dict.get('timestamp', 'N/A'))
            recent_logs.append(log_dict)

    except Exception as e:
        print(f"Dashboard DB error: {e}")
        traceback.print_exc()
        total = 0
        recent_logs = []
    finally:
        conn.close()
    
    return render_template("dashboard.html", 
                           username=session.get('username','User'), 
                           total_logs=total, 
                           recent_logs=recent_logs)

@app.route("/upload_file", methods=["POST"])
def upload_file():
    if "logfile" not in request.files:
        flash("No file has been chosen", "error")
        return redirect(url_for("dashboard"))

    file = request.files["logfile"]
    if file.filename == "":
        flash("No file selected", "error")
        return redirect(url_for("dashboard"))

    if file and file.filename.endswith((".log",".txt")):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        try:
            parsed_logs = []
            with open(filepath, "r") as f:
                for line in f:
                    parsed = parse_line(line.strip())
                    if parsed:
                        parsed_logs.append(parsed)

            df = pd.DataFrame(parsed_logs)

            if not df.empty:
                try:
                    df['src_port'] = pd.to_numeric(df['src_port'], errors='coerce').fillna(0).astype(int)
                    df['dst_port'] = pd.to_numeric(df['dst_port'], errors='coerce').fillna(0).astype(int)
                except Exception as e:
                    print(f"Port conversion error during upload: {e}")

                df['is_anomaly'] = 0
                restricted_ports = {21,22,23,25,110,143,445,3389}

                for i, row in df.iterrows():
                    src_ip = row.get('src_ip','')
                    dst_port = row.get('dst_port',0)
                    action = row.get('action','').upper()
                    
                    # Rule 1: Suspicious external IP trying block action
                    if src_ip and not (src_ip.startswith(("192.","10.","172."))) and action in {"DENY","REJECT","DROP"}:
                        df.at[i,'is_anomaly'] = 1
                    
                    # Rule 2: Accessing restricted port
                    if dst_port in restricted_ports:
                        df.at[i,'is_anomaly'] = 1

                df['timestamp'] = df['timestamp'].astype(str)

                # Prepare records for bulk insert
                records = df.to_dict(orient='records')

                # Save records to DB
                conn = engine.connect()
                try:
                    with conn.begin():
                        conn.execute(logs_table.delete()) # remove old logs
                        if records:
                            conn.execute(logs_table.insert(), records)
                finally:
                    conn.close()

                total_anomalies = df['is_anomaly'].sum() if not df.empty else 0
                
                if total_anomalies > 0:
                    flash(f"⚠️ File uploaded! {total_anomalies} suspicious logs found.", "warning")
                else:
                    flash("✅ File uploaded! No anomalies found.", "success")
            
            else:
                flash("No valid logs found in the file.", "info")


        except Exception as e:
            print("❌ Error while processing the file:", e)
            traceback.print_exc()
            flash("❌ Error during file analysis. Please check server logs.", "error")
            
        return redirect(url_for('dashboard')) 

    else:
        flash("Invalid file type. Please upload a .log or .txt file", "error")
        return redirect(url_for("dashboard"))


# =====================================================
# Detection Routes 
# =====================================================

def render_detection_results(df, message, type):
    """A helper to render detection results on a common template."""
    if df.empty:
        flash("⚠️ No log data found. Please upload a file first.", "warning")
        return render_template("_results.html", recent_logs=[], results_title="Detection Results")

    # Convert DataFrame to list of dicts
    recent_logs = df.to_dict(orient='records')
    
    flash(message, type)
    return render_template("_results.html", recent_logs=recent_logs, results_title="Detection Results")

@app.route("/detect_failed_connections")
def detect_failed_connections():
    if 'user_id' not in session:
        flash("Please login first!", "error")
        return redirect(url_for('login'))

    df = get_logs_df()
    failed = df[df['action'].isin(["DENY", "DROP", "REJECT"])].copy()
    failed.loc[:, 'is_anomaly'] = 1 
    
    message = f"✅ Analysis complete! {len(failed)} failed connections found."
    return render_detection_results(failed, message, "info")

@app.route("/detect_unusual_ip")
def detect_unusual_ip():
    if 'user_id' not in session:
        flash("Please login first!", "error")
        return redirect(url_for("login"))

    df = get_logs_df()
    trusted_prefixes = ("192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", 
                        "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", 
                        "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "127.", "0.")
    
    def is_trusted(ip):
        return any(ip.startswith(prefix) for prefix in trusted_prefixes)

    unusual = df[~df['src_ip'].apply(is_trusted)].copy()
    unusual.loc[:, 'is_anomaly'] = 1

    message = (f"⚠️ {len(unusual)} unusual IP activities found."
               if len(unusual) else "✅ All IPs appear to be trusted/local.")
    
    return render_detection_results(unusual, message, "warning" if len(unusual) else "success")

@app.route("/detect_high_traffic")
def detect_high_traffic():
    if 'user_id' not in session:
        flash("Please login first!", "error")
        return redirect(url_for("login"))

    df = get_logs_df()
    if df.empty:
        return render_detection_results(df, "⚠️ No log data found.", "warning")

    # Ensure IP column is treated as strings for counting
    df['src_ip'] = df['src_ip'].astype(str)
    
    ip_counts = df['src_ip'].value_counts()
    
    # FIX 2 (College Demo Optimized): Logic ko zyada sensitive banaya. 
    # Threshold ab 1.1 times average hai, taki 5 logs wale IPs bhi detect ho jayein.
    avg_count = ip_counts.mean() if not ip_counts.empty else 0
    # Threshold is now 1.1 times the average, but MUST be at least 5 to count as high traffic.
    threshold = max(avg_count * 1.1, 5.0) 
    
    high_traffic_ips = ip_counts[ip_counts >= threshold].index.tolist()
    
    high_traffic_logs = df[df['src_ip'].isin(high_traffic_ips)].copy()
    high_traffic_logs.loc[:, 'is_anomaly'] = 1

    message = (f"⚠️ {len(high_traffic_ips)} High traffic detected from IP(s). (Threshold: {round(threshold, 2)} logs)"
               if high_traffic_ips else "✅ No high traffic sources found.")
    
    return render_detection_results(high_traffic_logs, message, "warning" if high_traffic_ips else "success")


@app.route("/detect_restricted_ports")
def detect_restricted_ports():
    if 'user_id' not in session:
        flash("Please login first!", "error")
        return redirect(url_for('login'))

    df = get_logs_df()
    restricted_ports = {21,22,23,25,110,143,445,3389}
    restricted_logs = df[df['dst_port'].isin(restricted_ports)].copy()
    restricted_logs.loc[:, 'is_anomaly'] = 1

    message = (f"⚠️ {len(restricted_logs)} Logs are reaching restricted ports!"
               if len(restricted_logs) else "✅ No restricted port access found.")
    
    return render_detection_results(restricted_logs, message, "warning" if len(restricted_logs) else "success")


@app.route("/detect_packet_drops")
def detect_packet_drops():
    if 'user_id' not in session:
        flash("Please login first!", "error")
        return redirect(url_for('login'))

    df = get_logs_df()
    dropped_logs = df[df['action'].isin(["DROP", "REJECT"])].copy() 
    dropped_logs.loc[:, 'is_anomaly'] = 1

    message = (f"⚠️ {len(dropped_logs)} Rejected/Dropped packets found."
               if len(dropped_logs) else "✅ No packet drops found.")
    
    return render_detection_results(dropped_logs, message, "warning" if len(dropped_logs) else "success")


@app.route("/detect_anomalies_full")
def detect_anomalies_full():
    if 'user_id' not in session:
        flash("Please login first!", "error")
        return redirect(url_for('login'))

    df = get_logs_df()
    anomalous_logs = df[df['is_anomaly'] == 1].copy()

    total_anomalies = len(anomalous_logs)
    message = (f"⚠️ Analysis complete! {total_anomalies} Suspicious logs found."
               if total_anomalies else "✅ Analysis complete! No anomalies found.")
    
    return render_detection_results(anomalous_logs, message, "warning" if total_anomalies else "success")

# -------------------------
# History
# -------------------------
@app.route("/history")
def history():
    if 'user_id' not in session:
        flash("Please login first!", "error")
        return redirect(url_for('login'))
    
    conn = engine.connect()
    db_rows = []
    try:
        rows = conn.execute(logs_table.select().order_by(logs_table.c.id.desc()).limit(200)).mappings().all()
        
        for row in rows:
            row_dict = dict(row)
            row_dict['src_port'] = int(row_dict.get('src_port', 0) or 0)
            row_dict['dst_port'] = int(row_dict.get('dst_port', 0) or 0)
            row_dict['is_anomaly'] = int(row_dict.get('is_anomaly', 0) or 0)
            row_dict['timestamp'] = str(row_dict.get('timestamp', 'N/A'))
            db_rows.append(row_dict)
    except Exception as e:
        print(f"History DB error: {e}")
        db_rows = []
    finally:
        conn.close()

    return render_template("_results.html", 
                           recent_logs=db_rows, 
                           results_title="Full Log History (Last 200 Entries)")

# -------------------------
# Auth
# -------------------------
@app.route("/login", methods=["GET","POST"])
def login():
    if request.method=="POST":
        email = request.form.get("email")
        password = request.form.get("password")
        conn = engine.connect()
        try:
            user = conn.execute(users_table.select().where(users_table.c.email==email)).mappings().first()
            if user and check_password_hash(user['password'],password):
                session['user_id']=user['id']
                session['username']=user['username']
                flash("Login Successful!","success")
                return redirect(url_for("dashboard"))
            else:
                flash("Invalid email or password","error") 
        except:
            flash("There is a database error","error") 
        finally:
            conn.close()
    return render_template("login.html")

@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username")
    email = request.form.get("email")
    password = request.form.get("password")
    if not username or not email or not password:
        flash("All fields are required","error")
        return redirect(url_for("login"))
    hashed = generate_password_hash(password)
    conn = engine.connect()
    try:
        with conn.begin():
            conn.execute(users_table.insert().values(username=username,email=email,password=hashed))
        flash("Registration Successful! Please log in.","success") 
    except:
        flash("DB error: This user may already be registered.","error") 
    finally:
        conn.close()
    return redirect(url_for("login"))

@app.route("/logout")
def logout():
    session.clear()
    flash("Logout Successful!","success") 
    return redirect(url_for("login"))

# -------------------------
# Run App
# -------------------------
if __name__=="__main__":
    os.makedirs(os.path.join(BASE_DIR, "templates"), exist_ok=True)
    app.run(debug=True)
