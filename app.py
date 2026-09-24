import os, io, json, csv, re, ipaddress, socket
from functools import wraps
from datetime import datetime
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, Response, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

from database import get_db, init_db, now_iso
from ml.detector import detector
from utils.pdf_report import build_pdf_report

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "jobshield-change-this-secret")
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in or create an account to use JobShield AI.", "warning")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("is_admin"):
            flash("Admin access required.", "danger")
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)
    return wrapped


def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    conn = get_db(); user = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone(); conn.close()
    return user


@app.context_processor
def inject_globals():
    return {"current_user": current_user(), "detector_status": detector.model_status}


@app.route("/")
def index():
    if not session.get("user_id"):
        return redirect(url_for("login"))
    return render_template("index.html")


@app.route("/about")
@login_required
def about():
    return render_template("about.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,30}", username):
            flash("Username must be 3–30 characters and use letters, numbers, dot, underscore or hyphen.", "danger")
            return render_template("register.html")
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            flash("Please enter a valid email address.", "danger"); return render_template("register.html")
        if len(password) < 8 or not any(c.isdigit() for c in password):
            flash("Password must be at least 8 characters and contain a number.", "danger"); return render_template("register.html")
        if password != confirm:
            flash("Passwords do not match.", "danger"); return render_template("register.html")
        conn = get_db()
        exists = conn.execute("SELECT id FROM users WHERE username=? OR email=?", (username, email)).fetchone()
        if exists:
            conn.close(); flash("Username or email is already registered.", "danger"); return render_template("register.html")
        first = conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"] == 0
        conn.execute("INSERT INTO users(username,email,password_hash,is_admin,created_at) VALUES(?,?,?,?,?)", (username,email,generate_password_hash(password),int(first),now_iso()))
        conn.commit(); conn.close()
        flash("Account created. Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        identifier = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        conn = get_db(); user = conn.execute("SELECT * FROM users WHERE username=? OR email=?", (identifier, identifier.lower())).fetchone(); conn.close()
        if user and check_password_hash(user["password_hash"], password):
            session.clear(); session["user_id"] = user["id"]; session["username"] = user["username"]; session["is_admin"] = bool(user["is_admin"])
            flash(f"Welcome back, {user['username']}!", "success")
            return redirect(request.args.get("next") or url_for("dashboard"))
        flash("Invalid username/email or password.", "danger")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear(); flash("You have been logged out.", "info"); return redirect(url_for("login"))


def save_check(result, data):
    conn = get_db()
    cur = conn.execute("""INSERT INTO checks(user_id,company_name,company_url,contact_email,job_text,salary_text,ml_probability,rule_score,company_confidence,final_score,risk_level,flags_json,notes_json,recs_json,created_at)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (session["user_id"], data["company_name"], data["company_url"], data["contact_email"], data["job_text"], data["salary_text"], result["ml_probability"], result["rule_score"], result["company_confidence"], result["final_score"], result["risk_level"], json.dumps(result["flags"]), json.dumps(result["company_notes"]), json.dumps(result["recommendations"]), now_iso()))
    conn.commit(); cid = cur.lastrowid; conn.close(); return cid


def collect_form():
    return {k: request.form.get(k, "").strip() for k in ["job_text","company_name","company_url","contact_email","salary_text"]}


@app.route("/check", methods=["POST"])
@login_required
def check():
    data = collect_form()
    if len(data["job_text"]) < 20:
        flash("Paste at least 20 characters of the job description.", "danger"); return redirect(url_for("index"))
    result = detector.analyze(**data)
    cid = save_check(result, data)
    return render_template("result.html", result=result, company_name=data["company_name"], company_url=data["company_url"], contact_email=data["contact_email"], check_id=cid)


@app.route("/scan-url", methods=["POST"])
@login_required
def scan_url():
    raw = request.form.get("job_url", "").strip()
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    try:
        parsed = urlparse(raw)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("Invalid URL")
        host = parsed.hostname
        for info in socket.getaddrinfo(host, None):
            ip = ipaddress.ip_address(info[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                raise ValueError("Private/local URLs are not allowed")
        response = requests.get(raw, timeout=8, headers={"User-Agent":"JobShieldAI/2.0"}, allow_redirects=True)
        response.raise_for_status()
        if len(response.content) > 3_000_000:
            raise ValueError("Page is too large")
        soup = BeautifulSoup(response.text, "html.parser")
        for tag in soup(["script","style","noscript"]): tag.decompose()
        text = " ".join(soup.stripped_strings)
        text = re.sub(r"\s+", " ", text)
        if len(text) < 20:
            raise ValueError("Could not extract enough readable job text from this page")
        title = soup.title.get_text(strip=True) if soup.title else parsed.netloc
        result = detector.analyze(text[:12000], company_name=parsed.netloc, company_url=raw)
        cid = save_check(result, {"job_text": text[:12000], "company_name": parsed.netloc, "company_url": raw, "contact_email":"", "salary_text":""})
        return render_template("result.html", result=result, company_name=parsed.netloc, company_url=raw, contact_email="", check_id=cid, source_title=title)
    except Exception as exc:
        flash(f"URL scan could not be completed: {exc}", "danger")
        return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    conn=get_db(); uid=session["user_id"]
    recent=conn.execute("SELECT * FROM checks WHERE user_id=? ORDER BY created_at DESC LIMIT 6",(uid,)).fetchall()
    total=conn.execute("SELECT COUNT(*) c FROM checks WHERE user_id=?",(uid,)).fetchone()["c"]
    avg=conn.execute("SELECT COALESCE(AVG(final_score),0) a FROM checks WHERE user_id=?",(uid,)).fetchone()["a"]
    by=conn.execute("SELECT risk_level,COUNT(*) c FROM checks WHERE user_id=? GROUP BY risk_level",(uid,)).fetchall()
    fav=conn.execute("SELECT COUNT(*) c FROM favorites WHERE user_id=?",(uid,)).fetchone()["c"]
    conn.close(); risks={"Low":0,"Medium":0,"High":0}; [risks.__setitem__(r["risk_level"],r["c"]) for r in by]
    return render_template("dashboard.html", checks=recent,total=total,avg_score=round(avg,1),risk_counts=risks,favorites=fav)


@app.route("/history")
@login_required
def history():
    conn=get_db(); rows=conn.execute("SELECT c.*, CASE WHEN f.id IS NULL THEN 0 ELSE 1 END favorite FROM checks c LEFT JOIN favorites f ON f.check_id=c.id AND f.user_id=? WHERE c.user_id=? ORDER BY c.created_at DESC",(session["user_id"],session["user_id"])).fetchall(); conn.close()
    return render_template("history.html", checks=rows)


@app.post("/favorite/<int:check_id>")
@login_required
def favorite(check_id):
    conn=get_db(); owned=conn.execute("SELECT id FROM checks WHERE id=? AND user_id=?",(check_id,session["user_id"])).fetchone()
    if not owned: conn.close(); return jsonify(ok=False,error="Not found"),404
    existing=conn.execute("SELECT id FROM favorites WHERE user_id=? AND check_id=?",(session["user_id"],check_id)).fetchone()
    if existing: conn.execute("DELETE FROM favorites WHERE id=?",(existing["id"],)); state=False
    else: conn.execute("INSERT INTO favorites(user_id,check_id,created_at) VALUES(?,?,?)",(session["user_id"],check_id,now_iso())); state=True
    conn.commit(); conn.close(); return jsonify(ok=True,favorite=state)


@app.post("/history/delete/<int:check_id>")
@login_required
def delete_check(check_id):
    conn=get_db(); conn.execute("DELETE FROM checks WHERE id=? AND user_id=?",(check_id,session["user_id"])); conn.commit(); conn.close(); flash("Scan removed from your history.","info"); return redirect(url_for("history"))


@app.route("/export.csv")
@login_required
def export_csv():
    conn=get_db(); rows=conn.execute("SELECT company_name,company_url,final_score,risk_level,created_at FROM checks WHERE user_id=? ORDER BY created_at DESC",(session["user_id"],)).fetchall(); conn.close()
    out=io.StringIO(); writer=csv.writer(out); writer.writerow(["Company","Website","Risk Score","Risk Level","Date"]); writer.writerows([[r["company_name"],r["company_url"],r["final_score"],r["risk_level"],r["created_at"]] for r in rows]); return Response(out.getvalue(),mimetype="text/csv",headers={"Content-Disposition":"attachment; filename=jobshield_history.csv"})


@app.route("/report/<int:check_id>.pdf")
@login_required
def report_pdf(check_id):
    conn=get_db(); row=conn.execute("SELECT * FROM checks WHERE id=? AND user_id=?",(check_id,session["user_id"])).fetchone(); conn.close()
    if not row: return "Not found",404
    return send_file(build_pdf_report(row),as_attachment=True,download_name=f"JobShield_Report_{check_id}.pdf",mimetype="application/pdf")


@app.post("/feedback/<int:check_id>")
@login_required
def feedback(check_id):
    rating=max(1,min(5,int(request.form.get("rating",5)))); comment=request.form.get("comment","").strip()[:500]
    conn=get_db(); conn.execute("INSERT INTO feedback(user_id,check_id,rating,comment,created_at) VALUES(?,?,?,?,?)",(session["user_id"],check_id,rating,comment,now_iso())); conn.commit(); conn.close(); flash("Thanks for your feedback!", "success"); return redirect(url_for("history"))


@app.route("/profile", methods=["GET","POST"])
@login_required
def profile():
    conn=get_db(); user=conn.execute("SELECT * FROM users WHERE id=?",(session["user_id"],)).fetchone()
    if request.method=="POST":
        email=request.form.get("email","").strip().lower(); newpass=request.form.get("new_password","")
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+",email): flash("Enter a valid email.","danger")
        else:
            if newpass:
                if len(newpass)<8 or not any(c.isdigit() for c in newpass): flash("New password must be 8+ characters and contain a number.","danger"); conn.close(); return render_template("profile.html",user=user)
                conn.execute("UPDATE users SET email=?,password_hash=? WHERE id=?",(email,generate_password_hash(newpass),user["id"]))
            else: conn.execute("UPDATE users SET email=? WHERE id=?",(email,user["id"]))
            conn.commit(); flash("Profile updated successfully.","success")
        user=conn.execute("SELECT * FROM users WHERE id=?",(session["user_id"],)).fetchone()
    stats=conn.execute("SELECT COUNT(*) total,COALESCE(AVG(final_score),0) avg FROM checks WHERE user_id=?",(session["user_id"],)).fetchone(); conn.close(); return render_template("profile.html",user=user,stats=stats)


@app.route("/admin")
@admin_required
def admin_panel():
    conn=get_db(); users=conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]; checks=conn.execute("SELECT COUNT(*) c FROM checks").fetchone()["c"]; high=conn.execute("SELECT COUNT(*) c FROM checks WHERE risk_level='High'").fetchone()["c"]; recent=conn.execute("SELECT c.*,u.username FROM checks c JOIN users u ON u.id=c.user_id ORDER BY c.created_at DESC LIMIT 12").fetchall(); conn.close(); return render_template("admin.html",total_users=users,total_checks=checks,high=high,recent=recent)


@app.errorhandler(404)
def not_found(e): return render_template("404.html"),404


@app.errorhandler(500)
def server_error(e): return render_template("500.html"),500


init_db()

if __name__ == "__main__":
    app.run(debug=True)
