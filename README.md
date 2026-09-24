# JobShield AI Pro — Fake Job & Internship Detection System

A Flask + SQLite project designed as a college/internship-ready AI safety platform.

## Major features
- Mandatory Login / Sign Up before accessing the application
- Password hashing with Werkzeug
- 3D animated background using Three.js
- ML scam probability using TF-IDF + Logistic Regression
- Explainable red-flag detection
- Company/domain/recruiter email checks
- Salary/stipend risk analysis
- Public Job URL scanner (extracts readable page text)
- 0–100 Job Safety Score and Low/Medium/High risk levels
- Dashboard with analytics
- Private scan history with search/filter
- Favorite scans
- Delete scans
- CSV export
- Professional PDF report
- Result feedback
- User profile and password update
- Admin dashboard (first registered account becomes admin)
- Responsive dark glassmorphism UI
- Automatic model retraining fallback if the bundled model cannot be loaded with the installed scikit-learn version

## Python 3.13 setup (Windows / VS Code)

Open PowerShell in the `fake_job_detector` folder:

```powershell
python -m venv venv
venv\Scripts\activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt
python app.py
```

Open: http://127.0.0.1:5000

## If scikit-learn still fails

The requirements intentionally use a modern scikit-learn range compatible with Python 3.13. If an old environment has cached packages, recreate the venv:

```powershell
deactivate
Remove-Item -Recurse -Force venv
python -m venv venv
venv\Scripts\activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt
python app.py
```

## Notes
The company verification component is heuristic/local-reference based; it is not a legal or government registry verification. The URL scanner only processes public HTTP/HTTPS pages and blocks private/local network destinations. JobShield is decision support, not a definitive verdict.
