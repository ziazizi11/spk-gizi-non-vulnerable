import os
import sqlite3
import json
import base64
import secrets
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, redirect, jsonify

app = Flask(__name__)

# SECURE: Secret key diambil dari environment variable atau di-generate secara acak kriptografis (CWE-798 Fixed)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)

@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

def get_db_connection():
    conn = sqlite3.connect('gizi.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS food_recommendations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            calories INTEGER NOT NULL,
            protein REAL NOT NULL DEFAULT 0,
            fat REAL NOT NULL DEFAULT 0
        )
    ''')
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM food_recommendations")
    if cursor.fetchone()[0] == 0:
        cursor.executemany(
            "INSERT INTO food_recommendations (name, category, calories, protein, fat) VALUES (?, ?, ?, ?, ?)",
            [
                ('Dada Ayam Panggang', 'Defisit', 165, 31.0, 3.6),
                ('Nasi Merah & Tempe', 'Defisit', 250, 12.0, 5.0),
                ('Alpukat & Telur Rebus', 'Maintenance', 300, 9.0, 22.0),
                ('Susu Full Cream & Pisang', 'Surplus', 450, 11.0, 10.0),
                ('Ikan Salmon Panggang', 'Defisit', 208, 20.0, 13.0),
                ('Daging Sapi Rendang', 'Surplus', 390, 26.0, 21.0),
                ('Salad Sayur & Tahu', 'Defisit', 130, 8.0, 4.0),
                ('Oatmeal & Pisang', 'Maintenance', 220, 7.0, 3.5)
            ]
        )
        conn.commit()
    conn.close()

init_db()

def calculate_saw_ranking(foods, weights=None):
    """
    Menghitung perangkingan makanan menggunakan metode Simple Additive Weighting (SAW).
    Kriteria:
    - Kalori (Cost): semakin rendah kalori semakin baik untuk efisiensi diet defisit
    - Protein (Benefit): semakin tinggi protein semakin baik untuk asupan gizi
    - Lemak (Cost): semakin rendah lemak semakin baik
    """
    if not foods:
        return []
    
    if weights is None:
        weights = {'calories': 0.3, 'protein': 0.5, 'fat': 0.2}

    min_cal = min(f['calories'] for f in foods)
    max_protein = max(f['protein'] for f in foods)
    min_fat = min(f['fat'] for f in foods)

    ranked_results = []
    for food in foods:
        r_cal = (min_cal / food['calories']) if food['calories'] > 0 else 0
        r_protein = (food['protein'] / max_protein) if max_protein > 0 else 0
        r_fat = (min_fat / food['fat']) if food['fat'] > 0 else 0

        v = (weights.get('calories', 0.3) * r_cal) + \
            (weights.get('protein', 0.5) * r_protein) + \
            (weights.get('fat', 0.2) * r_fat)

        ranked_results.append({
            'id': food['id'],
            'name': food['name'],
            'category': food['category'],
            'calories': food['calories'],
            'protein': food['protein'],
            'fat': food['fat'],
            'normalized_scores': {
                'calories': round(r_cal, 4),
                'protein': round(r_protein, 4),
                'fat': round(r_fat, 4)
            },
            'saw_score': round(v, 4)
        })

    ranked_results.sort(key=lambda x: x['saw_score'], reverse=True)
    for rank, item in enumerate(ranked_results, start=1):
        item['rank'] = rank

    return ranked_results

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/calculate', methods=['POST'])
def calculate():
    try:
        weight = float(request.form.get('weight', 0))
    except (ValueError, TypeError):
        weight = 0.0

    try:
        height = float(request.form.get('height', 0))
    except (ValueError, TypeError):
        height = 0.0

    try:
        age = int(request.form.get('age', 0))
    except (ValueError, TypeError):
        age = 0

    gender = request.form.get('gender', 'male')
    goal = request.form.get('goal', 'Defisit')

    # Validasi whitelist untuk kategori goal
    allowed_goals = {'Defisit', 'Maintenance', 'Surplus'}
    if goal not in allowed_goals:
        goal = 'Defisit'

    # Perhitungan BMR (Rumus Mifflin-St Jeor)
    if gender == 'male':
        bmr = (10 * weight) + (6.25 * height) - (5 * age) + 5
    else:
        bmr = (10 * weight) + (6.25 * height) - (5 * age) - 161

    tdee = bmr * 1.375 # Faktor aktivitas sedang

    # SECURE: Menggunakan parameter binding / prepared statement (CWE-89 Fixed)
    conn = get_db_connection()
    foods = conn.execute("SELECT * FROM food_recommendations WHERE category = ?", (goal,)).fetchall()
    conn.close()

    return render_template('result.html', bmr=bmr, tdee=tdee, goal=goal, foods=foods)

@app.route('/search', methods=['GET'])
def search_food():
    keyword = request.args.get('q', '').strip()
    # SECURE: Menggunakan template Jinja2 terpisah dengan autoescape untuk mencegah XSS & SSTI (CWE-79 Fixed)
    return render_template('search.html', keyword=keyword)

@app.route('/export', methods=['POST'])
def export_report():
    user_notes = request.form.get('notes', '')
    
    # SECURE: Menulis data menggunakan file I/O Python standar tanpa shell command (CWE-78 Fixed)
    with open('report_log.txt', 'w', encoding='utf-8') as f:
        f.write(user_notes + '\n')
    
    return render_template('export_success.html', notes=user_notes)

ALLOWED_GUIDES = {'general.txt'}

@app.route('/guide', methods=['GET'])
def view_guide():
    filename = request.args.get('file', 'general.txt')
    safe_filename = secure_filename(filename)
    if safe_filename not in ALLOWED_GUIDES:
        safe_filename = 'general.txt'

    # SECURE: Path Traversal dicegah dengan secure_filename dan whitelist file yang diizinkan (CWE-22 Fixed)
    filepath = os.path.join('guides', safe_filename)
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    if request.args.get('format') == 'raw':
        return content
    return render_template('guide.html', filename=safe_filename, content=content)

@app.route('/spk/saw', methods=['GET', 'POST'])
def spk_saw_rank():
    # Endpoint Fitur SPK 1: Perangkingan Alternatif Makanan dengan metode Simple Additive Weighting (SAW)
    if request.method == 'POST':
        data = request.get_json(silent=True) or request.form
    else:
        data = request.args

    category = data.get('category')
    try:
        w_cal = float(data.get('w_calories', 0.3))
    except (ValueError, TypeError):
        w_cal = 0.3

    try:
        w_protein = float(data.get('w_protein', 0.5))
    except (ValueError, TypeError):
        w_protein = 0.5

    try:
        w_fat = float(data.get('w_fat', 0.2))
    except (ValueError, TypeError):
        w_fat = 0.2

    weights = {'calories': w_cal, 'protein': w_protein, 'fat': w_fat}

    conn = get_db_connection()
    if category:
        foods = conn.execute("SELECT * FROM food_recommendations WHERE category = ?", (category,)).fetchall()
    else:
        foods = conn.execute("SELECT * FROM food_recommendations").fetchall()
    conn.close()

    rankings = calculate_saw_ranking(foods, weights)

    if request.args.get('format') == 'json' or request.is_json:
        return jsonify({
            "status": "success",
            "method": "Simple Additive Weighting (SAW)",
            "weights": weights,
            "total_alternatives": len(rankings),
            "rankings": rankings
        })

    return render_template('saw_rankings.html', rankings=rankings, weights=weights, category=category)

@app.route('/spk/load-profile', methods=['POST'])
def load_spk_profile():
    # Endpoint Fitur SPK 2: Import model / preferensi bobot pengguna tersimpan
    profile_data = request.form.get('profile_data', '')
    if not profile_data and request.is_json:
        profile_data = request.json.get('profile_data', '')

    user_profile = None
    if profile_data:
        # SECURE: Menggunakan JSON parser terstruktur untuk mencegah Insecure Deserialization (CWE-502 Fixed)
        try:
            decoded_bytes = base64.b64decode(profile_data)
            user_profile = json.loads(decoded_bytes.decode('utf-8'))
        except Exception:
            try:
                user_profile = json.loads(profile_data)
            except Exception:
                user_profile = None

    if not isinstance(user_profile, dict):
        user_profile = {'calories': 0.35, 'protein': 0.45, 'fat': 0.20}

    if request.is_json or request.args.get('format') == 'json':
        return jsonify({
            "status": "success",
            "message": "Profil SPK berhasil dimuat",
            "profile": user_profile
        })

    return render_template('profile_loaded.html', profile=user_profile)

ALLOWED_REDIRECT_MAP = {
    'https://promkes.kemkes.go.id': 'https://promkes.kemkes.go.id',
    'https://kemkes.go.id': 'https://kemkes.go.id',
    'https://who.int': 'https://who.int'
}
DEFAULT_REDIRECT = 'https://promkes.kemkes.go.id'

@app.route('/spk/redirect-reference', methods=['GET'])
def redirect_reference():
    # Endpoint Fitur SPK 3: Navigasi dan rujukan ke portal gizi / referensi diet eksternal
    target_url = request.args.get('url', '')
    # SECURE: Validasi URL terhadap whitelist ketat untuk mencegah Open Redirect (CWE-601 Fixed)
    safe_url = ALLOWED_REDIRECT_MAP.get(target_url, DEFAULT_REDIRECT)
    return redirect(safe_url)

if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1')
    app.run(debug=debug_mode, port=5000)
