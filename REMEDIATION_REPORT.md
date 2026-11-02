# Laporan Remediasi Kerentanan (Non-Vulnerable Benchmark)
## Objek Penelitian: Sistem Pendukung Keputusan (SPK) Rekomendasi Menu Gizi

Dokumen ini mendokumentasikan perbaikan keamanan yang diterapkan pada repositori **`spk-gizi-non-vulnerable`** agar seluruh kerentanan keamanan yang sebelumnya disisipkan pada **`spk-gizi-vulnerable`** dihilangkan sepenuhnya, sehingga menjadi *clean benchmark* untuk pengujian akurasi alat Static Application Security Testing (SAST).

---

### Ringkasan Remediasi Kerentanan

| ID | Kategori CWE | Tipe Kerentanan | Status Sebelum Remediasi (`vulnerable`) | Status Sesudah Remediasi (`non-vulnerable`) |
| :--- | :--- | :--- | :--- | :--- |
| **VULN-001** | CWE-798 | Hardcoded Credentials | Hardcoded secret key statis di `app.py` | Menggunakan `os.environ.get()` dengan fallback `secrets.token_hex(32)` acak |
| **VULN-002** | CWE-89 | SQL Injection | Konkatenasi string langsung pada SQL query: `f"... category = '{goal}'"` | Menggunakan *Parameterized Query / Prepared Statement* (`?`) dan validasi whitelist input |
| **VULN-003** | CWE-79 | Cross-Site Scripting (Reflected XSS) | Format string mentah ke `render_template_string(html_response)` | Template Jinja2 mandiri (`search.html`) dengan *context-aware auto-escaping* |
| **VULN-004** | CWE-78 | OS Command Injection | Eksekusi shell `os.system(f"echo '{user_notes}' > ...")` | Native Python file I/O (`with open(...)`) tanpa memanggil shell/subproses OS |
| **VULN-005** | CWE-22 | Path Traversal / LFI | Membaca berkas langsung via `os.path.join('guides', filename)` | Sanitasi nama berkas via `secure_filename()` dan validasi *whitelist* |
| **VULN-006** | CWE-502 | Insecure Deserialization | Deserialisasi untrusted data menggunakan `pickle.loads()` | Mengganti `pickle` dengan parsing terstruktur format JSON (`json.loads()`) |
| **VULN-007** | CWE-601 | Open Redirect (Untrusted URL Redirection) | Redirect langsung ke parameter input pengguna `redirect(target_url)` | Validasi pemetaan terhadap *whitelist* domain dan URL rujukan resmi |
| **HARDENING** | CWE-489 | Flask Debug Mode Active | `app.run(debug=True)` terekspos | `debug_mode` dikendalikan via environment variable (default: `False`) |
| **HARDENING** | - | Missing Security Headers | Tidak ada HTTP security headers | Menambahkan header `X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection` |

---

### Detail Implementasi Perbaikan

#### 1. VULN-001: CWE-798 - Hardcoded Credentials
- **File**: `app.py`
- **Sebelumnya**:
  ```python
  app.secret_key = "super_secret_hardcoded_key_12345"
  ```
- **Perbaikan**:
  ```python
  app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
  ```
- **Keterangan**: Kunci rahasia diambil dari variabel lingkungan (*environment variable*) pada server produksi atau digenerasi secara acak menggunakan modul `secrets` standar Python yang memenuhi standar CSPRNG (*Cryptographically Secure Pseudo-Random Number Generator*).

---

#### 2. VULN-002: CWE-89 - SQL Injection
- **File**: `app.py` (Route `/calculate`)
- **Sebelumnya**:
  ```python
  query = f"SELECT * FROM food_recommendations WHERE category = '{goal}'"
  foods = conn.execute(query).fetchall()
  ```
- **Perbaikan**:
  ```python
  allowed_goals = {'Defisit', 'Maintenance', 'Surplus'}
  if goal not in allowed_goals:
      goal = 'Defisit'

  conn = get_db_connection()
  foods = conn.execute("SELECT * FROM food_recommendations WHERE category = ?", (goal,)).fetchall()
  conn.close()
  ```
- **Keterangan**: Memisahkan instruksi SQL dari data masukan pengguna dengan *parameter binding*, didukung validasi *whitelist* kategori gizi.

---

#### 3. VULN-003: CWE-79 - Reflected Cross-Site Scripting (XSS)
- **File**: `app.py` & `templates/search.html` (Route `/search`)
- **Sebelumnya**:
  ```python
  html_response = f"""... <strong>{keyword}</strong> ..."""
  return render_template_string(html_response)
  ```
- **Perbaikan**:
  ```python
  @app.route('/search', methods=['GET'])
  def search_food():
      keyword = request.args.get('q', '').strip()
      return render_template('search.html', keyword=keyword)
  ```
  Di dalam `templates/search.html`:
  ```html
  <div class="query-box">Kata kunci pencarian: <strong>{{ keyword }}</strong></div>
  ```
- **Keterangan**: Menghapus penggunaan `render_template_string()` yang rentan terhadap SSTI dan XSS, memindahkannya ke berkas template Jinja2 terpisah yang secara otomatis melakukan *HTML entity escaping*.

---

#### 4. VULN-004: CWE-78 - Command Injection
- **File**: `app.py` (Route `/export`)
- **Sebelumnya**:
  ```python
  os.system(f"echo '{user_notes}' > report_log.txt")
  ```
- **Perbaikan**:
  ```python
  with open('report_log.txt', 'w', encoding='utf-8') as f:
      f.write(user_notes + '\n')
  ```
- **Keterangan**: Menggunakan fungsi bawaan Python `open()` dengan mode tulis UTF-8. Tidak ada shell atau perintah sistem operasi yang dipanggil.

---

#### 5. VULN-005: CWE-22 - Path Traversal
- **File**: `app.py` (Route `/guide`)
- **Sebelumnya**:
  ```python
  filepath = os.path.join('guides', filename)
  with open(filepath, 'r') as f:
      content = f.read()
  ```
- **Perbaikan**:
  ```python
  ALLOWED_GUIDES = {'general.txt'}
  safe_filename = secure_filename(filename)
  if safe_filename not in ALLOWED_GUIDES:
      safe_filename = 'general.txt'

  filepath = os.path.join('guides', safe_filename)
  with open(filepath, 'r', encoding='utf-8') as f:
      content = f.read()
  ```
- **Keterangan**: Nama berkas disanitasi menggunakan `werkzeug.utils.secure_filename` dan divalidasi terhadap daftar berkas panduan yang diizinkan (*whitelist*).

---

#### 6. VULN-006: CWE-502 - Insecure Deserialization
- **File**: `app.py` (Route `/spk/load-profile`)
- **Sebelumnya**:
  ```python
  import pickle
  ...
  decoded_data = base64.b64decode(profile_data)
  user_profile = pickle.loads(decoded_data)
  ```
- **Perbaikan**:
  ```python
  import json
  # import pickle DIHAPUS SEPENUHNYA
  ...
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
  ```
- **Keterangan**: Modul `pickle` dieliminasi total dari sistem karena berisiko eksekusi kode arbitrer (*Remote Code Execution*). Proses pertukaran dan pemulihan profil preferensi SPK digantikan dengan format data standar JSON.

---

#### 7. VULN-007: CWE-601 - Open Redirect
- **File**: `app.py` (Route `/spk/redirect-reference`)
- **Sebelumnya**:
  ```python
  target_url = request.args.get('url', 'https://promkes.kemkes.go.id')
  return redirect(target_url)
  ```
- **Perbaikan**:
  ```python
  ALLOWED_REDIRECT_MAP = {
      'https://promkes.kemkes.go.id': 'https://promkes.kemkes.go.id',
      'https://kemkes.go.id': 'https://kemkes.go.id',
      'https://who.int': 'https://who.int'
  }
  DEFAULT_REDIRECT = 'https://promkes.kemkes.go.id'

  @app.route('/spk/redirect-reference', methods=['GET'])
  def redirect_reference():
      target_url = request.args.get('url', '')
      safe_url = ALLOWED_REDIRECT_MAP.get(target_url, DEFAULT_REDIRECT)
      return redirect(safe_url)
  ```
- **Keterangan**: Mencegah penyerang mengarahkan pengguna ke situs *phishing* pihak ketiga dengan membatasi tujuan pengalihan URL hanya pada peta rujukan resmi kesehatan yang telah divalidasi.

---

### Hasil Validasi SAST Lokal (Bandit)

Hasil pemindaian Bandit versi 1.9.4 pada repositori `spk-gizi-non-vulnerable`:
```text
Test results:
	No issues identified.

Code scanned:
	Total lines of code: 362
	Total lines skipped (#nosec): 0
	Total potential issues skipped due to specifically being disabled: 0

Run metrics:
	Total issues (by severity):
		Undefined: 0, Low: 0, Medium: 0, High: 0
	Total issues (by confidence):
		Undefined: 0, Low: 0, Medium: 0, High: 0
```
**Status: 0 Kerentanan Terdeteksi (Clean Baseline).**

