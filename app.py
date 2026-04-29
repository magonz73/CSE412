from flask import Flask, render_template, request, redirect, url_for, flash
import psycopg2
import psycopg2.extras

app = Flask(__name__)
app.secret_key = 'shhhh'

# Database connection
# UPDATE these values to match your local PostgreSQL setup
DB_CONFIG = {
    'host': 'localhost',
    'database': 'postgres',
    'user': 'postgres',
    'password': 'postgres123',
    'port': 5432
}

def get_db():
    conn = psycopg2.connect(**DB_CONFIG)
    return conn

#Dashboard (READ)
@app.route('/')
def index():
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    cur.execute("SELECT COUNT(*) FROM Finding WHERE Status = 'Open'")
    open_findings = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM Asset")
    total_assets = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM Finding WHERE Severity = 'Critical' AND Status = 'Open'")
    critical_open = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM Scan")
    total_scans = cur.fetchone()[0]

    cur.execute("""
        SELECT Severity, COUNT(*) AS total
        FROM Finding
        GROUP BY Severity
        ORDER BY total DESC
    """)
    severity_counts = cur.fetchall()

    cur.execute("""
        SELECT a.Hostname, a.IPAddress, v.CVE_ID, v.Title,
               f.Severity, f.Status, f.FindingID
        FROM Finding f
        JOIN Scan s ON f.ScanID = s.ScanID
        JOIN Asset a ON s.AssetID = a.AssetID
        JOIN Vulnerability v ON f.VulnerabilityID = v.VulnerabilityID
        WHERE f.Severity IN ('Critical', 'High') AND f.Status = 'Open'
        ORDER BY f.FindingID DESC
    """)
    critical_findings = cur.fetchall()

    cur.close()
    conn.close()
    return render_template('index.html',
                           open_findings=open_findings,
                           total_assets=total_assets,
                           critical_open=critical_open,
                           total_scans=total_scans,
                           severity_counts=severity_counts,
                           critical_findings=critical_findings)
# Assets: READ
@app.route('/assets')
def assets():
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute("""
        SELECT a.*, u.Name AS OwnerName
        FROM Asset a
        LEFT JOIN "User" u ON a.OwnerUserID = u.UserID
        ORDER BY a.AssetID
    """)
    assets = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('assets.html', assets=assets)

# Assets: CREATE
@app.route('/assets/add', methods=['GET', 'POST'])
def add_asset():
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    if request.method == 'POST':
        hostname = request.form['hostname']
        ipaddress = request.form['ipaddress']
        os = request.form['operatingsystem']
        env = request.form['environment']
        owner = request.form['owneruserid']
        try:
            cur.execute("""
                INSERT INTO Asset (Hostname, IPAddress, OperatingSystem, Environment, OwnerUserID)
                VALUES (%s, %s, %s, %s, %s)
            """, (hostname, ipaddress, os, env, owner))
            conn.commit()
            flash('Asset added successfully!', 'success')
            return redirect(url_for('assets'))
        except Exception as e:
            conn.rollback()
            flash(f'Error adding asset: {e}', 'error')

    # Load users for the dropdown
    cur.execute('SELECT UserID, Name FROM "User" ORDER BY Name')
    users = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('add_asset.html', users=users)


# Assets: DELETE
@app.route('/assets/delete/<int:asset_id>', methods=['POST'])
def delete_asset(asset_id):
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM Asset WHERE AssetID = %s", (asset_id,))
        conn.commit()
        flash('Asset deleted.', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Error deleting asset: {e}', 'error')
    cur.close()
    conn.close()
    return redirect(url_for('assets'))


# Findings: READ
@app.route('/findings')
def findings():
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute("""
        SELECT f.FindingID, a.Hostname, v.CVE_ID, v.Title,
               f.Severity, f.Status, f.FirstSeen, f.LastSeen
        FROM Finding f
        JOIN Scan s          ON f.ScanID = s.ScanID
        JOIN Asset a         ON s.AssetID = a.AssetID
        JOIN Vulnerability v ON f.VulnerabilityID = v.VulnerabilityID
        ORDER BY f.FindingID
    """)
    findings = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('findings.html', findings=findings)

# Findings: UPDATE
@app.route('/findings/edit/<int:finding_id>', methods=['GET', 'POST'])
def edit_finding(finding_id):
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    if request.method == 'POST':
        status = request.form['status']
        lastseen = request.form['lastseen']
        try:
            cur.execute("""
                UPDATE Finding
                SET Status = %s, LastSeen = %s
                WHERE FindingID = %s
            """, (status, lastseen, finding_id))
            conn.commit()
            flash('Finding updated successfully!', 'success')
            return redirect(url_for('findings'))
        except Exception as e:
            conn.rollback()
            flash(f'Error updating finding: {e}', 'error')

    cur.execute("""
        SELECT f.*, v.Title, v.CVE_ID, a.Hostname
        FROM Finding f
        JOIN Vulnerability v ON f.VulnerabilityID = v.VulnerabilityID
        JOIN Scan s          ON f.ScanID = s.ScanID
        JOIN Asset a         ON s.AssetID = a.AssetID
        WHERE f.FindingID = %s
    """, (finding_id,))
    finding = cur.fetchone()
    cur.close()
    conn.close()
    return render_template('edit_finding.html', finding=finding)

# Findings: DELETE
@app.route('/findings/delete/<int:finding_id>', methods=['POST'])
def delete_finding(finding_id):
    conn = get_db()
    cur = conn.cursor()
    try:
        # Remove linked remediation first (foreign key)
        cur.execute("DELETE FROM Remediation WHERE FindingID = %s", (finding_id,))
        cur.execute("DELETE FROM Finding WHERE FindingID = %s", (finding_id,))
        conn.commit()
        flash('Finding deleted.', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Error deleting finding: {e}', 'error')
    cur.close()
    conn.close()
    return redirect(url_for('findings'))

if __name__ == '__main__':
    app.run(debug=True)