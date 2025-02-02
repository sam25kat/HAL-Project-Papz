from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from flask_cors import CORS
from web3 import Web3
import os
from datetime import datetime
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import requests

app = Flask(__name__)
app.secret_key = "secret_key"
CORS(app)
#dh
# Blockchain Configuration
ganache_url = "HTTP://127.0.0.1:7545"
contract_address = "0xad560d26153f1aDac32D9016a2e3FCda5EB4f252"
contract_abi = [  {
		"inputs": [
			{
				"internalType": "uint256",
				"name": "id",
				"type": "uint256"
			}
		],
		"name": "approveFile",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [],
		"stateMutability": "nonpayable",
		"type": "constructor"
	},
	{
		"anonymous": False,
		"inputs": [
			{
				"indexed": False,
				"internalType": "uint256",
				"name": "id",
				"type": "uint256"
			}
		],
		"name": "FileApproved",
		"type": "event"
	},
	{
		"anonymous": False,
		"inputs": [
			{
				"indexed": False,
				"internalType": "uint256",
				"name": "id",
				"type": "uint256"
			},
			{
				"indexed": False,
				"internalType": "string",
				"name": "name",
				"type": "string"
			},
			{
				"indexed": False,
				"internalType": "string",
				"name": "category",
				"type": "string"
			},
			{
				"indexed": False,
				"internalType": "address",
				"name": "uploader",
				"type": "address"
			}
		],
		"name": "FileUploaded",
		"type": "event"
	},
	{
		"inputs": [
			{
				"internalType": "string",
				"name": "name",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "category",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "hash",
				"type": "string"
			}
		],
		"name": "uploadFile",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "admin",
		"outputs": [
			{
				"internalType": "address",
				"name": "",
				"type": "address"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"name": "files",
		"outputs": [
			{
				"internalType": "uint256",
				"name": "id",
				"type": "uint256"
			},
			{
				"internalType": "string",
				"name": "name",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "category",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "hash",
				"type": "string"
			},
			{
				"internalType": "address",
				"name": "uploader",
				"type": "address"
			},
			{
				"internalType": "uint256",
				"name": "timestamp",
				"type": "uint256"
			},
			{
				"internalType": "bool",
				"name": "approved",
				"type": "bool"
			},
			{
				"internalType": "uint256",
				"name": "version",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "filesCount",
		"outputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "uint256",
				"name": "id",
				"type": "uint256"
			}
		],
		"name": "getFile",
		"outputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			},
			{
				"internalType": "string",
				"name": "",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "",
				"type": "string"
			},
			{
				"internalType": "address",
				"name": "",
				"type": "address"
			},
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			},
			{
				"internalType": "bool",
				"name": "",
				"type": "bool"
			},
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	}] 

web3 = Web3(Web3.HTTPProvider(ganache_url))
contract = web3.eth.contract(address=contract_address, abi=contract_abi)
admin_account = "0xc1D408c094048597737f4FB661300227D1B6339F"

# Database Configuration
DATABASE = 'file_logs.db'

# IPFS Configuration
ipfs_api_url = "http://127.0.0.1:5001/api/v0"








# Additional Database Setup for Circulars
def init_circulars_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS circulars (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    content TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )''')
    conn.commit()
    conn.close()

# Update init_db to initialize circulars table as well
init_circulars_db()

# Helper Function to Get Circulars
def get_circular():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('SELECT id, content, timestamp FROM circulars ORDER BY timestamp DESC LIMIT 1')
    circular = c.fetchone()
    conn.close()
    return circular











def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    # Create tables
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE,
                    password TEXT,
                    metamask_address TEXT,
                    is_admin INTEGER DEFAULT 0,
                    is_approved INTEGER DEFAULT 0
                )''')

    c.execute('''CREATE TABLE IF NOT EXISTS logs (
                    dept TEXT DEFAULT UNKNOWN,
                    username TEXT UNIQUE DEFAULT UNKNOWN,
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_address TEXT,
                    action TEXT,
                    file_name TEXT,
                    category TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS incentives (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_name TEXT NOT NULL,
                    user_id INTEGER NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )''')

    conn.commit()
    conn.close()

# Helper Functions
def log_action(user_address, action, file_name, category, username, dept):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('INSERT INTO logs (user_address, action, file_name, category, username, dept) VALUES (?, ?, ?, ?, ?, ?)',
              (user_address, action, file_name, category, username, dept))
    conn.commit()
    conn.close()

def get_user(username):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('SELECT id, username, password, metamask_address, is_admin, is_approved FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    conn.close()
    return user

def upload_to_ipfs(file):
    try:
        files = {'file': file}
        response = requests.post(f"{ipfs_api_url}/add", files=files)
        response.raise_for_status()
        response_data = response.json()
        return response_data["Hash"]
    except requests.RequestException as e:
        raise Exception(f"IPFS upload failed: {e}")


# Routes
@app.route('/')
def index():
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        metamask_address = request.form['metamask_address']

        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        try:
            c.execute('INSERT INTO users (username, password, metamask_address, is_admin, is_approved) VALUES (?, ?, ?, 0, 0)',
                      (username, password, metamask_address))
            conn.commit()
        except sqlite3.IntegrityError:
            return "Username already exists"
        finally:
            conn.close()
        message = "Waiting for admin's approval." 
        return render_template('login.html')
    return render_template('signup.html')

@app.route('/loginfromhome')
def loginfromhome():
    return render_template('login.html')  # This will render the login page


@app.route('/facdoc')
def facdoc():
    if request.method == 'POST':
        file = request.files['file']
        category = request.form['category']
        
        visibility = request.form.get('visibility', 'Private')  # Default visibility to Private
        dept=request.form['dept']

        try:
            # Upload file to IPFS
            file_hash = upload_to_ipfs(file)
            file_name = file.filename
            username = session.get('username', 'Unknown')

            # Upload file details to blockchain
            tx_hash = contract.functions.uploadFile(file_name, category, file_hash).transact({
                'from': get_user(session['username'])[3]
            })
            web3.eth.wait_for_transaction_receipt(tx_hash)

            # Log file upload in local database
            log_action(get_user(session['username'])[3], 'Upload', file_name, category, username, dept)
            return jsonify({"message": "File uploaded successfully!", "ipfs_hash": file_hash})
        except Exception as e:
            return jsonify({"error": str(e)})

    # Render files
    files = []
    try:
        files_count = contract.functions.filesCount().call()
        for i in range(files_count):
            file = contract.functions.getFile(i).call()
            if file[6]:  # Only approved files
                visibility = "Public" if file[6] else "Private"
                file_name = file[1]
                c = sqlite3.connect(DATABASE).cursor()
                c.execute("SELECT dept FROM logs WHERE file_name = ?", (file_name,))
                dept = c.fetchone()
                dept = dept[0] if dept else "Unknown"
                files.append({
                    "id": file[0],
                    "name": file[1],
                    "category": file[2],
                    "uploader": file[4],
                    "timestamp": datetime.fromtimestamp(file[5]).strftime('%Y-%m-%d %H:%M:%S'),
                    "approved": file[6],
                    "version": file[7],
                    "visibility": visibility,
                    "dept":dept,
                    "ipfs_hash": f"https://ipfs.io/ipfs/{file[3]}"
                })
    except Exception as e:
        return jsonify({"error": str(e)})
    return render_template('facdoc.html', files=files)





from flask import request, jsonify
from datetime import datetime  # Import only the class


import sqlite3

@app.route('/log_incentive', methods=['POST'])
def log_incentive():
    try:
        conn = sqlite3.connect(DATABASE)
        data = request.json
        user_id = data.get('user_id')
        file_name = data.get('file_name')
        timestamp = datetime.now()  # Ensure correct usage of datetime

        # Insert into your database (ensure table 'incentives' has user_id, file_name, timestamp columns)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO incentives (user_id, file_name, timestamp) VALUES (?, ?, ?)",
            (user_id, file_name, timestamp)
        )
        conn.commit()
        conn.close()

        return jsonify({"status": "success", "message": "Incentive logged successfully."}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/incentive_table')
def incentive_table():
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("SELECT id, file_name, user_id, timestamp FROM incentives ORDER BY timestamp DESC")
        incentives = cursor.fetchall()
        conn.close()
        
        return render_template('incentive_table.html', incentives=incentives)
    
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500





@app.route('/docs', methods=['GET', 'POST'])
def admindoc():
    if request.method == 'POST':
        if 'file_id' in request.form:
            file_id = int(request.form['file_id'])
            dept = request.form.get('dept')
            visibility = request.form.get('visibility', 'Private')  # Default to Private

            # Approve the file on the blockchain
            tx_hash = contract.functions.approveFile(file_id).transact({
                'from': admin_account
            })
            web3.eth.wait_for_transaction_receipt(tx_hash)

            # Log approval with visibility
            file_name = contract.functions.getFile(file_id).call()[1]  # Fetch file name from contract
            category = contract.functions.getFile(file_id).call()[2]  # Fetch category from contract
            username = session.get('username', 'Unknown')
            log_action(admin_account, f"Approved ({visibility})", file_name, category, username, dept)
            flash('File approved as Public!')
            return redirect(url_for('admin'))

        if 'approve_user' in request.form:
            user_id = int(request.form['approve_user'])
            conn = sqlite3.connect(DATABASE)
            c = conn.cursor()
            c.execute('UPDATE users SET is_approved = 1 WHERE id = ?', (user_id,))
            conn.commit()
            conn.close()
            return "User approved successfully!"

    # Fetch pending users
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE is_approved = 0')
    pending_users = c.fetchall()
    conn.close()

    # Fetch uploaded files
    files = []
    try:
        files_count = contract.functions.filesCount().call()
        for i in range(files_count):
            file = contract.functions.getFile(i).call()
            file_name = file[1]
            c = sqlite3.connect(DATABASE).cursor()
            c.execute("SELECT dept FROM logs WHERE file_name = ?", (file_name,))
            dept = c.fetchone()
            dept = dept[0] if dept else "Unknown"
            visibility = "Public" if file[6] else "Admin Only"
            name = file[1]
            c = sqlite3.connect(DATABASE).cursor()
            c.execute("SELECT username FROM logs WHERE file_name = ?", (file_name,))
            uploader_username = c.fetchone()
            uploader_username = uploader_username[0] if uploader_username else "Unknown"

            files.append({
                "id": file[0],
                "name": file[1],
                "category": file[2],
                "uploader": file[4],
                "uploader_username": uploader_username,
                "timestamp": datetime.fromtimestamp(file[5]).strftime('%Y-%m-%d %H:%M:%S'),
                "approved": file[6],
                "version": file[7],
                "visibility": visibility,
                "dept": dept,
                "ipfs_hash": file[3]
            })
    except Exception as e:
        return jsonify({"error": str(e)})
    return render_template('docs.html', files=files)


@app.route('/admin_loginfromhome')
def admin_loginfromhome():
    return render_template('admin_login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    user = get_user(username)

    if user and check_password_hash(user[2], password):
        if user[5] == 0:  # Check if the account is approved
            return "Your account is pending admin approval."
        session['username'] = username
        session['is_admin'] = bool(user[4])
        session['metamask_address'] = user[3]
        return redirect(url_for('admin' if session['is_admin'] else 'faculty'))
    return "Invalid credentials"

@app.route('/admin_login', methods=['POST'])
def admin_login():
    admin_password = request.form['adminpassword']
    correct_password = "Admin"  # Replace with your actual admin password

    if admin_password == correct_password:
        session['is_admin'] = True  # Set session to mark user as admin
        session['username'] = "admin"  # Optional: Set a username for the admin
        return redirect(url_for('admin'))  # Redirect to the admin dashboard
    else: 
        # Render the login page with an error message
        return render_template('login.html', error="Invalid admin password")




@app.route('/faculty', methods=['GET', 'POST'])
def faculty():
    if 'username' not in session or session.get('is_admin', False):
        return redirect(url_for('index'))
    
    circular = get_circular()

    if request.method == 'POST':
        file = request.files['file']
        category = request.form['category']
        
        visibility = request.form.get('visibility', 'Private')  # Default visibility to Private
        dept=request.form['dept']

        try:
            # Upload file to IPFS
            file_hash = upload_to_ipfs(file)
            file_name = file.filename
            username = session.get('username', 'Unknown')

            # Upload file details to blockchain
            tx_hash = contract.functions.uploadFile(file_name, category, file_hash).transact({
                'from': get_user(session['username'])[3]
            })
            web3.eth.wait_for_transaction_receipt(tx_hash)

            # Log file upload in local database
            log_action(get_user(session['username'])[3], 'Upload', file_name, category, username, dept)
            return redirect(url_for('faculty') + '?message=upload_success')
        except Exception as e:
            return jsonify({"error": str(e)})

    # Render files
    files = []
    try:
        files_count = contract.functions.filesCount().call()
        for i in range(files_count):
            file = contract.functions.getFile(i).call()
            if file[6]:  # Only approved files
                visibility = "Public" if file[6] else "Private"
                file_name = file[1]
                c = sqlite3.connect(DATABASE).cursor()
                c.execute("SELECT dept FROM logs WHERE file_name = ?", (file_name,))
                dept = c.fetchone()
                dept = dept[0] if dept else "Unknown"
                files.append({
                    "id": file[0],
                    "name": file[1],
                    "category": file[2],
                    "uploader": file[4],
                    "timestamp": datetime.fromtimestamp(file[5]).strftime('%Y-%m-%d %H:%M:%S'),
                    "approved": file[6],
                    "version": file[7],
                    "visibility": visibility,
                    "dept":dept,
                    "ipfs_hash": f"https://ipfs.io/ipfs/{file[3]}"
                })
    except Exception as e:
        return jsonify({"error": str(e)})

    return render_template('faculty.html', files=files, circular=circular)











import os
import docx
import PyPDF2
import re
from spellchecker import SpellChecker


from spellchecker import SpellChecker

def analyze_text_quality(text):
    """Analyzes text formatting, spelling mistakes, and blank spaces, then assigns a rating."""
    
    if not text.strip():
        return 4  # Default rating if no text is found

    spell = SpellChecker()
    words = text.split()
    misspelled = spell.unknown(words)  # Finds words that are not in the dictionary
    
    word_count = len(words)
    blank_spaces = text.count("  ")  # Double spaces as an error metric
    spelling_mistakes = len(misspelled)  # Count only actual misspelled words

    # Simple scoring based on detected issues
    score = 5
    if blank_spaces > 5 and blank_spaces <= 10:
        score -= 1
    elif blank_spaces > 10 and blank_spaces <=20:
        score -= 2
    elif blank_spaces > 20:
        score -= 3
    if spelling_mistakes > 5 and spelling_mistakes <=10:
        score -= 1
    elif spelling_mistakes > 10 and spelling_mistakes<=20:
        score -= 2
    elif spelling_mistakes > 20:
        score -= 3
    if word_count < 10:
        score = 4  # Not much text found, default to 4
    
    return max(1, score)  # Ensure rating is between 1 and 5


@app.route('/analyze', methods=['POST'])
def analyze_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    filename = file.filename
    file_ext = os.path.splitext(filename)[1].lower()
    
    text_content = ""
    
    try:
        if file_ext == '.txt':
            text_content = file.read().decode('utf-8')
        elif file_ext == '.docx':
            doc = docx.Document(file)
            text_content = '\n'.join([para.text for para in doc.paragraphs])
        elif file_ext == '.pdf':
            reader = PyPDF2.PdfReader(file)
            text_content = '\n'.join([page.extract_text() for page in reader.pages if page.extract_text()])
        else:
            return jsonify({'rating': 4})  # Non-text files default to rating 4
        
        rating = analyze_text_quality(text_content)
        return jsonify({'rating': rating})
    except Exception as e:
        return jsonify({'error': str(e), 'rating': 4})  # If error, assign default rating 4














@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if 'username' not in session or not session.get('is_admin', False):
        return redirect(url_for('index'))
    
    circular = get_circular()

    if request.method == 'POST':
        if 'file_id' in request.form:
            file_id = int(request.form['file_id'])
            dept=request.form.get('dept')
            visibility = request.form.get('visibility', 'Private')  # Default to Private

            # Approve the file on the blockchain
            tx_hash = contract.functions.approveFile(file_id).transact({
                'from': admin_account
            })
            web3.eth.wait_for_transaction_receipt(tx_hash)

            # Log approval with visibility
            file_name = contract.functions.getFile(file_id).call()[1]  # Fetch file name from contract
            category = contract.functions.getFile(file_id).call()[2]  # Fetch category from contract
            username = session.get('username', 'Unknown')
            log_action(admin_account, f"Approved ({visibility})", file_name, category, username, dept)
            flash('File approved as Public!') 
            return redirect(url_for('admin'))


        if 'approve_user' in request.form:
            user_id = int(request.form['approve_user'])
            conn = sqlite3.connect(DATABASE)
            c = conn.cursor()
            c.execute('UPDATE users SET is_approved = 1 WHERE id = ?', (user_id,))
            conn.commit()
            conn.close()
            return "User approved successfully!"

    # Fetch pending users
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE is_approved = 0')
    pending_users = c.fetchall()
    conn.close()

    # Fetch uploaded files
    files = []
    try:
        files_count = contract.functions.filesCount().call()
        for i in range(files_count):
            file = contract.functions.getFile(i).call()
            file_name = file[1]
            c = sqlite3.connect(DATABASE).cursor()
            c.execute("SELECT dept FROM logs WHERE file_name = ?", (file_name,))
            dept = c.fetchone()
            dept = dept[0] if dept else "Unknown"
            visibility = "Public" if file[6] else "Admin Only"
            name=file[1]
            c = sqlite3.connect(DATABASE).cursor()
            c.execute("SELECT username FROM logs WHERE file_name = ?", (file_name,))
            uploader_username = c.fetchone()
            uploader_username = uploader_username[0] if uploader_username else "Unknown"

            files.append({
                "id": file[0],
                "name": file[1],
                "category": file[2],
                "uploader": file[4],
                "uploader_username": uploader_username,
                "timestamp": datetime.fromtimestamp(file[5]).strftime('%Y-%m-%d %H:%M:%S'),
                "approved": file[6],
                "version": file[7],
                "visibility": visibility,
                "dept":dept,
                "ipfs_hash": file[3]
            })
    except Exception as e:
        return jsonify({"error": str(e)})

    return render_template('admin.html', files=files, pending_users=pending_users, circular=circular)



@app.route('/manage_circular', methods=['GET', 'POST'])
def manage_circular():
    if 'username' not in session or not session.get('is_admin', False):
        return redirect(url_for('index'))

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'add':
            content = request.form['content']
            conn = sqlite3.connect(DATABASE)
            c = conn.cursor()
            c.execute('INSERT INTO circulars (content) VALUES (?)', (content,))
            conn.commit()
            conn.close()
            return redirect(url_for('admin'))

        elif action == 'remove':
            conn = sqlite3.connect(DATABASE)
            c = conn.cursor()
            c.execute('DELETE FROM circulars')  # Remove all circulars (or customize to remove specific ones)
            conn.commit()
            conn.close()
            return redirect(url_for('admin'))

    # Fetch current circular
    circular = get_circular()
    return render_template('admin.html', circular=circular)





    
    
   








import sqlite3
import google.generativeai as genai
from flask import Flask, request, jsonify, render_template

genai.configure(api_key="AIzaSyCBt1P_Hr9RK4-P6e872pjbUoXCObGlO6U")
model = genai.GenerativeModel("gemini-1.5-flash")

def get_db_connection():
    try:
        conn = sqlite3.connect(DATABASE)
        conn.row_factory = sqlite3.Row
        return conn
    except Exception as e:
        print(f"Error connecting to database: {e}")
        return None

def fetch_data_from_db(table_name):
    conn = get_db_connection()
    if not conn:
        return []

    try:
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM {table_name}")
        data = cursor.fetchall()
        conn.close()
        return [dict(row) for row in data]
    except sqlite3.OperationalError as e:
        print(f"Database error with table {table_name}: {e}")
        return []

def generate_reference_prompt():
    logs = fetch_data_from_db("logs")
    users = fetch_data_from_db("users")
    incentives = fetch_data_from_db("incentives")

    prompt = "The following database records should be used as reference for all queries:\n\n"

    for table_name, data in [("Logs", logs), ("Users", users), ("Incentives", incentives)]:
        if data:
            prompt += f"{table_name}:\n"
            for item in data[:200]:  # Limit to first 5 records
                prompt += "- " + ", ".join(f"{key}: {value if value is not None else 'N/A'}" for key, value in item.items()) + "\n"
            prompt += "\n"

    prompt += "User queries should be answered based on the above data. If the answer is not found, respond with 'Sorry, I could not find anything. I may not be able to answer your question yet'. Refer only data from the february month. Ignore all previous records. just answer what is asked and do not mention based on february"
    return prompt

@app.route("/chatbot", methods=["GET", "POST"])
def chatbot():
    reference_prompt = generate_reference_prompt()

    if request.method == "POST":
        user_query = request.form.get("query", "").strip()

        if not user_query:
            return jsonify({"response": "Please enter a query."})

        full_prompt = f"""{reference_prompt}

        Now, engage in a natural, conversational chat with the user, using the provided database information as context.  If the user's query can be directly answered from the database, provide the answer. If the query is more conversational or requires interpretation, respond appropriately, referencing the data where relevant. If the answer is not found in the database, respond politely indicating this.

        User Query: {user_query}
        """

        try:
            response = model.generate_content(full_prompt)
            chat_response = response.text.strip() if response else "I'm having trouble processing your request."  # More conversational fallback

        except Exception as e:
            print(f"Error generating response: {e}")
            chat_response = "I'm having trouble processing your request."

        return jsonify({"response": chat_response})

    return render_template("chatbot.html")

















def update_schema():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    # Check if the column already exists
    c.execute("PRAGMA table_info(files);")
    columns = [col[1] for col in c.fetchall()]
    if 'visibility' not in columns:
        # Add the 'visibility' column
        c.execute("ALTER TABLE files ADD COLUMN visibility TEXT DEFAULT 'Private';")
        print("Column 'visibility' added to the 'files' table.")
    else:
        print("Column 'visibility' already exists in the 'files' table.")
    
    conn.commit()
    conn.close()
    
    
def update_schema2():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    # Check if the 'username' column already exists in the 'logs' table
    c.execute("PRAGMA table_info(logs);")
    columns = [col[1] for col in c.fetchall()]
    if 'username' not in columns:
        # Add the 'username' column
        c.execute("ALTER TABLE logs ADD COLUMN username TEXT DEFAULT 0;")
        print("Column 'username' added to the 'logs' table.")
    else:
        print("Column 'username' already exists in the 'logs' table.")
    
    conn.commit()
    conn.close()
    
def update_schema3():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    # Check if the 'username' column already exists in the 'logs' table
    c.execute("PRAGMA table_info(logs);")
    columns = [col[1] for col in c.fetchall()]
    if 'dept' not in columns:
        # Add the 'username' column
        c.execute("ALTER TABLE logs ADD COLUMN dept TEXT DEFAULT Unknown;")
        print("Column 'dept' added to the 'logs' table.")
    else:
        print("Column 'dept' already exists in the 'logs' table.")
    
    conn.commit()
    conn.close()
    
    
def update_schema4():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    # Check if the 'files' table exists
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='files';")
    if not c.fetchone():
        # Create the 'files' table if it doesn't exist
        c.execute('''CREATE TABLE IF NOT EXISTS files (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        file_name TEXT,
                        category TEXT,
                        ipfs_hash TEXT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        approved INTEGER DEFAULT 0,
                        version INTEGER DEFAULT 1,
                        visibility TEXT DEFAULT 'Private',
                        dept TEXT DEFAULT 'Unknown'
                    )''')
        print("Created 'files' table.")
    
    # Check if the 'visibility' column exists in the 'files' table
    c.execute("PRAGMA table_info(files);")
    columns = [col[1] for col in c.fetchall()]
    if 'visibility' not in columns:
        # Add the 'visibility' column
        c.execute("ALTER TABLE files ADD COLUMN visibility TEXT DEFAULT 'Private';")
        print("Column 'visibility' added to the 'files' table.")
    
    conn.commit()
    conn.close()


if __name__ == '__main__':
    if not os.path.exists('uploads'):
        os.mkdir('uploads')
    init_db()
    update_schema()
    update_schema2()
    update_schema3()
    update_schema4()
    app.run(debug=True)