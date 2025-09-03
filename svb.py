import requests
import re
import time

def process_card_svb(cc):
    try:
        # Format the card correctly for the API
        formatted_cc = cc.replace('|', '%7C')
        
        headers = {
            'accept': '*/*',
            'accept-language': 'en-US,en;q=0.9',
            'priority': 'u=1, i',
            'referer': 'https://wizvenex.com/',
            'sec-ch-ua': '"Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36',
            'x-requested-with': 'XMLHttpRequest'
        }
        
        url = f'https://wizvenex.com/Vbv.php?lista={formatted_cc}'
        
        start_time = time.time()
        response = requests.get(url, headers=headers, timeout=30)
        end_time = time.time()
        processing_time = round(end_time - start_time, 2)
        
        response_text = response.text
        
        # Extract status
        status_match = re.search(r'<span class="text-(danger|success)">(APPROVED|DECLINED)</span>', response_text)
        if status_match:
            status = status_match.group(2).upper()
        else:
            status = "ERROR"
        
        # Extract response message
        response_match = re.search(r'➔ <span class="text-(danger|success|warning)">([^<]+)</span>', response_text)
        if response_match:
            response_msg = response_match.group(2)
            # Clean up the response message
            if 'AUTHENTICATE_SUCCESSFUL' in response_msg:
                response_msg = 'AUTHENTICATE_SUCCESSFUL'
            elif 'AUTHENTICATE_FRICTIONLESS_FAILED' in response_msg:
                response_msg = 'AUTHENTICATE_FRICTIONLESS_FAILED'
        else:
            response_msg = "Unknown response"
        
        # Extract time if available
        time_match = re.search(r'TIME :\((\d+s)\)', response_text)
        if time_match:
            server_time = time_match.group(1)
        else:
            server_time = f"{processing_time}s"
        
        return {
            "gateway": "Secure VBV",
            "response": response_msg,
            "status": status,
            "processing_time": server_time
        }
        
    except requests.exceptions.Timeout:
        return {
            "gateway": "Secure VBV",
            "response": "Timeout - Server took too long to respond",
            "status": "ERROR",
            "processing_time": "30s+"
        }
    except requests.exceptions.RequestException as e:
        return {
            "gateway": "Secure VBV", 
            "response": f"Network error: {str(e)}",
            "status": "ERROR",
            "processing_time": "0s"
        }
    except Exception as e:
        return {
            "gateway": "Secure VBV",
            "response": f"Processing error: {str(e)}",
            "status": "ERROR",
            "processing_time": "0s"
        }
