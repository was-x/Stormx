import httpx
import os
import time
import json

# Configuration
GATEWAY = "3DS Lookup"
VBVBIN_GITHUB_URL = "https://raw.githubusercontent.com/d0x-dev/b/refs/heads/main/vbvbin.txt"

async def download_vbvbin():
    """Download the latest vbvbin.txt from GitHub"""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(VBVBIN_GITHUB_URL)
            if response.status_code == 200:
                with open("vbvbin.txt", "wb") as f:
                    f.write(response.content)
                print("Successfully updated vbvbin.txt from GitHub")
                return True
    except Exception as e:
        print(f"Error downloading vbvbin.txt: {e}")
    return False

async def get_bin_info(bin_number):
    try:
        async with httpx.AsyncClient() as client:
            url = f"https://bins.antipublic.cc/bins/{bin_number}"
            response = await client.get(url)
            if response.status_code == 200:
                return response.json()
            return None
    except Exception:
        return None

async def check_vbv_bin(bin_number):
    try:
        if not os.path.exists("vbvbin.txt"):
            if not await download_vbvbin():
                return {
                    "status": "3D FALSE",
                    "response": "Lookup Error"
                }

        with open("vbvbin.txt", "r", encoding="utf-8") as file:
            for line in file:
                if line.startswith(bin_number[:6]):
                    parts = line.strip().split('|')
                    if len(parts) >= 3:
                        return {
                            "status": parts[1],
                            "response": parts[2]
                        }

        return {
            "status": "3D FALSE",
            "response": "BIN Not Found in Database"
        }
    except Exception as e:
        print(f"Error reading BIN database: {e}")
        return {
            "status": "3D FALSE",
            "response": "Lookup Error"
        }

def check_vbv_card(ccx):
    """Check VBV status for a single card"""
    import asyncio
    
    ccx = ccx.strip()
    parts = ccx.split('|')
    if len(parts) != 4:
        return {
            "status": "Declined", 
            "response": "Invalid card format. Use CC|MM|YYYY|CVV",
            "gateway": GATEWAY
        }

    cc_num, mes, ano, cvv = parts
    bin_number = cc_num[:6]

    if bin_number.startswith('3'):
        return {
            "cc": ccx,
            "response": "❌ Unsupported card type (AMEX)",
            "status": "Declined",
            "gateway": GATEWAY
        }

    # Run async functions synchronously
    try:
        vbv_status = asyncio.run(check_vbv_bin(bin_number))
        bin_info = asyncio.run(get_bin_info(bin_number))
    except:
        return {
            "status": "Declined",
            "response": "Lookup Error",
            "gateway": GATEWAY
        }

    if "FALSE ✅" in vbv_status["status"]:
        status = "Approved"
        response_emoji = "✅"
    else:
        status = "Declined"
        response_emoji = "❌"

    response = f"{response_emoji} {vbv_status['response']}"

    return {
        "cc": ccx,
        "response": response,
        "status": status,
        "gateway": GATEWAY,
        "bin_info": bin_info or {}
    }
