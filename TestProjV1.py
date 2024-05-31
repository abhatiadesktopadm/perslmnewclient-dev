from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS, cross_origin
import requests
import logicmonitor_sdk
from logicmonitor_sdk.rest import ApiException
import json
import base64
import logging
import sys
from os import path
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential

app = Flask(__name__)
CORS(app)

# Set up logging
loghandler = logging.StreamHandler(stream=sys.stdout)
logger = logging.getLogger('azure')
logger.addHandler(loghandler)

run_local = False
DEBUG = True
VERSION = '1.3.14'

# Set our logging level
if DEBUG:
    logger.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.INFO)

CONFIGFILE = 'config.json'

# Global keyvault vals
LM_ID = None
LM_KEY = None
CW_CLIENTID = None
CW_USERNAME = None
CW_PASSWORD = None
CW_COMPANY = None
CW_URL = None
CW_DOMAIN = None
CW_EPOINT = None

api_instance = None

LOGSEQUENCE = 0

# Safely extract values from JSON formatted data string and provide a default if not found
def GetConfigValue(configdata, key, subkey=None, default=None):
    if configdata and key:
        try:
            if subkey:
                return configdata[key][subkey]
            else:
                return configdata[key]
        except:
            return default
    else:
        return default

def LogOutput(message, level=0, debug=False):
    global LOGSEQUENCE
    if level == 0:  # Informational
        logger.info(f"[{LOGSEQUENCE:{0}{4}}] INFO: {message}")
    elif level == 1:  # Warning
        logger.info(f"[{LOGSEQUENCE:{0}{4}}] WARN: {message}")
    elif level == 2:  # Error
        logger.info(f"[{LOGSEQUENCE:{0}{4}}] ERR : {message}")
    elif level == 3 and (debug or DEBUG):  # Debug
        logger.info(f"[{LOGSEQUENCE:{0}{4}}] DEBG: [{VERSION}]: {message}")

LogOutput("\n\nPROGRAM STARTED - DEFINED LOGOUTPUT\n\n")

@app.after_request
def set_cache_control(response):
    response.headers['Cache-Control'] = 'public, max-age=3600, stale-while-revalidate=2592000'
    return response

# ... [Other parts of the code remain unchanged]

@app.route('/get-locations', methods=['GET'])
def get_locations():
    client_id = request.args.get('clientId')
    if not client_id:
        return jsonify({'error': 'Client ID is required'}), 400
    try:
        url = f'https://api-na.myconnectwise.net/v4_6_release/apis/3.0/company/companies/{client_id}/sites?fields=id,name,city,stateReference/identifier,country/name&conditions=inactiveFlag=false'
        username = 'align+r7wyECnfZ3BaZXtd'
        password = 'bEpKrPNKppqOApnP'
        credentials = base64.b64encode(f"{username}:{password}".encode()).decode('utf-8')
        headers = {
            'Authorization': f'Basic {credentials}',
            'clientId': '8acd3927-2171-4fd9-8ebb-c88c7d387d56'
        }
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return jsonify(response.json()), 200
        else:
            logger.error(f"Failed to fetch locations: {response.text}")
            return jsonify({'error': 'Failed to fetch locations', 'details': response.text}), response.status_code
    except Exception as e:
        logger.error(f"Exception in /get-locations: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/get-companies', methods=['GET'])
def get_companies():
    api_url = 'https://api-na.myconnectwise.net/v4_6_release/apis/3.0/company/companies?fields=id,identifier,name&orderBy=name asc&pageSize=1000&childConditions=types/name="Client"&conditions=status/name="Active"'
    username = 'align+r7wyECnfZ3BaZXtd'
    password = 'bEpKrPNKppqOApnP'
    credentials = base64.b64encode(f"{username}:{password}".encode('utf-8')).decode('utf-8')
    headers = {
        'Authorization': f'Basic {credentials}',
        'clientId': '8acd3927-2171-4fd9-8ebb-c88c7d387d56'
    }
    try:
        response = requests.get(api_url, headers=headers)
        if response.status_code == 200:
            return jsonify(response.json()), 200
        else:
            logger.error(f"Failed to fetch companies: {response.text}")
            return jsonify({'error': 'Failed to fetch companies'}), response.status_code
    except Exception as e:
        logger.error(f"Exception in /get-companies: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__' and run_local:
    app.run(debug=True, port=5001)
