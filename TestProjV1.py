"""
Author: Arnav Bhatia
Company  : Align Communications
Version  : 1.3.10
Modified : 2024-04-17
Created  : 2023-11-10

The Python backend is designed to interact with LogicMonitor and ConnectWise APIs, facilitating the automation 
of client and location setup within LogicMonitor based on data retrieved from ConnectWise. It initializes 
the Flask application, sets up CORS, and configures the LogicMonitor SDK. Through endpoints like 
/get-companies and /get-locations, it fetches data from ConnectWise, and with /create-client-folder, 
it processes user selections to create and configure folders in LogicMonitor. Utility functions within 
the backend check for existing folders to prevent duplication and handle the creation of client and 
location folders, including setting specific properties like company ID, location ID, and site addresses.

The HTML frontend provides a user-friendly interface, allowing users to select clients and locations from 
dynamically loaded dropdown menus, and choose which folders to include. On form submission, the selections are 
sent back to the Flask server, which then carries out the LogicMonitor configuration. This setup streamlines 
the organizational process, leveraging ConnectWise data to efficiently structure and annotate elements 
within LogicMonitor.
"""


from re import L
from smtplib import LMTP_PORT
import sys
import requests
import logicmonitor_sdk
from logicmonitor_sdk.rest import ApiException
import json
import base64
import logging
from os import path
#from azure.identity import DefaultAzureCredential

from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS, cross_origin

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

# global keyvault vals

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
def GetConfigValue(configdata,key,subkey=None,default=None):
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
 
def LogOutput(message, level = 0, debug = False):
 
    global LOGSEQUENCE
 
    if level == 0: # Informational
        logger.info(f"[{LOGSEQUENCE:{0}{4}}] INFO: {message}")
    elif level == 1: # Warning
        logger.info(f"[{LOGSEQUENCE:{0}{4}}] WARN: {message}")
    elif level == 2: # Error
        logger.info(f"[{LOGSEQUENCE:{0}{4}}] ERR : {message}")
    elif level == 3 and (debug or DEBUG): # Debug
        logger.info(f"[{LOGSEQUENCE:{0}{4}}] DEBG: [{VERSION}]: {message}")
        
LogOutput("\n\nPROGRAM STARTED - DEFINED LOGOUTPUT\n\n")

@app.after_request
def set_cache_control(response):
    """Set Cache-Control headers for all responses."""
    response.headers['Cache-Control'] = 'public, max-age=3600, stale-while-revalidate=2592000'
    return response



# Configure API key authorization: LMv1


group_settings = [
    ("_Collectors", lambda path: f"join(system.staticgroups,\",\") =~ \"{path}/\" && isCollectorDevice()", False),
    ("_Domain Controllers", lambda path: f"system.displayname =~ \"DC-\" && displayname !~ \"networkinterface\" && displayname !~ \"iDRAC\" && join(system.staticgroups,\",\") =~ \"{path}/\"", False),
    ("_Firewalls", lambda path: f"system.displayname =~ \"-fw\" && join(system.staticgroups,\",\") =~ \"{path}/\"", True),
    ("_Routers", lambda path: f"system.displayname =~ \"^rt\" && join(system.staticgroups,\",\") =~ \"{path}/\"", False),
    ("_Switches", lambda path: f"(system.displayname =~ \"^sw\" || system.displayname =~ \"-asw\" || system.displayname =~ \"-sw\") && join(system.staticgroups,\",\") =~ \"{path}/\"", False),
    ("_Wireless", lambda path: f"system.displayname =~ \"^*-wap\" && join(system.staticgroups,\",\") =~ \"{path}/\"", False),
    ("_Disabled", lambda path: f"system.displayname =~ \"-test`$\" || System.azure.resourcegroupname =~ \"-test\" || system.azure.status=~ \"deallocated\" || system.azure.resourcegroupname =~ \"-desktops\" ) && join(system.staticgroups,\",\") =~ \"{path}/\"", False)
]


def create_client_folder(api_instance, clients_folder_id, client_name):
    try:
        if check_if_group_exists(api_instance, clients_folder_id, client_name):
            logging.info(f"Client folder '{client_name}' already exists.")
            return

        new_client_folder = logicmonitor_sdk.DeviceGroup(name=client_name, parent_id=clients_folder_id)
        api_response = api_instance.add_device_group(new_client_folder)
            
        print(f"Client folder '{client_name}' created. ID: {api_response.id}")
        
        return api_response.id
    except ApiException as e:
        print(f"Exception when creating client folder: {e}")
        return None

def check_if_group_exists(api_client, parent_id, group_name):
    try:
        device_groups = api_client.get_device_group_by_id(parent_id)

        print(device_groups)        

        for group in device_groups.sub_groups:
            if group.name == group_name:
                return True
            
        return False    
        
    except ApiException as e:
        print(f"Error checking if group exists: {e}")
        return False
    

# def get_group_id_by_name(api_client, parent_id, group_name):
       
    
def create_folder(api_instance, parent_id, name, query, disable_alerting=False, enable_netflow=False):
    try:
        if check_if_group_exists(api_instance, parent_id, name):
            print(f"Group '{name}' already exists.")
            return

        new_group = logicmonitor_sdk.DeviceGroup(
            name=name, 
            parent_id=parent_id, 
            applies_to=query, 
            disable_alerting=disable_alerting, 
            enable_netflow=enable_netflow
        )
        api_response = api_instance.add_device_group(new_group)
        print(f"Group '{name}' created. ID: {api_response.id}")
    except ApiException as e:
        print("Exception when calling add_device_group: %s\n" % e)

def create_device_groups(parent_device_group, selected_groups):
    path = parent_device_group.full_path
    for name, query_func, enable_netflow in group_settings:
        if name in selected_groups:
            query = query_func(path)
            create_folder(api_instance, parent_device_group.id, name, query, enable_netflow)
            

def create_location_folder(api_instance, parent_id, name):
    try:
        if check_if_group_exists(api_instance, parent_id, name):
            print(f"Group '{name}' already exists.")
            return
        
        new_group = logicmonitor_sdk.DeviceGroup(
                    name=name, 
                    parent_id=parent_id, 
        )
        api_response = api_instance.add_device_group(new_group)
        location_group_id = api_response.id

        # api_instance.add_device_group_property(location_group_id, )

        # Create sub-groups within the location group
        sub_groups = ["Network", "Power", "Services"]
        for sub_group_name in sub_groups:
            api_instance.add_device_group(logicmonitor_sdk.DeviceGroup(name=sub_group_name, parent_id=location_group_id))
            print(f"Created sub-group '{sub_group_name}' under '{name}'")
        return {"status": "success", "message": f"Location '{name}' and its sub-groups created successfully."}
        
    except ApiException as e:
        print("Exception when calling add_device_group: %s\n" % e)

@app.route('/')
def serve_html_page():
    
    LogOutput("\n\nENTERED ENTRY POINT\n\n")
    
    # Open the config file
    if path.exists('config.json'):
        LogOutput("\n\nPATH EXISTS")
        CONFIGDATA = json.load(open('config.json'))
    else:
        CONFIGDATA = None
        
    AKV_VAL = GetConfigValue(CONFIGDATA, 'AzureKeyVault', None)
        
    LogOutput(f'\n\nAZUREKEYVAULT FROM CONFIGDATA: {AKV_VAL}')
    
    with open('config.json', 'r') as f:
        config = json.load(f)
    
    AKV_VAL2 = config['AzureKeyVault']
    
    LogOutput(f'\n\nAZUREKEYVAULT NOT USING GETCONFIGVALUE: {AKV_VAL2}')
 
    global DEBUG
    DEBUG = GetConfigValue(CONFIGDATA,'DEBUG',default=False)
    
    url = "http://127.0.0.1:5001" if run_local else GetConfigValue(CONFIGDATA, 'URL', default = "https://lmnewclient-dev.azurewebsites.net")
    
    html_path = "index.html"
    
        # Put the banner out there
    LogOutput( """
    -= LMNewClient =-
    DEBUG      : %r
    PRODUCTION : %r
    CONFIG     : %r
    VERSION    : %s""" % (DEBUG, run_local, CONFIGFILE, VERSION) )
 
    LogOutput(f"CONFIGDATA: {CONFIGDATA}",3)
    
    # Set up for the interwebs
    logging.info("Setting up communication...")
    requests.packages.urllib3.disable_warnings() # unsigned SSL is OK
    session = requests.Session()
    
    # Setting keyvault vals

    # Connect to Key Vault
    LogOutput("Getting access to keys...")
    AZUREKEYVAULT = GetConfigValue(CONFIGDATA,'AzureKeyVault')
    
    LogOutput(f'\n\nAZUREKEYVAULT: {AZUREKEYVAULT}', 3)

    if AZUREKEYVAULT:
        KV_URL    = f"https://{AZUREKEYVAULT}.vault.azure.net"
        KV_CLIENT = SecretClient(vault_url=KV_URL, credential=DefaultAzureCredential())
    else:
        KV_URL    = None    
        KV_CLIENT = None
        
    LogOutput(f'\n\nKV_URL: {KV_URL} - - - KV_CLIENT: {KV_CLIENT}', 3)
    
    global CW_DOMAIN
    global CW_EPOINT
    global CW_COMPANY
       
    # key vault api parameters
    LogOutput("Setting up for ConnectWise...")
    CW_DOMAIN           = GetConfigValue(CONFIGDATA,'ConnectWise','domain','https://api-na.myconnectwise.net')
    CW_EPOINT           = GetConfigValue(CONFIGDATA,'ConnectWise','apiVersion','/v4_6_release/apis/3.0')
    CW_COMPANY		  = GetConfigValue(CONFIGDATA,'ConnectWise','company','align')
    CW_CLIENTIDSECRET   = GetConfigValue(CONFIGDATA,'ConnectWise','clientId-secret')
    CW_USERNAMESECRET  = GetConfigValue(CONFIGDATA,'ConnectWise','username-secret')
    CW_PASSWORDSECRET = GetConfigValue(CONFIGDATA,'ConnectWise','password-secret')
    LM_IDSECRET = GetConfigValue(CONFIGDATA, 'LogicMonitor', 'access_id-secret')
    LM_KEYSECRET = GetConfigValue(CONFIGDATA, 'LogicMonitor', 'access_key-secret')
        
    global CW_URL
    CW_URL = f'{CW_DOMAIN}{CW_EPOINT}'

    global CW_CLIENTID
    CW_CLIENTID         = None
    global CW_USERNAME
    CW_USERNAME        = None
    global CW_PASSWORD
    CW_PASSWORD       = None
    global LM_ID
    LM_ID = None
    global LM_KEY
    LM_KEY = None
    
    if KV_CLIENT:
        if CW_CLIENTIDSECRET:
            CW_CLIENTID = KV_CLIENT.get_secret(CW_CLIENTIDSECRET).value
        if CW_USERNAMESECRET:
            CW_USERNAME = KV_CLIENT.get_secret(CW_USERNAMESECRET).value
        if CW_PASSWORDSECRET:
            CW_PASSWORD = KV_CLIENT.get_secret(CW_PASSWORDSECRET).value
        if LM_IDSECRET:
            LM_ID = KV_CLIENT.get_secret(LM_IDSECRET)
        if LM_KEYSECRET:
            LM_KEY = KV_CLIENT.get_secret(LM_KEYSECRET)
 
    if not CW_CLIENTID:
        CW_CLIENTID   = GetConfigValue(CONFIGDATA,'ConnectWise','clientid')
    if not CW_USERNAME:
        CW_USERNAME  = GetConfigValue(CONFIGDATA,'ConnectWise','username')
    if not CW_PASSWORD:
        CW_PASSWORD = GetConfigValue(CONFIGDATA,'ConnectWise','password')
    if not LM_ID:
        LM_ID = GetConfigValue(CONFIGDATA, 'LogicMonitor', 'access_id')
    if not LM_KEY:
        LM_KEY = GetConfigValue(CONFIGDATA, 'LogicMonitor', 'access_key')
            
    LogOutput("setting up logic monitor")
        
    lmconfig = logicmonitor_sdk.Configuration()
    lmconfig.company = GetConfigValue(CONFIGDATA, 'LogicMonitor', 'company')
    lmconfig.access_id = LM_ID
    lmconfig.access_key = LM_KEY

    global api_instance
    api_instance = logicmonitor_sdk.LMApi(logicmonitor_sdk.ApiClient(lmconfig))
            

    LogOutput(f'\n\nCW CREDENTIALS: {CW_USERNAME} - {CW_PASSWORD} - {CW_CLIENTID}\n\n', 3)

    

    # LOADING HTML

    with open(html_path, 'r') as file:
        html_var = file.read()
    html_var = html_var.replace("{{ url }}", url)  # Assuming you'll place {{ url }} in your HTML where the URL should go
    return render_template_string(html_var)

    

@app.route('/create-client-folder', methods=['POST'])
@cross_origin()
def create_client_folder_route():
    try:
        data = request.json
        client_id = data['clientId']
        client_name = data['clientName']
        selected_groups = data['selectedFolders']
        selected_locations = data.get('locations', [])  # Extract locations
        loc_ids = data.get('loc_ids', [])  # Capture location IDs from the request
        loc_details = data.get('loc_details', [])

        print("Client name: ", client_name)

        clients_folder_id = 2  # ID of CLIENTS folder
        parent_id = create_client_folder(api_instance, clients_folder_id, client_name)
        
        if(parent_id):
            
            for loc_id, location in zip(loc_ids, selected_locations):
                # Assuming create_location_folder accepts location ID as an argument
                # Adjust the function signature if necessary
                create_location_folder(api_instance, parent_id, location, loc_id, loc_details.address, loc_details.city, loc_details.state)
        
            rec_id_prop = logicmonitor_sdk.models.EntityProperty(
                name= "connectwisev2.companyid",
                value= client_id
            )

            name_prop = logicmonitor_sdk.models.EntityProperty(
                name= "company.name",
                value= client_name
            )

            api_instance.add_device_group_property(parent_id, rec_id_prop)
            api_instance.add_device_group_property(parent_id, name_prop)

        
        

        if parent_id:
            # Existing logic to create selected groups
            parent_folder = api_instance.get_device_group_by_id(parent_id)
            path = parent_folder.full_path
        
            filtered_group_settings = [
                (name, query_func(path), enable_netflow)
                for name, query_func, enable_netflow in group_settings
                if name in selected_groups
            ]
        
            for name, query, enable_netflow in filtered_group_settings:
                create_folder(api_instance, parent_id, name, query, enable_netflow)

            # New logic to create location folders
            for location in selected_locations:
                # Assuming create_location_folder takes the name of the location as a parameter
                # Adjust this call as necessary based on your function's parameters
                create_location_folder(api_instance, parent_id, location)

        return jsonify({'status': 'success', 'message': f'Client folder {client_name} created with selected groups and locations.'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/get-locations', methods=['GET'])
def get_locations():
    client_id = request.args.get('clientId')  # Get clientId from query parameters
    if not client_id:
        return jsonify({'error': 'Client ID is required'}), 400
    # ConnectWise API URL for fetching locations
    url = f'https://api-na.myconnectwise.net/v4_6_release/apis/3.0/company/companies/{client_id}/sites?fields=id,name,city,stateReference/identifier,country/name&conditions=inactiveFlag=false'
    # Replace 'username' and 'password' with your ConnectWise credentials
    username = 'align+r7wyECnfZ3BaZXtd'
    password = 'bEpKrPNKppqOApnP'
    credentials = base64.b64encode(f"{username}:{password}".encode()).decode('utf-8')
    headers = {
        'Authorization': f'Basic {credentials}',
        'clientId': '8acd3927-2171-4fd9-8ebb-c88c7d387d56'
        # Add any other necessary headers here
    }
    # Make the request to ConnectWise
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return jsonify(response.json()), 200
    else:
        # Forward any errors from the ConnectWise API
        return jsonify({'error': 'Failed to fetch locations', 'details': response.text}), response.status_code
@app.route('/get-companies', methods=['GET'])
def get_companies():
    api_url = 'https://api-na.myconnectwise.net/v4_6_release/apis/3.0/company/companies?fields=id,identifier,name&orderBy=name asc&pageSize=1000&childConditions=types/name="Client"&conditions=status/name="Active"'
    
    # Encode your username and password in Base64
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
            companies = response.json()
            return jsonify(companies), 200
        else:
            return jsonify({'error': 'Failed to fetch companies'}), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 50


if __name__ == '__main__' and run_local:
    app.run(debug=True, port=5001)
  
    # read file, store in variable (html_var)
    # return HTML output (html_var), status code (200)


# add locationid and address from connectwise to location folder properties
# fix location properties
