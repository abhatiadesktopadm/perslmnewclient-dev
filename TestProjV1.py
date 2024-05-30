import sys
import requests
import logicmonitor_sdk
from logicmonitor_sdk.rest import ApiException
import json
import base64

from flask import Flask, request, jsonify
from flask_cors import CORS, cross_origin

app = Flask(__name__)
CORS(app)

@app.after_request
def set_cache_control(response):
    """Set Cache-Control headers for all responses."""
    response.headers['Cache-Control'] = 'public, max-age=3600, stale-while-revalidate=2592000'
    return response

# Configure API key authorization: LMv1
lmconfig = logicmonitor_sdk.Configuration()
lmconfig.company = 'align'
lmconfig.access_id = '3sG44q9cJk7VD674EydM'
lmconfig.access_key = '(=(+rHtgLSmqDCrq7r3Pev6T(=Q9_qDVyA8}_]p='

api_instance = logicmonitor_sdk.LMApi(logicmonitor_sdk.ApiClient(lmconfig))

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
            print(f"Client folder '{client_name}' already exists.")
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
        location_id = api_response.id
        
        

        api_instance.add_device_group_property(location_id, )
        
        # Create sub-groups within the location group
        sub_groups = ["Network", "Power", "Services"]
        for sub_group_name in sub_groups:
            api_instance.add_device_group(logicmonitor_sdk.DeviceGroup(name=sub_group_name, parent_id=location_id))
            print(f"Created sub-group '{sub_group_name}' under '{name}'")

        return {"status": "success", "message": f"Location '{name}' and its sub-groups created successfully."}

        
    except ApiException as e:
        print("Exception when calling add_device_group: %s\n" % e)
    
      
        
@app.route('/create-client-folder', methods=['POST'])
@cross_origin()
def create_client_folder_route():
    try:
        data = request.json
        client_id = data['clientId']
        client_name = data['clientName']
        selected_groups = data['selectedFolders']
        selected_locations = data.get('locations', [])  # Extract locations

        print("Client name: ", client_name)

        clients_folder_id = 2  # ID of CLIENTS folder
        parent_id = create_client_folder(api_instance, clients_folder_id, client_name)
        
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
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5001)

def main():
    clients_folder_id = 2  # Replace with the actual ID of your "CLIENTS" folder
    client_name = input("Enter the name of the new client folder: ")
    parent_id = create_client_folder(api_instance, clients_folder_id, client_name)

    if parent_id:
        parent_folder = api_instance.get_device_group_by_id(parent_id)
        create_device_groups(parent_folder)




# add locationid and address from connectwise to location folder properties
# add company rec id and company name from connectwise to properties
#   first use Postman to see what the names of the properties are
# disable submit button until required properties are fulfilled
