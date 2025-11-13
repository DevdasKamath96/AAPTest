import requests
import logging
import json
import os
import sys

# Setup logger
logger = logging.getLogger("CreateFreshLaunchWF")
logger.setLevel(logging.DEBUG)
file_handler = logging.FileHandler("CreateFreshLaunchWF.log")
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# AAP API details
AAP_HOST = "https://controller.example.org"
API_TOKEN = "your-api-token"
HEADERS = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {API_TOKEN}"
}

def create_workflow_job_template(name, description, organization):
    
    url = f"{AAP_HOST}/api/v2/workflow_job_templates/"
    payload = {
        "name": name,
        "description": description,
        "organization": organization
    }
    logger.debug(f"Creating workflow job template: {payload}")
    response = requests.post(url, json=payload, headers=HEADERS, verify=False)
    logger.debug(f"Response [{response.status_code}]: {response.text}")
    if response.status_code == 201:
        logger.info(f"Workflow Job Template '{name}' created successfully.")
        return response.json()["id"]
    else:
        logger.error(f"Error creating workflow job template: {response.text}")
        print("Error:", response.text)
        return None
    
def link_workflow_nodes(parent_node_id, child_node_id, relationship_type="success"):
    """
    Links two workflow nodes based on the relationship type.
    :param parent_node_id: ID of the parent node
    :param child_node_id: ID of the child node
    :param relationship_type: Type of relationship ('success', 'failure', etc.)
    :return: True if linked successfully, else False
    """
    url = f"{AAP_HOST}/api/v2/workflow_job_template_nodes/{parent_node_id}/{relationship_type}_nodes/"
    payload = {"id": child_node_id}
    logger.debug(f"Linking node {child_node_id} as {relationship_type} to parent {parent_node_id}")
    response = requests.post(url, json=payload, headers=HEADERS, verify=False)
    logger.debug(f"Link response [{response.status_code}]: {response.text}")
    if response.status_code == 204:
        logger.info(f"Nodes linked successfully: {parent_node_id} -> {child_node_id} ({relationship_type})")
        return True
    else:
        logger.error(f"Error linking nodes: {response.text}")
        print("Error linking nodes:", response.text)
        return False


def add_workflow_node(wfjt_id, job_template_id, inventory, node_type='success', parent_nodes=None):
    """
    Adds a node to the workflow job template.
    :param wfjt_id: Workflow Job Template ID
    :param job_template_id: Job Template ID to add as node
    :param success_nodes: List of node IDs to link as 'success' (optional)
    :return: Node ID if created, else None
    """
    url = f"{AAP_HOST}/api/v2/workflow_job_template_nodes/"
    payload = {
        "workflow_job_template": wfjt_id,
        "unified_job_template": job_template_id,
        "inventory": inventory
    }
    logger.debug(f"Adding workflow node: {payload}")
    response = requests.post(url, json=payload, headers=HEADERS, verify=False)
    logger.debug(f"Node response [{response.status_code}]: {response.text}")
    if response.status_code == 201:
        node_id = response.json()["id"]
        logger.info(f"Node for job template {job_template_id} added with ID {node_id}")
        # Link parent nodes if provided
        if parent_nodes:
            for parent_id in parent_nodes:
                link_workflow_nodes(parent_id, node_id, relationship_type=node_type)
        return node_id
    else:
        logger.error(f"Error adding workflow node: {response.text}")
        print("Error adding workflow node:", response.text)
        return None
    
def get_organization_id(org_name):
        """
        Fetches the organization ID for the given organization name.
        :param org_name: Name of the organization
        :return: Organization ID if found, else None
        """
        url = f"{AAP_HOST}/api/v2/organizations/?name={org_name}"
        logger.debug(f"Fetching organization ID for '{org_name}'")
        response = requests.get(url, headers=HEADERS, verify=False)
        logger.debug(f"Organization response [{response.status_code}]: {response.text}")
        if response.status_code == 200 and response.json()["count"] > 0:
            org_id = response.json()["results"][0]["id"]
            logger.info(f"Organization '{org_name}' found with ID {org_id}")
            return org_id
        else:
            logger.error(f"Organization '{org_name}' not found.")
            print(f"Organization '{org_name}' not found.")
            return None
        
def get_api_token(username, password):
        """
        Authenticates with AAP and returns an API token.
        :param username: Username for authentication
        :param password: Password for authentication
        :return: API token string if successful, else None
        """
        auth_url = f"{AAP_HOST}/api/v2/tokens/"
        logger.debug(f"Authenticating with {auth_url} as {username}")
        auth_response = requests.post(auth_url, auth=(username, password), verify=False)
        logger.debug(f"Auth response [{auth_response.status_code}]: {auth_response.text}")
        if auth_response.status_code == 201:
            token = auth_response.json()["token"]
            logger.info("Authenticated and token acquired.")
            print("Authenticated and token acquired.")
            return token
        else:
            logger.error(f"Authentication failed: {auth_response.text}")
            print("Authentication failed:", auth_response.text)
            return None
        

def get_workflow_node_id(wfjt_id, node_name):
    """
    Fetches the node ID for a given node name in the workflow job template.
    :param wfjt_id: Workflow Job Template ID
    :param node_name: Name of the node/job template
    :return: Node ID if found, else None
    """
    nodes_url = f"{AAP_HOST}/api/v2/workflow_job_template_nodes/?workflow_job_template={wfjt_id}&unified_job_template__name={node_name}"
    nodes_response = requests.get(nodes_url, headers=HEADERS, verify=False)
    logger.debug(f"Workflow node response [{nodes_response.status_code}]: {nodes_response.text}")
    if nodes_response.status_code == 200 and nodes_response.json()["count"] > 0:
        node_id = nodes_response.json()["results"][0]["id"]
        logger.info(f"Node '{node_name}' in workflow has ID {node_id}")
        print(f"Node '{node_name}' in workflow has ID {node_id}")
        return node_id
    else:
        logger.error(f"Node '{node_name}' not found in workflow: {nodes_response.text}")
        print(f"Node '{node_name}' not found in workflow:", nodes_response.text)
        return None

def load_config_from_json(json_path):
    """
    Loads workflow configuration from a JSON file.
    :param json_path: Path to the JSON config file
    :return: Dictionary with config data
    """
    if not os.path.exists(json_path):
        logger.error(f"Config file '{json_path}' not found.")
        print(f"Config file '{json_path}' not found.")
        exit(1)
    with open(json_path, "r") as f:
        try:
            config = json.load(f)
            logger.info(f"Loaded config from {json_path}")
            return config
        except Exception as e:
            logger.error(f"Error reading config file: {e}")
            print(f"Error reading config file: {e}")
            exit(1)

if __name__ == "__main__":

    # Load config from JSON file

    if len(sys.argv) < 2:
        print("Usage: python CreateFreshLaunchWF.py <config.json>")
        exit(1)
    
    config_path = sys.argv[1]
    config = load_config_from_json(config_path)

    wf_name = config.get("wf_name", "Fresh Launch Workflow")
    wf_desc = config.get("wf_description", "Workflow for fresh container launch")
    org_name = config.get("organization", "Default")
    template_data = config.get("templates", [])
    username = config.get("aap_user", "admin")
    password = config.get("aap_password", "redhat")

    # Get API token and update HEADERS
    token = get_api_token(username, password)
    if token is None:
        exit(1)
    HEADERS["Authorization"] = f"Bearer {token}"

    org_id = get_organization_id(org_name)
    if org_id is None:
        exit(1)

    for data in template_data:
        url = f"{AAP_HOST}/api/v2/job_templates/?name={data['Node']}"
        logger.debug(f"Fetching job template '{data['Node']}'")
        response = requests.get(url, headers=HEADERS, verify=False)
        logger.debug(f"Job template response [{response.status_code}]: {response.text}")
        if response.status_code == 200 and response.json()["count"] > 0:
            jt = response.json()["results"][0]
            data.update({"ID": jt["id"]})
            logger.info(f"Job template '{data['Node']}' found with ID {jt['id']}")
        else:
            logger.error(f"Job template '{data['Node']}' not found.")
            print(f"Job template '{data['Node']}' not found.")
            exit(1)

    wfjt_id = create_workflow_job_template(wf_name, wf_desc, org_id)

    print(f"Updated templates --> {template_data}")

    # Add first node (CreateTestFile)
    if wfjt_id is None:
        logger.error("Workflow Job Template creation failed. Exiting.")
        exit(1)

    for data in template_data:
        # Fetch node ID for the current node name in the workflow job template
        parent_ids = []
        for nodes in data.get('Parent', []):
            node_id = get_workflow_node_id(wfjt_id, nodes)
            if node_id:
                parent_ids.append(node_id)

        parent_id = add_workflow_node(wfjt_id, data['ID'], inventory=data.get('Inventory'), node_type = data.get('NodeType'), parent_nodes=parent_ids)
        



