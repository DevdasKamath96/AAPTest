import requests
import yaml

class BaseCreateInventory:
    def __init__(self, aap_url: str, aap_user: str, aap_password: str):
        self.aap_url = aap_url
        self.aap_user = aap_user
        self.aap_password = aap_password

class CreateInventory(BaseCreateInventory):

    def __init__(self, aap_url: str, aap_user: str, aap_password: str, organization_name: str, logger):
        super().__init__(aap_url, aap_user, aap_password)
        self.organization_name = organization_name
        self.logger = logger
        self.headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.get_auth_token(aap_user, aap_password)}"
        }
        self.organization_id = self.get_organization_id(organization_name)


    def get_auth_token(self, username, password):
        url = f"{self.aap_url}/tokens/"
        self.logger.info(f"Fetching AAP token for user '{username}'")
        resp = requests.post(url, auth=(username, password))
        self.logger.info(f"Token fetch response: {resp.status_code} {resp.text}")
        resp.raise_for_status()
        token = resp.json()["token"]
        self.logger.info(f"Token received: {token}")
        return token

    def get_organization_id(self, organization_name: str) -> int:
        self.logger.info(f"Getting organization ID for: {organization_name}")
        url = f"{self.aap_url}/organizations/?name={organization_name}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()

        organizations = response.json().get("results", [])
        if organizations:
            org_id = organizations[0]["id"]
            self.logger.info(f"Found organization ID: {org_id}")
            return org_id
        self.logger.error(f"Organization '{organization_name}' not found")
        raise ValueError(f"Organization '{organization_name}' not found.")

    def create_inventory(self, name: str, variables: dict) -> str:
        variables_str = yaml.dump(variables) if variables else ""
        payload = {
            "name": name,
            "organization": self.organization_id,
            "variables": variables_str
        }
        self.logger.info(f"Creating inventory with payload: {payload}")
        resp = requests.post(f"{self.aap_url}/inventories/", json=payload, headers=self.headers)
        self.logger.info(f"Inventory creation response: {resp.status_code} {resp.text}")
        resp.raise_for_status()
        inventory_id = resp.json()["id"]
        self.logger.info(f"Inventory created with ID: {inventory_id}")
        return inventory_id
    
    def check_inventory_exists(self, name: str) -> bool:
        self.logger.info(f"Checking if inventory exists: {name}")
        url = f"{self.aap_url}/inventories/?name={name}&organization_id={self.organization_id}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        inventory = response.json().get("results", [])
        exists = len(inventory) > 0
        self.logger.info(f"Inventory {name} exists: {exists}")
        return exists
    
    def get_inventory_id(self, name: str) -> int:
        self.logger.info(f"Getting inventory ID for: {name}")
        url = f"{self.aap_url}/inventories/?name={name}&organization_id={self.organization_id}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        inventories = response.json().get("results", [])
        if inventories:
            inventory_id = inventories[0]["id"]
            self.logger.info(f"Found inventory ID: {inventory_id}")
            return inventory_id
        self.logger.error(f"Inventory '{name}' not found")
        raise ValueError(f"Inventory '{name}' not found.")

    def update_inventory_vars(self, name: str, variables: dict) -> None:
        variables_str = yaml.dump(variables) if variables else ""
        self.logger.info(f"Updating inventory variables for: {name}")
        inventory_id = self.get_inventory_id(name)
        url = f"{self.aap_url}/inventories/{inventory_id}/"
        payload = {"variables": variables_str}
        response = requests.patch(url, headers=self.headers, json=payload)
        response.raise_for_status()
        self.logger.info(f"Updated inventory variables for: {name}")
        
    def get_inventory_vars(self, name: str) -> dict:
        self.logger.info(f"Reading inventory variables for: {name}")
        inventory_id = self.get_inventory_id(name)
        url = f"{self.aap_url}/inventories/{inventory_id}/"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        variables = response.json().get("variables", {})
        self.logger.info(f"Retrieved variables for inventory: {name}")
        return yaml.safe_load(variables) if variables else {}
        
    def delete_inventory(self, name: str) -> None:
        self.logger.info(f"Deleting inventory: {name}")
        inventory_id = self.get_inventory_id(name)
        url = f"{self.aap_url}/inventories/{inventory_id}/"
        response = requests.delete(url, headers=self.headers)
        response.raise_for_status()
        self.logger.info(f"Deleted inventory: {name}")
        
    def check_host_exists(self, inventory_name: str, host_name: str) -> bool:
        self.logger.info(f"Checking if host exists: {host_name} in inventory: {inventory_name}")
        inventory_id = self.get_inventory_id(inventory_name)
        url = f"{self.aap_url}/hosts/?name={host_name}&inventory_id={inventory_id}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        hosts = response.json().get("results", [])
        exists = len(hosts) > 0
        self.logger.info(f"Host {host_name} exists in {inventory_name}: {exists}")
        return exists

    def create_host(self, inventory_name: str, host_name: str) -> str:
        self.logger.info(f"Creating host: {host_name} in inventory: {inventory_name}")
        inventory_id = self.get_inventory_id(inventory_name)
        url = f"{self.aap_url}/inventories/{inventory_id}/hosts/"
        payload = {"name": host_name}
        response = requests.post(url, headers=self.headers, json=payload)
        response.raise_for_status()
        host_id = response.json().get("id", "")
        self.logger.info(f"Created host {host_name} with ID: {host_id}")
        return host_id
    
    def get_host_id(self, inventory_name: str, host_name: str) -> int:
        self.logger.info(f"Getting host ID for: {host_name} in inventory: {inventory_name}")
        inventory_id = self.get_inventory_id(inventory_name)
        url = f"{self.aap_url}/hosts/?name={host_name}&inventory_id={inventory_id}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        hosts = response.json().get("results", [])
        if hosts:
            host_id = hosts[0]["id"]
            self.logger.info(f"Found host ID: {host_id}")
            return host_id
        self.logger.error(f"Host '{host_name}' not found in inventory '{inventory_name}'")
        raise ValueError(f"Host '{host_name}' not found in inventory '{inventory_name}'.")
    
    def delete_host(self, inventory_name: str, host_name: str) -> None:
        self.logger.info(f"Deleting host: {host_name} from inventory: {inventory_name}")
        host_id = self.get_host_id(inventory_name, host_name)
        url = f"{self.aap_url}/hosts/{host_id}/"
        response = requests.delete(url, headers=self.headers)
        response.raise_for_status()
        self.logger.info(f"Deleted host: {host_name}")
        
    def get_hosts_in_inventory(self, inventory_name: str) -> list:
        self.logger.info(f"Getting hosts in inventory: {inventory_name}")
        inventory_id = self.get_inventory_id(inventory_name)
        url = f"{self.aap_url}/hosts/?inventory_id={inventory_id}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        hosts = response.json().get("results", [])
        host_names = [host["name"] for host in hosts]
        self.logger.info(f"Found {len(host_names)} hosts in inventory {inventory_name}")
        return host_names
    
    def get_host_vars(self, inventory_name: str, host_name: str) -> dict:
        self.logger.info(f"Getting variables for host: {host_name} in inventory: {inventory_name}")
        inventory_id = self.get_inventory_id(inventory_name)
        url = f"{self.aap_url}/hosts/?name={host_name}&inventory_id={inventory_id}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        hosts = response.json().get("results", [])
        if hosts:
            variables = hosts[0].get("variables", {})
            self.logger.info(f"Retrieved variables for host: {host_name}")
            return variables
        self.logger.error(f"Host '{host_name}' not found in inventory '{inventory_name}'")
        raise ValueError(f"Host '{host_name}' not found in inventory '{inventory_name}'.")
    
    def update_host_vars(self, inventory_name: str, host_name: str, variables: dict) -> None:
        variables_str = yaml.dump(variables) if variables else ""
        self.logger.info(f"Updating variables for host: {host_name} in inventory: {inventory_name}")
        inventory_id = self.get_inventory_id(inventory_name)
        url = f"{self.aap_url}/hosts/?name={host_name}&inventory_id={inventory_id}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        hosts = response.json().get("results", [])
        if not hosts:
            self.logger.error(f"Host '{host_name}' not found in inventory '{inventory_name}'")
            raise ValueError(f"Host '{host_name}' not found in inventory '{inventory_name}'.")
        
        host_id = hosts[0]["id"]
        url = f"{self.aap_url}/hosts/{host_id}/"
        payload = {"variables": variables_str}
        response = requests.patch(url, headers=self.headers, json=payload)
        response.raise_for_status()
        self.logger.info(f"Updated variables for host: {host_name}")
        
    def create_group(self, inventory_name: str, group_name: str) -> str:
        self.logger.info(f"Creating group: {group_name} in inventory: {inventory_name}")
        inventory_id = self.get_inventory_id(inventory_name)
        url = f"{self.aap_url}/inventories/{inventory_id}/groups/"
        payload = {"name": group_name}
        response = requests.post(url, headers=self.headers, json=payload)
        response.raise_for_status()
        group_id = response.json().get("id", "")
        self.logger.info(f"Created group {group_name} with ID: {group_id}")
        return group_id
    
    def get_groups_in_inventory(self, inventory_name: str) -> list:
        self.logger.info(f"Getting groups in inventory: {inventory_name}")
        inventory_id = self.get_inventory_id(inventory_name)
        url = f"{self.aap_url}/groups/?inventory_id={inventory_id}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        groups = response.json().get("results", [])
        group_names = [group["name"] for group in groups]
        self.logger.info(f"Found {len(group_names)} groups in inventory {inventory_name}")
        return group_names
    
    def get_group_id(self, inventory_name: str, group_name: str) -> int:
        self.logger.info(f"Getting group ID for: {group_name} in inventory: {inventory_name}")
        inventory_id = self.get_inventory_id(inventory_name)
        url = f"{self.aap_url}/groups/?name={group_name}&inventory_id={inventory_id}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        groups = response.json().get("results", [])
        if groups:
            group_id = groups[0]["id"]
            self.logger.info(f"Found group ID: {group_id}")
            return group_id
        self.logger.error(f"Group '{group_name}' not found in inventory '{inventory_name}'")
        raise ValueError(f"Group '{group_name}' not found in inventory '{inventory_name}'.")
    
    def get_group_vars(self, inventory_name: str, group_name: str) -> dict:
        self.logger.info(f"Getting variables for group: {group_name} in inventory: {inventory_name}")
        inventory_id = self.get_inventory_id(inventory_name)
        url = f"{self.aap_url}/groups/?name={group_name}&inventory_id={inventory_id}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        groups = response.json().get("results", [])
        if groups:
            variables = groups[0].get("variables", {})
            self.logger.info(f"Retrieved variables for group: {group_name}")
            return variables
        self.logger.error(f"Group '{group_name}' not found in inventory '{inventory_name}'")
        raise ValueError(f"Group '{group_name}' not found in inventory '{inventory_name}'.")
    
    def update_group_vars(self, inventory_name: str, group_name: str, variables: dict) -> None:
        self.logger.info(f"Updating variables for group: {group_name} in inventory: {inventory_name}")
        inventory_id = self.get_inventory_id(inventory_name)
        url = f"{self.aap_url}/groups/?name={group_name}&inventory_id={inventory_id}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        groups = response.json().get("results", [])
        if not groups:
            self.logger.error(f"Group '{group_name}' not found in inventory '{inventory_name}'")
            raise ValueError(f"Group '{group_name}' not found in inventory '{inventory_name}'.")
        
        group_id = groups[0]["id"]
        url = f"{self.aap_url}/groups/{group_id}/"
        payload = {"variables": variables}
        response = requests.patch(url, headers=self.headers, json=payload)
        response.raise_for_status()
        self.logger.info(f"Updated variables for group: {group_name}")
        
    def add_host_to_group(self, inventory_name: str, host_name: str, group_name: str) -> None:
        self.logger.info(f"Adding host {host_name} to group {group_name} in inventory {inventory_name}")
        inventory_id = self.get_inventory_id(inventory_name)
        
        # Get host ID
        host_id = self.get_host_id(inventory_name, host_name)
        
        # Get group ID
        group_id = self.get_group_id(inventory_name, group_name)
        
        # Add host to group
        url = f"{self.aap_url}/groups/{group_id}/hosts/"
        payload = {"id": host_id}
        response = requests.post(url, headers=self.headers, json=payload)
        response.raise_for_status()
        self.logger.info(f"Added host {host_name} to group {group_name}")
        
    def add_hosts_to_group(self, inventory_name: str, host_names: list, group_name: str) -> None:
        self.logger.info(f"Adding {len(host_names)} hosts to group {group_name} in inventory {inventory_name}")
        inventory_id = self.get_inventory_id(inventory_name)
        
        # Get group ID
        group_id = self.get_group_id(inventory_name, group_name)
        
        for host_name in host_names:
            # Get host ID
            host_id = self.get_host_id(inventory_name, host_name)
            
            # Add host to group
            url = f"{self.aap_url}/groups/{group_id}/hosts/"
            payload = {"id": host_id}
            response = requests.post(url, headers=self.headers, json=payload)
            response.raise_for_status()
            self.logger.info(f"Added host {host_name} to group {group_name}")
            
    def remove_host_from_group(self, inventory_name: str, host_name: str, group_name: str) -> None:
        self.logger.info(f"Removing host {host_name} from group {group_name} in inventory {inventory_name}")
        inventory_id = self.get_inventory_id(inventory_name)
        
        # Get host ID
        host_id = self.get_host_id(inventory_name, host_name)
        
        # Get group ID
        group_id = self.get_group_id(inventory_name, group_name)
        
        # Remove host from group
        url = f"{self.aap_url}/groups/{group_id}/hosts/{host_id}/"
        response = requests.delete(url, headers=self.headers)
        response.raise_for_status()
        self.logger.info(f"Removed host {host_name} from group {group_name}")
    
    def remove_hosts_from_group(self, inventory_name: str, host_names: list, group_name: str) -> None:
        self.logger.info(f"Removing {len(host_names)} hosts from group {group_name} in inventory {inventory_name}")
        inventory_id = self.get_inventory_id(inventory_name)
        
        # Get group ID
        group_id = self.get_group_id(inventory_name, group_name)
        
        for host_name in host_names:
            # Get host ID
            host_id = self.get_host_id(inventory_name, host_name)
            
            # Remove host from group
            url = f"{self.aap_url}/groups/{group_id}/hosts/{host_id}/"
            response = requests.delete(url, headers=self.headers)
            response.raise_for_status()
            self.logger.info(f"Removed host {host_name} from group {group_name}")

