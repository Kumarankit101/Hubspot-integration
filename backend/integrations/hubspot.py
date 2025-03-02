# slack.py

from fastapi import Request, HTTPException
import base64
import secrets
import json
import httpx
from fastapi.responses import HTMLResponse
import asyncio
import requests
from integrations.integration_item import IntegrationItem


from redis_client import add_key_value_redis, get_value_redis, delete_key_redis


CLIENT_ID = "XXXXXX"
CLIENT_SECRET = "XXXXXX"
encoded_client_id_secret = base64.b64encode(
    f"{CLIENT_ID}:{CLIENT_SECRET}".encode()
).decode()

REDIRECT_URI = "http://localhost:8000/integrations/hubspot/oauth2callback"
authorization_url = f"https://app.hubspot.com/oauth/authorize?client_id={CLIENT_ID}&response_type=code&redirect_uri={REDIRECT_URI}&scope=oauth%20crm.objects.contacts.read"


async def authorize_hubspot(user_id, org_id):
    state_data = {
        "state": secrets.token_urlsafe(32),
        "user_id": user_id,
        "org_id": org_id,
    }
    encoded_state = json.dumps(state_data)
    await add_key_value_redis(
        f"hubspot_state:{org_id}:{user_id}", encoded_state, expire=600
    )
    print(f"{authorization_url}&state={encoded_state}")
    return f"{authorization_url}&state={encoded_state}"


async def oauth2callback_hubspot(request: Request):
    if request.query_params.get("error"):
        raise HTTPException(status_code=400, detail=request.query_params.get("error"))

    code = request.query_params.get("code")
    print("code", code)
    encoded_state = request.query_params.get("state")
    state_data = json.loads(encoded_state)

    original_state = state_data.get("state")
    user_id = state_data.get("user_id")
    org_id = state_data.get("org_id")
    saved_state = await get_value_redis(f"hubspot_state:{org_id}:{user_id}")
    if not saved_state or original_state != json.loads(saved_state).get("state"):
        raise HTTPException(status_code=400, detail="State does not match.")

    async with httpx.AsyncClient() as client:
        response, _ = await asyncio.gather(
            client.post(
                "https://api.hubapi.com/oauth/v1/token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": REDIRECT_URI,
                    "client_id": CLIENT_ID,
                    "client_secret": CLIENT_SECRET,
                },
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            ),
            delete_key_redis(f"hubspot_state:{org_id}:{user_id}"),
        )

    print("Response Status Code:", response.status_code)
    print("Response Content:", response.text)  # Debug response

    await add_key_value_redis(
        f"hubspot_credentials:{org_id}:{user_id}",
        json.dumps(response.json()),
        expire=600,
    )

    close_window_script = """
    <html>
        <script>
            window.close();
        </script>
    </html>
    """
    return HTMLResponse(content=close_window_script)


async def get_hubspot_credentials(user_id, org_id):
    credentials = await get_value_redis(f"hubspot_credentials:{org_id}:{user_id}")
    if not credentials:
        raise HTTPException(status_code=400, detail="No credentials found.")
    credentials = json.loads(credentials)
    if not credentials:
        raise HTTPException(status_code=400, detail="No credentials found.")
    await delete_key_redis(f"hubspot_credentials:{org_id}:{user_id}")

    return credentials


def _recursive_dict_search(data, target_key, default=None):
    """Recursively searches for a key in a nested dictionary, returning a default if not found."""
    if isinstance(data, dict):
        if target_key in data:
            return data[target_key]
        for key, value in data.items():
            result = _recursive_dict_search(value, target_key, default)
            if result is not None:
                return result
    elif isinstance(data, list):
        for item in data:
            result = _recursive_dict_search(item, target_key, default)
            if result is not None:
                return result
    return default


def create_integration_item_metadata_object(response_json: dict) -> IntegrationItem:
    """Creates an IntegrationItem object from a HubSpot API response."""
    field_mappings = {
        "id": "id",
        "type": ("type", "contact"),
        "name": ("name", ""),
        "creation_time": "createdAt",
        "last_modified_time": "updatedAt",
        "url": "url",
        "children": ("associatedObjects", []),
        "parent_path_or_name": "parent_path_or_name",
        "parent_id": "parent_id",
        "directory": ("directory", False),
        "mime_type": "mime_type",
        "delta": "delta",
        "drive_id": "drive_id",
        "visibility": ("visibility", False),
    }

    item_data = {}
    for key, mapping in field_mappings.items():
        if isinstance(mapping, tuple):
            item_data[key] = _recursive_dict_search(
                response_json, mapping[0], mapping[1]
            )
        else:
            item_data[key] = _recursive_dict_search(response_json, mapping)

    firstname = _recursive_dict_search(response_json, "firstname")
    lastname = _recursive_dict_search(
        response_json,
        "lastname",
    )
    item_data["name"] = f"{firstname} {lastname}".strip()

    return IntegrationItem(**item_data)


async def get_items_hubspot(credentials) -> list[IntegrationItem]:
    """Fetches items from HubSpot and handles potential errors."""
    credentials = json.loads(credentials)
    try:
        response = requests.get(
            "https://api.hubapi.com/crm/v3/objects/contacts",
            headers={
                "Authorization": f"Bearer {credentials.get('access_token')}",
                "Content-Type": "application/json",
            },
        )

        # Check if the response status code is not 200
        if response.status_code != 200:
            raise HTTPException(
                status_code=response.status_code,
                detail=f"Error fetching data from HubSpot: {response.text}",
            )

        # Attempt to parse the JSON response
        try:
            results = response.json().get("results", [])
        except ValueError as e:
            raise HTTPException(
                status_code=500, detail=f"Error parsing JSON response: {str(e)}"
            )

        # Process the results
        list_of_integration_item_metadata = []
        for result in results:
            list_of_integration_item_metadata.append(
                create_integration_item_metadata_object(result)
            )

        return list_of_integration_item_metadata

    except requests.exceptions.RequestException as e:
        # Handle network-related errors
        raise HTTPException(status_code=500, detail=f"Network error occurred: {str(e)}")
