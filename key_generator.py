from Crypto.PublicKey import RSA
import json

def generate_server_keys():
    """Outputs RSA keys if they don't exist"""
    priv_path = "Server/server_private.pem"
    pub_path = "Server/server_public.pem"
    print("Generating server RSA keys...")
    key = RSA.generate(2048)
    with open(priv_path, "wb") as f:
        f.write(key.export_key('PEM'))
    with open(pub_path, "wb") as f:
        f.write(key.publickey().export_key('PEM'))

def generate_client_keys(username):
    """Outputs RSA keys if they don't exist for the given username"""
    priv_path = f"Client/{username}_private.pem"
    pub_path = f"Client/{username}_public.pem"
    print(f"Generating client RSA keys for {username}...")
    key = RSA.generate(2048)
    with open(priv_path, "wb") as f:
        f.write(key.export_key('PEM'))
    with open(pub_path, "wb") as f:
        f.write(key.publickey().export_key('PEM'))

generate_server_keys()

with open("Server/user_pass.json", "r") as f:
    user_data = json.load(f)

    for username in user_data:
        generate_client_keys(username)