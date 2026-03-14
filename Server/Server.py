from Crypto.Hash import SHA256

# --- HELPER FUNCTION DOCSTRING ---
# Purpose: Generate a symmetric key for a user
# Input: username (str), password (str)
# Output: symmetric key (bytes)
# Authored by: Alex
# Date: 2026-03-14
# --- END HELPER FUNCTION DOCSTRING ---
def generate_sym_key(username: str, password: str) -> bytes:
    # Create a SHA256 hash object
    hash_object = SHA256.new()
    
    # Update the hash object with the username and password
    hash_object.update(username.encode('utf-8') + password.encode('utf-8'))
    
    # Return the hash object as bytes
    return hash_object.digest()

# --- TEST FUNCTION DOCSTRING ---
# Purpose: Test the generate_sym_key function
# Input: None
# Output: None``
# Authored by: Alex
# Date: 2026-03-14
# --- END TEST FUNCTION DOCSTRING ---
def test_generate_sym_key():
    U_name = "alex"
    P_word = "1234ABC!@#$"
    sym_key = generate_sym_key(U_name, P_word)
    expected_hex = "a14ade246c55db85f04c3f1c33b280dc6b65e758ce1a56239eae6f7619651dec"
    assert sym_key.hex() == expected_hex, f"Expected {expected_hex}, got {sym_key.hex()}"
    print("test_generate_sym_key passed successfully!")

def main():
    test_generate_sym_key() # Run the test function for generate_sym_key
    return

if __name__ == "__main__":
    main()