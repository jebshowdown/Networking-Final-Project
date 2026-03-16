from Crypto.Random import get_random_bytes

# --- HELPER FUNCTION DOCSTRING ---
# Purpose: Generate a symmetric key for a user
# Input: None
# Output: symmetric key (bytes)
# Authored by: Alex
# Date: 2026-03-14
# --- END HELPER FUNCTION DOCSTRING ---
def generate_sym_key() -> bytes:
    # Generates a cryptographically secure random 32-byte (256-bit) key
    return get_random_bytes(32)

# --- TEST FUNCTION DOCSTRING ---
# Purpose: Test the generate_sym_key function
# Input: None
# Output: None
# Authored by: Alex
# Date: 2026-03-14
# --- END TEST FUNCTION DOCSTRING ---
def test_generate_sym_key():
    sym_key = generate_sym_key()
    print(sym_key.hex())
    assert len(sym_key) == 32, f"Expected 32 bytes, got {len(sym_key)}"
    print("test_generate_sym_key passed successfully!")

def main():
    test_generate_sym_key() # Run the test function for generate_sym_key
    return

if __name__ == "__main__":
    main()