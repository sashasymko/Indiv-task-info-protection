"""
task2_sign_hide.py

Signs an image with a digital RSA signature and hides the signature within the image pixels using LSB steganography.

Process overview:
1. Loads the RSA private key 4096-bit from a PEM file.
2. Reads the original image as raw byte data.
3. Calculates the SHA-256 hash of the image data.
4. Creates a digital signature by encrypting the hash with the private key.
5. Converts the signature into a hexadecimal string to allow hiding in text format.
6. Embeds the hexadecimal signature into the least significant bits of the image pixels w/o affecting the visual appearance of the image.
7. Saves the signed image, which, when opened, has the same appearance as the original but has a secret cryptographic signature.

Notes:
- Ensure that 'original.png' and 'private_key.pem' are available in the specified directories.
- Run this script to generate 'signed_image.png' with the hidden signature.
"""

from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from stegano import lsb

BASE_DIR = Path(__file__).resolve().parent
original_image_path = BASE_DIR / "images" / "original.png"
signed_image_path = BASE_DIR / "images" / "signed_image.png"
private_key_path = BASE_DIR / "keys" / "private_key.pem"

def load_private_key(path: Path):
    """Loads an RSA private key from a file"""
    with open(path, "rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )

def read_image_bytes(path: Path) -> bytes:
    """Reads an image as raw byte data"""
    with open(path, "rb") as img_file:
        return img_file.read()

def calculate_image_hash(data: bytes) -> bytes:
    """Calculates the SHA-256 hash of the image"""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()

def create_signature(private_key, data_hash: bytes) -> bytes:
    """Creates a digital RSA signature from the image hash"""
    return private_key.sign(
        data_hash,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

def hide_signature_in_image(image_path: Path, signature_hex: str, output_path: Path):
    """Hides the digital signature in the image pixels using LSB steganography"""
    secret_image = lsb.hide(str(image_path), signature_hex)
    secret_image.save(str(output_path))

def main():
    """Main function to sign and hide the signature in the image"""
    private_key = load_private_key(private_key_path)
    image_data = read_image_bytes(original_image_path)
    image_hash = calculate_image_hash(image_data)
    signature = create_signature(private_key, image_hash)
    signature_hex = signature.hex()
    hide_signature_in_image(original_image_path, signature_hex, signed_image_path)

if __name__ == "__main__":
    main()
