"""
task3_verify.py

Verifies the presence and correctness of an RSA digital signature embedded in an image using LSB steganography.

Process overview:
1. Loads the RSA public key from a PEM file.
2. Reads the original image as raw byte data.
3. Calculates the SHA-256 hash of the original image data.
4. Extracts the hidden digital signature from the signed image using LSB steganography.
5. Converts the extracted hexadecimal signature back into bytes.
6. Verifies the extracted signature against the recalculated image hash using the public RSA key.
7. Outputs whether the signature is valid (the image is untampered) or invalid (the image may have been altered).

Notes: 
- If the signed image has been modified, the verification will fail.
- If the hidden signature cannot be detected, a clear error message is displayed.
- Ensure that 'original.png', 'signed_image.png', 'try.png', and 'public_key.pem' are present in the specified directories.
"""

from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from stegano import lsb

BASE_DIR = Path(__file__).resolve().parent
original_image_path = BASE_DIR / "images" / "original.png"
signed_image_path = BASE_DIR / "images" / "signed_image.png" #you can change here
public_key_path = BASE_DIR / "keys" / "public_key.pem"

def main():
    """Main function to verify the digital signature"""

    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    # read 
    with open(original_image_path, "rb") as img_file:
        original_data = img_file.read()

    # calculate 
    digest = hashes.Hash(hashes.SHA256())
    digest.update(original_data)
    image_hash = digest.finalize()

    # extract 
    try:
        signature_hex = lsb.reveal(str(signed_image_path))
        if signature_hex is None:
            print("No hidden signature found.")
            return
    except IndexError:
        print("Cannot detect hidden signature, the image may have been altered.")
        return

    # from hex to bytes
    signature = bytes.fromhex(signature_hex)

    # verify
    try:
        public_key.verify(
            signature,
            image_hash,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print("Signature is valid, the image is untampered.")
    except InvalidSignature:
        print("Signature is invalid, the image might have been altered.")

if __name__ == "__main__":
    main()
