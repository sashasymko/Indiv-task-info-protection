# Indiv-task-info-protection

### Overview

This project demonstrates how to digitally sign an image using an RSA 4096-bit private key, hide the signature invisibly inside the image pixels using LSB steganography, and verify the authenticity and integrity of the image using the public key.

The solution ensures that:

- The signed image visually remains identical to the original.

- The signature is hidden in a way that is hard to detect using simple methods.

- Any modification to the image (even a single pixel) invalidates the signature.

### Project Structure

```plaintext
  indiv_task/
  ├── task2_sign_hide.py       
  ├── task3_verify.py          
  ├── keys/
  │   ├── private_key.pem     
  │   └── public_key.pem      
  ├── images/
  │   ├── original.png        
  │   ├── signed_image.png    
  │   └── try.png             
  ├── requirements.txt       
  └── README.md                    
```

### How it works

**Sign and Hide** (task2_sign_hide.py)

- The program loads the original image and calculates its SHA-256 hash.

- It generates a digital signature by encrypting the hash with the RSA private key.

- The signature is converted to hexadecimal format and hidden inside the image pixels using Least Significant Bit steganography.

- The resulting signed image is saved and looks identical to the original when opened.

**Verifying** (task3_verify.py)

- The program extracts the hidden signature from the signed image.

- It recalculates the SHA-256 hash of the original image.

- It verifies the extracted signature against the newly calculated hash using the RSA public key.

- If the signature is valid, the image has not been altered.

- If the signature is missing, corrupted, or does not match, it means the image has been modified.
 

### How it works

Install required libraries: 

```plaintext
 pip install -r requirements.txt                  
```

Generate the signed image with hidden signature:

```plaintext
python task2_sign_hide.py
```

Verify the signature of the signed image:

```plaintext
python task3_verify.py               
```

### Testing

**Basic test:**

Run task2_sign_hide.py to generate a signed image.

Run task3_verify.py — it should output:


```plaintext
Signature is valid, the image is untampered.               
```

**Tampering test:**

You can open signed_image.png in any image editor, modify it in any way, save it, and then re-run task3_verify.py to check that the signature verification fails.

Alternatively, you can simply use try.png from the images/ directory,
which is already a modified image and will fail the signature verification test.

```plaintext
Cannot detect hidden signature, the image may have been altered.
```

This proves that the signature system correctly detects any modification.

**Note:**

In a real-world private keys must never be stored in a public repository or shared openly.
They should always be securely stored, encrypted, and managed with strict access controls.

In this project, the private key (private_key.pem) is included only for educational purposes and to allow complete demonstration and testing of the digital signature creation and verification process.
