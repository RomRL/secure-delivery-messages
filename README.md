
# Secure Messaging Application
![Secure Messaging App Interface](https://github.com/RomRL/secure-delivery-messages/blob/main/ScreenShot.png)

## Link To Deploy

[Secure Delivery Messages Application](https://secure-delivery-messages.onrender.com)

## Overview

This application offers a robust secure messaging service, utilizing advanced encryption and digital signature technologies to ensure the confidentiality, integrity, and authenticity of messages. It combines Serpent encryption in Cipher Block Chaining (CBC) mode, El-Gamal for secure key exchange, and Elliptic Curve Digital Signature Algorithm (ECDSA) for message signing.

## Features

- **Serpent Encryption**: A symmetric key block cipher that provides high levels of security. Used in CBC mode to ensure that each block of plaintext is XORed with the previous ciphertext block before being encrypted.
- **El-Gamal Key Exchange**: A secure method for exchanging cryptographic keys over a public channel. It's used to securely share the symmetric key needed for the Serpent encryption/decryption process.
- **ECDSA Signature**: Provides a mechanism for authenticating the origin and integrity of messages. Each message is signed using ECDSA to ensure that it has not been tampered with and to verify the sender's identity.

## Getting Started

### Prerequisites

- Python 3.9 or later


### Installation

Clone this repository to your local machine:

```bash
git clone https://github.com/RomRL/secure-delivery-messages.git
cd secure-messaging-app
```

Install the required dependencies:

```bash
pip install -r requirements.txt
```

### Configuration

Before running the application, you must generate key pairs for both El-Gamal and ECDSA. Follow the instructions in the `keys/README.md` file to generate and store your keys securely.

### Running the Application

To start the application, run:

```bash
streamlit run app.py
```

Follow the on-screen instructions to send and receive encrypted messages.

## Usage Example

1. **Alice sends a message to Bob**: Alice writes her message and the application encrypts it using Serpent with a key exchanged via El-Gamal. It then signs the message with Alice's ECDSA private key.
2. **Bob receives Alice's message**: Upon receiving the message, Bob's application verifies the signature using Alice's public key, decrypts the message using the symmetric key, and displays the original message.

