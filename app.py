import streamlit as st
import os
from ElGamal.el_gamal import decrypt_key, encrypt_key, generate_keypair
from SerpentinCbcMode.serpent import hexstring2bitstring
from SerpentinCbcMode.serpent_cipher_cbc import SerpentCipherCBC, generate_random_hex_key


def setup_page():
    """Configure Streamlit page settings and display the header."""
    st.set_page_config(page_title="Secure Delivery Messages", page_icon=":lock:")
    st.markdown('''
    <h1 style='color: yellow; text-align: center;'>Secure Delivery Messages</h1>
    <div style='text-align: left;'>
        <p style='color: cyan; font-size: 20px;'>This is a secure chat application that demonstrates the following:</p>
        <p style='color: white; font-size: 14px;'> Encryption and Decryption with Serpent in CBC mode<br>
         El-Gamal secret key delivery <br>
         ECDSA signature for a secure chat</p>
    </div>
    ''', unsafe_allow_html=True)


def initialize_keys():
    print("Initializing keys")
    """Initialize cryptographic keys and session states."""
    # Key pair generation for Alice and Bob
    for user in ['alise', 'bob']:
        public_key, private_key = 'public_key_' + user, 'private_key_' + user
        if public_key not in st.session_state:
            st.session_state[public_key], st.session_state[private_key] = generate_keypair()
            print(f"public_key_{user}: {st.session_state[public_key]}")

    # Initialization of hexKey and iv for encryption
    st.session_state['hexKey'] = generate_random_hex_key(64)  # 256-bit key
    st.text(f"Key: {st.session_state.hexKey}")
    # Encrypt the hexKey with Bob's public key
    # st.session_state['cipher_key_alise'] = encrypt_key(int(st.session_state.hexKey, 16),
    #                                                    st.session_state['public_key_bob'])

    if 'iv' not in st.session_state:
        st.session_state['iv'] = os.urandom(16)  # Generate a random IV


def display_encryption_details():
    """Display the encryption details including encrypted and decrypted keys."""
    with st.expander("Encrypted key for Bob"):
        st.markdown(f"<p>C1= {hex(st.session_state.cipher_key_alise[0])[2:]}</p>", unsafe_allow_html=True)
        st.markdown(f"<p>C2= {hex(st.session_state.cipher_key_alise[1])[2:]}</p>", unsafe_allow_html=True)

    decrypted_key = decrypt_key(st.session_state.cipher_key_alise, st.session_state.private_key_bob,
                                st.session_state.public_key_bob)
    st.session_state.decrypted_key_bob = decrypted_key

    with st.expander("Decrypted key for Bob"):
        st.markdown(f"<p>Decrypted key: {hex(decrypted_key)[2:]}</p>", unsafe_allow_html=True)

    st.text(f"Initialization Vector: {st.session_state.iv.hex()}")

    # Convert decrypted key to bitstring for Serpent cipher use
    if 'userKey' not in st.session_state:
        st.session_state.userKey = hexstring2bitstring(hex(decrypted_key)[2:])

    return SerpentCipherCBC(st.session_state.userKey)


def handle_messages(serpent_cipher):
    """Handle sending and displaying messages between Alice and Bob."""
    if 'messages' not in st.session_state:
        st.session_state.messages = {"alice": [], "bob": []}

    col1, col2 = st.columns(2)

    with col1:
        user_interface("Alice", serpent_cipher)

    with col2:
        user_interface("Bob", serpent_cipher)

    display_chat_logs()


def user_interface(user, serpent_cipher):
    """User interface for sending and displaying messages."""
    st.subheader(user)
    message = st.text_input(f"{user} says:", key=f"{user.lower()}_input")
    if st.button(f"Send Message as {user}", key=f"send_{user.lower()}"):
        send_message(user.lower(), message, serpent_cipher)


def send_message(user, message, serpent_cipher):
    """Encrypt and append messages to the chat log."""
    if message:
        encrypted_message = serpent_cipher.encrypt_cbc(message, st.session_state.iv)
        st.session_state.messages[user].append(f"Encrypted: {encrypted_message}")
        decrypted_message = serpent_cipher.decrypt_cbc(encrypted_message, st.session_state.iv)
        recipient = "bob" if user == "alice" else "alice"
        st.session_state.messages[recipient].append(f"Decrypted: {decrypted_message}")
    else:
        st.warning(f"{user.capitalize()}, please enter a message to send.")


def display_chat_logs():
    """Display the chat logs for Alice and Bob."""
    st.write("## Chat Log")
    for user in ["Alice's Messages", "Bob's Messages"]:
        with st.expander(user):
            for msg in st.session_state.messages[user.split("'")[0].lower()]:
                color = 'red' if "Encrypted" in msg else 'cyan'
                st.markdown(f"<p style='color: {color};'>{msg}</p>", unsafe_allow_html=True)


def main():
    setup_page()
    initialize_keys()
    serpent_cipher = display_encryption_details()
    handle_messages(serpent_cipher)


if __name__ == "__main__":
    main()
