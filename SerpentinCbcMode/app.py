import streamlit as st
import os

from serpent_cipher_cbc import SerpentCipherCBC, generate_random_hex_key
from serpent import hexstring2bitstring


def main():
    st.title("Secure Delivery Messages")
    st.markdown('''
    <p style='color: orange;'>
    Encr/Decr with Serpent in CBC mode<br>
    El-Gamal secret key delivery <br>
    ECDSA signature for a secure chat
    </p>
    ''', unsafe_allow_html=True)

    # Initialize hexKey, iv, and userKey if they don't exist in session state
    if 'hexKey' not in st.session_state:
        st.session_state.hexKey = generate_random_hex_key(64)  # 256-bit key

    if 'iv' not in st.session_state:
        st.session_state.iv = os.urandom(16)  # Generate a random IV

    if 'userKey' not in st.session_state:
        st.session_state.userKey = hexstring2bitstring(st.session_state.hexKey)

    st.text(f"Encryption Key: {st.session_state.hexKey}")
    st.text(f"Initialization Vector: {st.session_state.iv.hex()}")

    # Initialize the Serpent cipher with the user key
    serpent_cipher = SerpentCipherCBC(st.session_state.userKey)

    # Shared state for messages
    if 'messages' not in st.session_state:
        st.session_state.messages = {"alice": [], "bob": []}

    # Layout setup: Create two columns for Alice and Bob
    col1, col2 = st.columns(2)

    # Alice's interface on the left
    with col1:
        st.subheader("Alice")
        alice_message = st.text_input("Alice says:", key="alice_input")
        if st.button("Send Message as Alice"):
            if alice_message:
                encrypted_message = serpent_cipher.encrypt_cbc(alice_message, st.session_state.iv)
                # Append encrypted message to Alice's log
                st.session_state.messages["alice"].append(f"Encrypted: {encrypted_message}")
                # Decrypt and append the message to Bob's log
                decrypted_message = serpent_cipher.decrypt_cbc(encrypted_message, st.session_state.iv)
                st.session_state.messages["bob"].append(f"Decrypted: {decrypted_message}")
            else:
                st.warning("Alice, please enter a message to send.")
    # Bob's interface on the right
    with col2:
        st.subheader("Bob")
        bob_message = st.text_input("Bob says:", key="bob_input")
        if st.button("Send Message as Bob", key="send_bob"):
            if bob_message:
                encrypted_message = serpent_cipher.encrypt_cbc(bob_message, st.session_state.iv)
                # Append encrypted message to Bob's log
                st.session_state.messages["bob"].append(f"Encrypted: {encrypted_message}")
                # Decrypt and append the message to Alice's log
                decrypted_message = serpent_cipher.decrypt_cbc(encrypted_message, st.session_state.iv)
                st.session_state.messages["alice"].append(f"Decrypted: {decrypted_message}")
            else:
                st.warning("Bob, please enter a message to send.")

    # Display chat logs
    st.write("## Chat Log")
    with st.expander("Alice's Messages"):
        for msg in st.session_state.messages["alice"]:
            if "Decrypted" in msg:
                st.markdown(f"<p style='color: red;'>{msg}</p>", unsafe_allow_html=True)
            else:
                st.markdown(f"<p style='color: green;'>{msg}</p>", unsafe_allow_html=True)

    with st.expander("Bob's Messages"):
        for msg in st.session_state.messages["bob"]:
            if "Decrypted" in msg:
                st.markdown(f"<p style='color: red;'>{msg}</p>", unsafe_allow_html=True)
            else:
                st.markdown(f"<p style='color: green;'>{msg}</p>", unsafe_allow_html=True)


if __name__ == "__main__":
    main()
