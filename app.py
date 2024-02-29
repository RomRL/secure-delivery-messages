import streamlit as st
import os

from ElGamal.el_gamal import decrypt_key, encrypt_key, generate_keypair
from SerpentinCbcMode.serpent import hexstring2bitstring
from SerpentinCbcMode.serpent_cipher_cbc import SerpentCipherCBC, generate_random_hex_key


def main():
    st.set_page_config(page_title="Secure Delivery Messages", page_icon=":lock:")
    st.markdown('''
    <h1 style='color: yellow; text-align: center;'>Secure Delivery Messages</h1>
    <div style='display: flex; justify-content: center;'>
        <div style='text-align: left;'>
            <p style='color: cyan; font-size: 20px; margin: 0;'>This is a secure chat application that demonstrates the following:<br></p>
            <p style='color: white; font-size: 14px; margin: 0;'>Encryption and Decryption with Serpent in CBC mode<br>
            El-Gamal secret key delivery <br>
            ECDSA signature for a secure chat</p>
            <br>            <br>

    </div>
    ''', unsafe_allow_html=True)

    if 'public_key_alise' not in st.session_state and 'private_key_alise' not in st.session_state:
        st.session_state.public_key_alise, st.session_state.private_key_alise = generate_keypair()
    if 'public_key_bob' not in st.session_state and 'private_key_bob' not in st.session_state:
        st.session_state.public_key_bob, st.session_state.private_key_bob = generate_keypair()
    if 'flag' not in st.session_state:
        st.session_state.flag = True
    # Initialize hexKey, iv, and userKey if they don't exist in session state
    if 'hexKey' not in st.session_state:
        st.session_state.hexKey = generate_random_hex_key(64)  # 256-bit key
    st.text(f"Key: {st.session_state.hexKey}")
    # Encrypt the key using Bob's public key and store it in session state
    #                                                     KEY                                PUBLIC KEY BOB
    if 'cipher_key_alise' not in st.session_state:
        st.session_state.cipher_key_alise = encrypt_key(int(st.session_state.hexKey, 16),
                                                        st.session_state.public_key_bob)
    with st.expander("Encrypted key for Bob"):
        st.markdown(f"<p>C1=  {hex(st.session_state.cipher_key_alise[0])[2:]}</p>", unsafe_allow_html=True)
        st.markdown(f"<p>C2= {hex(st.session_state.cipher_key_alise[1])[2:]}</p>", unsafe_allow_html=True)

    decrypted_key_bob = st.session_state.decrypted_key_bob = decrypt_key(st.session_state.cipher_key_alise,
                                                                         st.session_state.private_key_bob,
                                                                         st.session_state.public_key_bob)

    with st.expander("Decrypted key for Bob"):
        st.markdown(f"<p>Decrypted key: {hex(decrypted_key_bob)[2:]}</p>", unsafe_allow_html=True)

    if 'iv' not in st.session_state:
        st.session_state.iv = os.urandom(16)  # Generate a random IV

    if 'userKey' not in st.session_state:
        st.session_state.userKey = hexstring2bitstring(hex(st.session_state.decrypted_key_bob)[2:])

    st.text(f"Initialization Vector: {st.session_state.iv.hex()}")

    # Initialize the Serpent cipher with the user key
    serpent_cipher = SerpentCipherCBC(st.session_state.userKey)

    # Shared state for messages
    if 'messages' not in st.session_state:
        st.session_state.messages = {"alice": [], "bob": []}


    # Layout setup: Create two columns for Alice and Bob
    col1, col2 = st.columns(2)
    public_key_bob = st.session_state.public_key_bob

    if st.session_state.flag:
        st.session_state.messages["alice"].append(
            f"Received Public Key Bob p = {hex(public_key_bob[0])[2:]}")
        st.session_state.messages["alice"].append(
            f"Received Public Key Bob g = {hex(public_key_bob[1])[2:]}")
        st.session_state.messages["alice"].append(
            f"Received Public Key Bob y = {hex(public_key_bob[2])[2:]}")
        st.session_state.messages["alice"].append(
            f"Sent To Bob Encrypted key: {st.session_state.cipher_key_alise[0]}")
        st.session_state.messages["bob"].append(f"Decrypted key: {hex(decrypted_key_bob)[2:]}")
        st.session_state.flag = False
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
            if msg.startswith("Encrypted"):
                st.markdown(f"<p style='color: red;'>{msg}</p>", unsafe_allow_html=True)
            if msg.startswith("Decrypted"):
                st.markdown(f"<p style='color: cyan;'>{msg}</p>", unsafe_allow_html=True)
            if msg.startswith("Received"):
                msg = msg.split("=")
                st.markdown(f"<p style='color: yellow;'>{msg[0]} </p><p style='color: white;'>{msg[1]}</p>",
                            unsafe_allow_html=True)



    with st.expander("Bob's Messages"):
        for msg in st.session_state.messages["bob"]:
            if "Decrypted" in msg and "Decrypted key" not in msg:
                st.markdown(f"<p style='color: cyan;'>{msg}</p>", unsafe_allow_html=True)
            if "Encrypted" in msg:
                st.markdown(f"<p style='color: red;'>{msg}</p>", unsafe_allow_html=True)
            if "Decrypted key" in msg:
                msg = msg.split(":")
                st.markdown(f"<p style='color: yellow;'>{msg[0]}</p><p style='color: white;'>{msg[1]}</p>",
                            unsafe_allow_html=True)


if __name__ == "__main__":
    main()
