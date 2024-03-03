import random
import os
import streamlit as st
from ElGamal.el_gamal import decrypt_key, encrypt_key, generate_keypair, generate_prime
from SerpentinCbcMode.serpent import hexstring2bitstring
from SerpentinCbcMode.serpent_cipher_cbc import SerpentCipherCBC, generate_random_hex_key


def initialize_session_state():
    if 'p' not in st.session_state or 'g' not in st.session_state:
        st.session_state.p, st.session_state.g = generate_prime(512), random.randint(2, 512)


    if 'private_key_alice' not in st.session_state or 'public_key_alice' not in st.session_state:
        st.session_state.public_key_alice, st.session_state.private_key_alice = generate_keypair(st.session_state.p,
                                                                                                 st.session_state.g)

    if 'private_key_bob' not in st.session_state or 'public_key_bob' not in st.session_state:
        st.session_state.public_key_bob, st.session_state.private_key_bob = generate_keypair(st.session_state.p,
                                                                                             st.session_state.g)

    if 'iv' not in st.session_state:
        st.session_state.iv = os.urandom(16)

    if 'messages' not in st.session_state:
        st.session_state.messages = {"alice": ["ALICE"], "bob": ["BOB"]}


def main():
    st.set_page_config(page_title="Secure Delivery Messages", page_icon=":lock:")
    st.markdown('''
    <h1 style='color: yellow; text-align: center;'>Secure Delivery Messages</h1>
    <div style='display: flex; justify-content: center;'>
        <div style='text-align: left;'>
            <p style='color: cyan; font-size: 20px; margin: 0;font-weight: bold;'>This is a secure chat application that demonstrates the following:<br></p>
            <p style='color: white; font-size: 14px; margin: 0;font-weight: bold;'>Encryption and Decryption with Serpent in CBC mode<br>
            El-Gamal secret key delivery <br>
            ECDSA signature for a secure chat</p>
            <br><br>
    </div>
    ''', unsafe_allow_html=True)

    initialize_session_state()

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Alice")
        alice_interaction()

    with col2:
        st.subheader("Bob")
        bob_interaction()

    display_chat_logs()


def alice_interaction():
    alice_message = st.text_input("Alice says:", key="alice_input")
    if st.button("Send Message as Alice"):
        send_message(alice_message, 'alice')


def bob_interaction():
    bob_message = st.text_input("Bob says:", key="bob_input")
    if st.button("Send Message as Bob"):
        send_message(bob_message, 'bob')


def send_message(message, sender):
    if message:
        if sender == 'alice':
            st.session_state.public_key_alice, st.session_state.private_key_alice = generate_keypair(
                st.session_state.p, st.session_state.g)
            hexKey = generate_random_hex_key(64)
            key_to_transport = int(hexKey, 16)
            cipher_key = encrypt_key(key=key_to_transport, private_key=st.session_state.private_key_alice,
                                     public_key=st.session_state.public_key_bob)
            recipient = 'bob'
        else:
            st.session_state.public_key_bob, st.session_state.private_key_bob = generate_keypair(
                st.session_state.p, st.session_state.g)
            hexKey = generate_random_hex_key(64)
            key_to_transport = int(hexKey, 16)

            cipher_key = encrypt_key(key=key_to_transport, private_key=st.session_state.private_key_bob,
                                     public_key=st.session_state.public_key_alice)
            recipient = 'alice'

        decrypted_key = decrypt_key(cipher_key,
                                    private_key=st.session_state.private_key_bob if recipient == 'bob' else st.session_state.private_key_alice,
                                    public_key=st.session_state.public_key_bob if recipient == 'bob' else st.session_state.public_key_alice)
        with st.sidebar:
                st.markdown('## Key Information : ')
                st.write(f"### IV", unsafe_allow_html=True)
                st.write(f"<span style='color:orange'>{st.session_state.iv.hex()}</span>",unsafe_allow_html=True)
                st.write(f"### Original Key", unsafe_allow_html=True)
                st.write(f"<span style='color:yellow'>{hex(key_to_transport)[2:]}</span>",unsafe_allow_html=True)
                st.write(f"# {sender.upper()}")
                st.write(f"### Message Key:")
                st.write(f"- Encrypted Key (C1)",unsafe_allow_html=True)
                st.write(f"<span style='color:cyan'>{hex(cipher_key[0])[2:]}{hex(decrypted_key)[2:]}</span>",unsafe_allow_html=True)
                st.write(f"- Encrypted Key (C2)",unsafe_allow_html=True)
                st.write(f"<span style='color:cyan'>{hex(cipher_key[1])[2:]}{hex(decrypted_key)[2:]}</span>",unsafe_allow_html=True)
                st.write(f"# {recipient.upper()}")
                st.write(f"{recipient} Decrypted Key: <span style='color:yellow'>{hex(decrypted_key)[2:]}</span>",
                         unsafe_allow_html=True)


        serpent_cipher_encryption = SerpentCipherCBC(hexstring2bitstring(hexKey))
        encrypted_message = serpent_cipher_encryption.encrypt_cbc(message, st.session_state.iv)
        st.session_state.messages[sender].append(f"Encrypted: {encrypted_message}")

        serpent_cipher_decryption = SerpentCipherCBC(hexstring2bitstring(hex(decrypted_key)[2:]))
        decrypted_message = serpent_cipher_decryption.decrypt_cbc(encrypted_message, st.session_state.iv)
        st.session_state.messages[recipient].append(f"Decrypted: {decrypted_message}")
    else:
        st.warning(f"{sender.capitalize()}, please enter a message to send.")


def display_chat_logs():
    st.write("## Chat Log")
    for user in ['alice', 'bob']:
        with st.chat_message(f"user") if user == 'alice' else st.chat_message(f"assistant"):
            for msg in st.session_state.messages[user]:
                if 'ALICE' in msg or 'BOB' in msg:
                    st.markdown(f"<p style='color: yellow; font-size: 20px;font-weight: bold;'>{msg}</p>", unsafe_allow_html=True)
                    continue
                color = 'cyan' if 'Decrypted' in msg else 'red'
                st.markdown(f"<p style='color: {color};'>{msg}</p>", unsafe_allow_html=True)


if __name__ == "__main__":
    main()