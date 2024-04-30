import hashlib
from hmac import digest

from Crypto.Cipher import CAST
import rsa
import os
import json

from Crypto.PublicKey import DSA, ElGamal
from PyQt5 import QtWidgets
from Crypto import Random
from cryptography.hazmat.primitives import serialization

from resources.ui_Key_Manager import KeyManagerUI


class KeyManagerWindow(QtWidgets.QDialog):
    def __init__(self):
        super().__init__()
        self.resize(531, 700)

        self.ui = KeyManagerUI()
        self.ui.setupUi(self)

        self.ui.backButton.clicked.connect(self.goToRings)

    def goToRings(self):
        from controllers.key_rings import KeyRingWindow
        self.hide()
        keyRing = KeyRingWindow()
        keyRing.exec_()

    def generate_key(self):
        from controllers.key_rings import KeyRingWindow

        username_text = self.ui.textbox_Username.text()
        email_text = self.ui.textbox_Email.text()
        password = self.ui.textbox_Password.text()
        algorithm = self.ui.dropdown_ALG.currentText()
        key_size = self.ui.dropdown_KeySize.currentText()
        if not username_text:
            self.ui.error_label.setText("请输入姓名.")
            return
        else:
            self.ui.error_label.setText("")
            print("Username in KeyManagerWindow:", username_text)

        if not email_text:
            self.ui.error_label.setText("Please enter an email.")
            return
        else:
            self.ui.error_label.setText("")
            print("Email in KeyManagerWindow:", email_text)

        if not password:
            self.ui.error_label.setText("Please enter a password.")
            return
        else:
            self.ui.error_label.setText("")
            print("Password in KeyManagerWindow:", password)

        if algorithm == "RSA":
            self.generateKeys(int(key_size))
        else:
            self.generateKeys(int(key_size))

        print(algorithm)

        self.hide()
        key_manager_window = KeyRingWindow()
        key_manager_window.exec_()

    def StoreInPublicKeyRingElGAmal_DSA(self, public_key, keyID):
        print(keyID)

    def StoreInPublicKeyRing(self, public_key, keyID):
        userID = self.ui.textbox_Username.text() + "[0x" + keyID[-8:] + "]"

        key_pairs = {
            userID: {
                "username": self.ui.textbox_Username.text(),
                "email": self.ui.textbox_Email.text(),
                "public_key": public_key.save_pkcs1().decode(),
                "public_key_ID": keyID
            }
        }

        file_path = "publicKeyRing.json"

        if os.path.exists(file_path):

            with open(file_path, "r") as file:
                existing_data = json.load(file)

            existing_data.append(key_pairs)
        else:
            existing_data = [key_pairs]

        with open(file_path, "w") as file:
            json.dump(existing_data, file, indent=4)

    def encodePrivateKey(self, private_key, password):

        password_bytes = password.encode('utf-8')

        sha1_hash = hashlib.sha1()
        sha1_hash.update(password_bytes)
        key = sha1_hash.digest()

        key = key[:16]
        print("key: ", key, "len: ", len(key))

        iv = Random.new().read(CAST.block_size)
        cipher = CAST.new(key, CAST.MODE_OPENPGP, iv)
        private_key_pem = private_key.save_pkcs1().decode()

        private_key_bytes = private_key_pem.encode('utf-8')
        private_key_encrypted = cipher.encrypt(private_key_bytes)

        print("ENKODOVANA: ", private_key_encrypted)
        return private_key_encrypted.hex()

        # try:
        #     eiv = private_key_encrypted[:CAST.block_size + 2]
        #     ciphertext = private_key_encrypted[CAST.block_size + 2:]
        #     cipher = CAST.new(key, CAST.MODE_OPENPGP, eiv)
        #
        #     k = cipher.decrypt(ciphertext)
        #     print("ORIGINAL: ", private_key_pem)
        #     print("DECRYPTED: ", k)
        #
        #     kljuc = k.decode('utf-8')
        #     print("kljuc: ", kljuc)
        # except ValueError as e:
        #     print("Invalid password:", e)

    def StoreInPrivateKeyRing(self, public_key, private_key, keyID):

        userID = self.ui.textbox_Username.text() + "[0x" + keyID[-8:] + "]"
        password = self.ui.textbox_Password.text()

        key_pairs = {
            userID: {
                "username": self.ui.textbox_Username.text(),
                "email": self.ui.textbox_Email.text(),
                "public_key": public_key.save_pkcs1().decode(),
                "private_key": self.encodePrivateKey(private_key, password),
                "public_key_ID": keyID
            }
        }

        file_path = "privateKeyRing.json"

        if os.path.exists(file_path):
            # File exists, read the existing JSON data
            with open(file_path, "r") as file:
                existing_data = json.load(file)

            # Append the new key_pairs dictionary to the existing data
            existing_data.append(key_pairs)
        else:
            existing_data = [key_pairs]

        # Write the updated JSON data back to the file
        with open(file_path, "w") as file:
            json.dump(existing_data, file, indent=4)

    def usernameALreadyExists(self, username, type):
        if type == "public":
            with open('publicKeyRing.json', 'r') as file:
                publicKeyRing = json.load(file)
                for key, item in enumerate(publicKeyRing):
                    key = list(item.values())[0]
                    if key['username'] == username:
                        return True
        if type == "private":
            with open('privateKeyRing.json', 'r') as file:
                publicKeyRing = json.load(file)
                for key, item in enumerate(publicKeyRing):
                    key = list(item.values())[0]
                    if key['username'] == username:
                        return True

    def generateKeys(self, key_size):
        if self.ui.dropdown_ALG.currentText() == "RSA":
            print("key_size:", key_size)
            public_key, private_key = rsa.newkeys(key_size)

            # Get the keyID
            keytoHex = public_key.n

            # Convert the modulus to hexadecimal string
            keyID = (hex(keytoHex)[2:])[-16:]

            print("keyID: ", keyID)
            self.StoreInPublicKeyRing(public_key, keyID)
            self.StoreInPrivateKeyRing(public_key, private_key, keyID)
        else:
            key = DSA.generate(key_size)

            # Get the private and public keys
            private_keyDSA = key.export_key()
            public_keyDSA = key.publickey().export_key()
            print("tu1:")
            key = ElGamal.generate(1024, Random.new().read)
            print("tu2: ",key)
            print("private_key:", key.has_private())
            print("public_key: y", key.publickey())
            private_key_pem = key.export_key()
            print("tu2:")
            private_key = ElGamal.import_key(private_key_pem)
            public_key = private_key.publickey()
            y = public_key.y
            g = public_key.g
            p = public_key.p
            print("private_key:", private_key)
            print("public_key: y =", y, ", g =", g, ", p =", p)

            # keyID = (hex(public_key)[2:])[-16:]
            # self.StoreInPublicKeyRingElGAmal_DSA(public_key,keyID)

        # Print the keys
        print("Public key:")
        print(public_key)
        print("\nPrivate key:")
        print(private_key)

        # private_keyKK = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
        # print(private_keyKK)
        # private_numbers = private_keyKK.private_numbers().d
        # d = private_keyKK.private_numbers().d
        # p = private_keyKK.private_numbers().p
        # q = private_keyKK.private_numbers().q
        # dp = private_keyKK.private_numbers().dmp1
        # dq = private_keyKK.private_numbers().dmq1
        # qi = private_keyKK.private_numbers().iqmp
        #
        # private_key_rsa = rsa.key.PrivateKey(
        #     n=None,  # Not needed for private key
        #     e=None,  # Not needed for private key
        #     d=d,
        #     p=p,
        #     q=q,
        #     dp=dp,
        #     dq=dq,
        #     qi=qi
        # )
        # print(private_key_rsa)

        # try:
        #     eiv = msg[:CAST.block_size + 2]
        #     ciphertext = msg[CAST.block_size + 2:]
        #     cipher = CAST.new(password_bytes1, CAST.MODE_OPENPGP, eiv)
        #
        #     k = cipher.decrypt(ciphertext)
        #     print("ORIGINAL: ", private_key_pem)
        #     print("DECRYPTED: ", k)
        #
        #     kljuc = k.decode('utf-8')
        #     print("kljuc: ", kljuc)
        # except ValueError as e:
        #     print("Invalid password:", e)
