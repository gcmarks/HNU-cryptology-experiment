import base64
import binascii
import hashlib
import json
import string
import re
import zlib

import rsa
from Crypto.Cipher import CAST, AES
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QFileDialog

from resources.ui_Deryption import DecryptorUI, PasswordDialog
from gmssl.sm4 import CryptSM4, SM4_DECRYPT

class DecryptorWindow(QtWidgets.QDialog):
    def __init__(self):
        super().__init__()
        self.data_dict = None
        self.ui = DecryptorUI()
        self.ui.setupUi(self)
        self.resize(531, 700)

        self.message = None

    def decrypt_verify_file(self):
        self.ui.disableWarning()
        self.ui.disable_widgets()
        try:
            with open(self.ui.file_path_input, 'r') as file:
                # is able to read RADIX64 and ONLY SIGNED data
                self.message = file.read()
                # print(self.message)
                # print(self.message)
                try:
                    data_dict = json.loads(self.message)
                except:
                    self.message = base64.b64decode(self.message)
                    try:
                        self.message = zlib.decompress(self.message)
                        data_dict = json.loads(self.message)
                    except:
                        data_dict = json.loads(self.message)

        except UnicodeDecodeError:
            with open(self.ui.file_path_input, 'rb') as file:
                self.message = file.read()
                #解压缩data和messageDigest数据段
                # print(self.message)
                self.message = zlib.decompress(self.message)
                data_dict = json.loads(self.message)
                # print("COMPRESSED: ", data_dict)
        except Exception:
            self.ui.enableWarning("文件被损坏")
            return



        if "sessionKey" in data_dict:
            # Message is encrypted
            keyID_recipien = data_dict["keyID_recipient"]
            with open('privateKeyRing.json', 'r') as file:
                privateKeyRing = json.load(file)
                for row, item in enumerate(privateKeyRing):
                    key = list(item.keys())[0]
                    values = item[key]
                    if key == keyID_recipien:
                        private_key = values.get('private_key', '')
            try:
                # print(data_dict)
                password_dialog = PasswordDialog()
                password_dialog.setupUI(keyID_recipien)
                password_dialog.exec_()
                private_key = self.decryptPrivateKey(private_key, password_dialog.textbox.text())
                if private_key is None:
                    self.ui.enableWarning("密码错误")
                    return
                else:
                    self.ui.disableWarning()
                private_key = rsa.PrivateKey.load_pkcs1(private_key)
                session_key = rsa.decrypt(bytes.fromhex(data_dict["sessionKey"]), private_key)

                msg = bytes.fromhex(data_dict["message"])
                # print(msg)
                if "nonce" in data_dict:
                    # print("tu")
                    cipher = AES.new(session_key, AES.MODE_EAX, nonce=bytes.fromhex(data_dict["nonce"]))
                    data_dict_bytes = cipher.decrypt(msg)
                    # print(data_dict_bytes)
                    # print(data_dict_bytes)
                    data_dict = json.loads(data_dict_bytes)
                    # print(data_dict)
                    self.ui.decryption_message_label.setText("加密算法为AES128\n" +
                                                             "解密成功\n解码消息为: " + keyID_recipien)
                    self.ui.enable_decrypt()

                elif "iv" in data_dict:
                    # Decrypt using SM4
                    crypt_sm4 = CryptSM4()
                    crypt_sm4.set_key(session_key, SM4_DECRYPT)
                    iv = bytes.fromhex(data_dict["iv"])

                    cipher = CryptSM4()
                    cipher.set_key(session_key, SM4_DECRYPT)
                    data_dict_bytes = cipher.crypt_cbc(iv, msg)
                    pad_len = data_dict_bytes[-1]
                    data_dict_bytes = data_dict_bytes[:-pad_len]
                    data_dict = json.loads(data_dict_bytes)
                    self.ui.decryption_message_label.setText("加密算法为SM4\n" +
                                                            "解密成功\n解码消息为: " + keyID_recipien)
                    self.ui.enable_decrypt()  
                    
                else:

                    eiv = msg[:CAST.block_size + 2]
                    ciphertext = msg[CAST.block_size + 2:]
                    cipher = CAST.new(session_key, CAST.MODE_OPENPGP, eiv)
                    data_dict_bytes = cipher.decrypt(ciphertext)

                    # print(data_dict_bytes)
                    data_dict = json.loads(data_dict_bytes)
                    self.ui.decryption_message_label.setText("加密算法为CAST5\n" +
                                                            "解密成功\n解码消息为: " + keyID_recipien)
                    self.ui.enable_decrypt()

            except Exception:
                self.ui.decryption_error_message_label.setText("解密失败\n消息被篡改")
                self.ui.enable_decrypt()
        
        
        if "messageDigest" in data_dict:
            # Message is signed
            # print(data_dict["keyID_sender"])
            public_key_ID = data_dict["keyID_sender"]
            with open('privateKeyRing.json', 'r') as file:
                publicKeyRing = json.load(file)
                for key, item in enumerate(publicKeyRing):
                    key = list(item.values())[0]
                    # print(public_key_ID)
                    if key['public_key_ID'] == public_key_ID:
                        public_key = key['public_key']

            try:
                public_key = rsa.PublicKey.load_pkcs1(public_key)
                data_bytes = data_dict["data"].encode('utf-8')
                # data_bytes = data_dict["data"]
                sha1_hash = hashlib.sha1()
                sha1_hash.update(data_bytes)
                data_hash = sha1_hash.digest()

                is_valid = rsa.verify(data_hash, bytes.fromhex(data_dict["messageDigest"]), public_key)
                self.ui.verification_message_label.setText(
                    "身份验证完成 \n验证者信息: " + key['username'] + " " +
                    key['email'] + "\n" + "签名时间为: " + data_dict["timestamp"])
                self.ui.enable_verify()
            except rsa.pkcs1.VerificationError:
                self.ui.verification_error_message_label.setText("身份验证失败\n消息被篡改")
                self.ui.enable_verify()
        self.data_dict = data_dict

        data_dict['data'] = base64.b64decode(data_dict['data'])
        #对data_dict['data']进行解压缩
        try:
            data_dict['data'] = zlib.decompress(data_dict['data'])
        except:
            pass


    def decryptPrivateKey(self, privateKey, password):
        # print(self.passwordCorrect(privateKey, password))
        privateKey = self.passwordCorrect(privateKey, password)
        return privateKey

    def passwordCorrect(self, private_key, password):
        password_bytes = password.encode('utf-8')
        sha1_hash = hashlib.sha1()
        sha1_hash.update(password_bytes)
        key = sha1_hash.digest()
        key = key[:16]

        msg = bytes.fromhex(private_key)

        try:
            eiv = msg[:CAST.block_size + 2]
            ciphertext = msg[CAST.block_size + 2:]
            cipher = CAST.new(key, CAST.MODE_OPENPGP, eiv)

            k = cipher.decrypt(ciphertext)

            kljuc = k.decode('utf-8')
            return kljuc
        except ValueError as e:
            return None

    def saveOriginalMess(self):
        file_path, _ = QFileDialog.getSaveFileName(None, "请选择文件","")
        # print("Selected File:", file_path)
        with open(file_path, 'wb') as file:
            file.write(self.data_dict["data"])
