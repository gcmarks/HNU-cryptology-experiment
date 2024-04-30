import base64
import binascii
import hashlib
import json
import os
import zlib
import base64

import rsa
from Crypto.Cipher import CAST, DES3, AES
from Crypto.Random import get_random_bytes
from PyQt5 import QtWidgets
from resources.ui_Encrypton import EncryptorUI
from datetime import datetime
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT


class EncryptWindow(QtWidgets.QDialog):
    def __init__(self):
        super().__init__()
        self.ui = EncryptorUI()  # 创建加密器用户界面实例
        self.ui.setupUi(self)  # 初始化用户界面
        self.resize(531, 700)  # 设置窗口大小

        # 初始化消息签名和加密字典
        self.message_sign = {}
        self.message_encrypt = {}
        self.message_sign_bytes = None
        self.message_sign_radix64 = None

        # 初始化会话密钥和接收者密钥ID
        self.sessionKey = None
        self.keyID_recipient = None

        # 初始化加密和签名状态标志
        self.isSigned = None
        self.isEncrypted = None
        self.isZipped = False
        self.isRadix64 = False
        self.encryptAlgorithm = None
        self.publicKeyEncrypt = None
        self.privateKeySign = None
        self.privateKeyPassword = None

        self.file_output_directory = None  # 输出文件目录

    def getDataAndStartEncrypt(self):
        # 检查是否选择加密和签名
        self.isEncrypted = self.ui.checkbox_encrypt.isChecked()
        self.isSigned = self.ui.checkbox_sign.isChecked()
        self.privateKeySign = self.ui.dropdown_privateKey.currentText()
        self.privateKeyPassword = self.ui.textbox_password.text()
        self.isZipped = self.ui.checkbox_compress.isChecked()
        self.isRadix64 = self.ui.checkbox_radix64.isChecked()

        self.file_output_directory = self.ui.directory_path_output

        # 读取文件路径输入并处理文件
        if self.ui.file_path_input is None:
            print("文件路径为空")
        else:
            with open(self.ui.file_path_input, "rb") as file:
                #对file进行压缩
                if self.isZipped:
                    self.message_sign["data"] = zlib.compress(file.read())
                    self.message_sign["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                else:
                    self.message_sign["data"] = file.read()
                    self.message_sign["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if 'data' in self.message_sign and isinstance(self.message_sign['data'], bytes):
            self.message_sign['data'] = base64.b64encode(self.message_sign['data']).decode('utf-8')

        # 签名处理代码
        if self.isSigned:
            data_bytes = self.message_sign["data"].encode('utf-8')
            sha1_hash = hashlib.sha1()
            sha1_hash.update(data_bytes)
            data_hash = sha1_hash.digest()

            for key, item in enumerate(self.ui.dataPrivateKeys): # 遍历私钥列表
                key = list(item.keys())[0] # 获取私钥ID
                if key == self.privateKeySign:# 如果私钥ID与选择的私钥ID相同
                    value = item[key]# 获取私钥信息
                    private_key = value['private_key']# 获取私钥
                    self.message_sign["keyID_sender"] = value['public_key_ID']# 设置发送者公钥ID
                    pam_key = self.passwordCorrect(private_key, self.privateKeyPassword)# 解密私钥
                    if pam_key is not None:# 如果解密成功
                        private_key_original = rsa.PrivateKey.load_pkcs1(pam_key)# 加载私钥
                        signature = rsa.sign(data_hash, private_key_original, 'SHA-1')# 使用私钥对数据进行签名
                        self.message_sign["messageDigest"] = signature.hex()# 设置签名

                        message_sign_json = json.dumps(self.message_sign)# 将签名信息转换为json格式
                        message_sign_bytes = message_sign_json.encode('utf-8')# 将json格式的签名信息转换为字节
                        self.message_sign_bytes = message_sign_bytes# 设置签名信息字节
                        # print(self.message_sign_bytes)
                        self.ui.successLabel.setText("数据成功签名。")
                    else:
                        self.ui.errorLabel.setText("私钥密码错误")
                        return
        else:
            message_sign_json = json.dumps(self.message_sign)
            message_sign_bytes = message_sign_json.encode('utf-8')
            self.message_sign_bytes = message_sign_bytes

        file_name = os.path.basename(self.ui.file_path_input)
        self.file_output_directory = os.path.join(self.file_output_directory, file_name + ".sgn")



        # 加密处理代码
        if self.isEncrypted:
            if self.ui.radio_button_cast5.isChecked():
                key = get_random_bytes(16)
                cipher = CAST.new(key, CAST.MODE_OPENPGP)
                plaintext = self.message_sign_bytes
                msg = cipher.encrypt(plaintext)
                # print("CAST: ", msg)

                self.message_encrypt["message"] = msg.hex()
                self.message_encrypt["sessionKey"] = self.encryptSessionKey(key).hex()
                self.message_encrypt["keyID_recipient"] = self.ui.dropdown_public_key.currentText()

                # print(self.message_encrypt)
                message_sign_json = json.dumps(self.message_encrypt)
                self.message_sign_bytes = message_sign_json.encode('utf-8')
                self.ui.successLabel.setText(self.ui.successLabel.text() + "\n" + "数据使用CAST5成功加密")
            if self.ui.radio_button_sm4.isChecked():  # 假设这里有一个SM4的单选按钮
                key = get_random_bytes(16)  # SM4使用128位（16字节）密钥
                iv = get_random_bytes(16)  # 生成随机的16字节IV
                crypt_sm4 = CryptSM4()
                crypt_sm4.set_key(key, SM4_ENCRYPT)

                plaintext = self.message_sign_bytes
                
                # print("SM4: ", msg)
                pad_len = 16 - len(plaintext) % 16
                padded_plaintext = plaintext + bytes([pad_len] * pad_len)

                ciphertext = crypt_sm4.crypt_cbc(iv, padded_plaintext)
                self.message_encrypt["message"] = ciphertext.hex()
                self.message_encrypt["sessionKey"] = self.encryptSessionKey(key).hex()
                self.message_encrypt["keyID_recipient"] = self.ui.dropdown_public_key.currentText()
                self.message_encrypt["iv"] = iv.hex()

                # print(self.message_encrypt)
                message_sign_json = json.dumps(self.message_encrypt)
                self.message_sign_bytes = message_sign_json.encode('utf-8')
                self.ui.successLabel.setText(self.ui.successLabel.text() + "\n" + "数据使用SM4成功加密")
            else:
                key = get_random_bytes(32)
                cipher = AES.new(key, AES.MODE_EAX)
                nonce = cipher.nonce
                ciphertext, tag = cipher.encrypt_and_digest(self.message_sign_bytes)
                # print("消息为密文:", ciphertext)

                self.message_encrypt["message"] = ciphertext.hex()
                self.message_encrypt["sessionKey"] = self.encryptSessionKey(key).hex()
                self.message_encrypt["keyID_recipient"] = self.ui.dropdown_public_key.currentText()
                self.message_encrypt["nonce"] = nonce.hex()
                # print(self.message_encrypt)

                message_sign_json = json.dumps(self.message_encrypt)
                self.message_sign_bytes = message_sign_json.encode('utf-8')
                self.ui.successLabel.setText(self.ui.successLabel.text() + "\n" + "数据使用AES128成功加密")

        # 压缩和Radix64编码处理
        # if self.isZipped:
        #     self.message_sign_bytes = zlib.compress(self.message_sign_bytes)
        #     self.ui.successLabel.setText(self.ui.successLabel.text() + "\n" + "数据成功压缩")

        if self.isRadix64:
            message_sign_radix64_encode = base64.b64encode(self.message_sign_bytes)
            self.message_sign_radix64 = message_sign_radix64_encode.decode('utf-8')
            self.ui.successLabel.setText(self.ui.successLabel.text() + "\n" + "数据成功转换为Basex64")
            with open(self.file_output_directory, "w") as file:
                file.write(self.message_sign_radix64)
                self.ui.successLabel.setText(
                    self.ui.successLabel.text() + "\n" + "文件写入:" + self.file_output_directory)
        else:
            with open(self.file_output_directory, "wb") as file:
                file.write(self.message_sign_bytes)
                self.ui.successLabel.setText(
                    self.ui.successLabel.text() + "\n" + "文件写入:" + self.file_output_directory)

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

    def encryptSessionKey(self, sessionKey):
        keyID_recipient = self.ui.dropdown_public_key.currentText()
        with open('publicKeyRing.json', 'r') as file:
            publicKeyRing = json.load(file)
            for item in publicKeyRing:
                if keyID_recipient in item:
                    public_key_pem = item[keyID_recipient]["public_key"]
        public_key = rsa.PublicKey.load_pkcs1(public_key_pem)
        data = sessionKey
        encrypted_sessionKey = rsa.encrypt(data, public_key)
        return encrypted_sessionKey
