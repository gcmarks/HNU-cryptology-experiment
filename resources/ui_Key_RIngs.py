import hashlib
import json
import os
import rsa
from Crypto.Cipher import CAST
from Crypto import Random

from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QFileDialog, QVBoxLayout, QDialog, QLabel, QLineEdit, QPushButton, QHBoxLayout
from cryptography.hazmat.primitives import serialization


class KeyRingsUI(object):
    def __init__(self):
        # 初始化错误标签
        self.errorLabelPrivate = None
        self.errorLabelPublic = None
        self.data = None

    def setupUi(self, KeyRingWindow):
        # 设置窗口基本属性
        KeyRingWindow.setObjectName("KeyRingWindow")
        KeyRingWindow.resize(531, 700)
        KeyRingWindow.setWindowTitle("密钥环")

        # 返回按钮
        self.backButton = QtWidgets.QPushButton("返回", KeyRingWindow)
        self.backButton.setGeometry(QtCore.QRect(430, 640, 80, 30))
        self.backButton.setStyleSheet("background-color: black; color: white;")
        self.backButton.setFont(QtGui.QFont("Arial", 12))

        # 公钥标签
        self.publicKeyLabel = QtWidgets.QLabel("公钥环", KeyRingWindow)
        self.publicKeyLabel.setGeometry(QtCore.QRect(10, 10, 511, 30))
        self.publicKeyLabel.setAlignment(QtCore.Qt.AlignCenter)
        self.publicKeyLabel.setFont(QtGui.QFont("Arial", 12))

        # 公钥表格
        self.publicKeyTable = QtWidgets.QTableWidget(KeyRingWindow)
        self.publicKeyTable.setGeometry(QtCore.QRect(10, 50, 511, 200))
        self.publicKeyTable.setColumnCount(3)
        self.publicKeyTable.setHorizontalHeaderLabels(["用户名", "邮箱", "KeyID"])
        self.publicKeyTable.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.publicKeyTable.setVerticalScrollMode(QtWidgets.QAbstractItemView.ScrollPerPixel)
        self.publicKeyTable.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)

        # 公钥操作按钮
        self.publicKeyDeleteButton = QtWidgets.QPushButton("删除", KeyRingWindow)
        self.publicKeyDeleteButton.setGeometry(QtCore.QRect(10, 260, 80, 30))
        self.publicKeyDeleteButton.setFont(QtGui.QFont("Arial", 12))
        self.publicKeyExportButton = QtWidgets.QPushButton("导出", KeyRingWindow)
        self.publicKeyExportButton.setGeometry(QtCore.QRect(100, 260, 80, 30))
        self.publicKeyExportButton.setFont(QtGui.QFont("Arial", 12))
        self.publicKeyImportButton = QtWidgets.QPushButton("导入", KeyRingWindow)
        self.publicKeyImportButton.setGeometry(QtCore.QRect(190, 260, 80, 30))
        self.publicKeyImportButton.setFont(QtGui.QFont("Arial", 12))

        # 私钥标签
        self.privateKeyLabel = QtWidgets.QLabel("私钥环", KeyRingWindow)
        self.privateKeyLabel.setGeometry(QtCore.QRect(10, 290, 511, 30))
        self.privateKeyLabel.setAlignment(QtCore.Qt.AlignCenter)
        self.privateKeyLabel.setFont(QtGui.QFont("Arial", 12))

        # 私钥表格
        self.privateKeyTable = QtWidgets.QTableWidget(KeyRingWindow)
        self.privateKeyTable.setGeometry(QtCore.QRect(10, 330, 511, 200))
        self.privateKeyTable.setColumnCount(3)
        self.privateKeyTable.setHorizontalHeaderLabels(["用户名", "邮箱", "KeyID"])
        self.privateKeyTable.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.privateKeyTable.setVerticalScrollMode(QtWidgets.QAbstractItemView.ScrollPerPixel)
        self.privateKeyTable.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)

        # 私钥操作按钮
        self.privateKeyDeleteButton = QtWidgets.QPushButton("删除", KeyRingWindow)
        self.privateKeyDeleteButton.setGeometry(QtCore.QRect(10, 540, 80, 30))
        self.privateKeyDeleteButton.setFont(QtGui.QFont("Arial", 12))
        self.privateKeyExportButton = QtWidgets.QPushButton("导出", KeyRingWindow)
        self.privateKeyExportButton.setGeometry(QtCore.QRect(100, 540, 80, 30))
        self.privateKeyExportButton.setFont(QtGui.QFont("Arial", 12))
        self.privateKeyImportButton = QtWidgets.QPushButton("导入", KeyRingWindow)
        self.privateKeyImportButton.setGeometry(QtCore.QRect(190, 540, 80, 30))
        self.privateKeyImportButton.setFont(QtGui.QFont("Arial", 12))

        # 生成新密钥对按钮
        self.generateKeyButton = QtWidgets.QPushButton("生成新的密钥对", KeyRingWindow)
        self.generateKeyButton.setGeometry(QtCore.QRect(10, 590, 200, 30))
        self.generateKeyButton.setFont(QtGui.QFont("Arial", 12))

        # 连接按钮事件
        self.publicKeyExportButton.clicked.connect(lambda: self.export_key("public"))
        self.publicKeyDeleteButton.clicked.connect(lambda: self.delete_key("public"))
        self.publicKeyImportButton.clicked.connect(self.import_key_public)
        self.privateKeyExportButton.clicked.connect(lambda: self.export_key("private"))
        self.privateKeyDeleteButton.clicked.connect(lambda: self.delete_key("private"))
        self.privateKeyImportButton.clicked.connect(self.import_key_private)

        # 错误标签
        self.errorLabelPrivate = QtWidgets.QLabel("", KeyRingWindow)
        self.errorLabelPrivate.setGeometry(QtCore.QRect(50, 565, 300, 30))
        self.errorLabelPrivate.setStyleSheet("color: red;")
        self.errorLabelPrivate.setFont(QtGui.QFont("Arial", 12))

        self.errorLabelPublic = QtWidgets.QLabel("", KeyRingWindow)
        self.errorLabelPublic.setGeometry(QtCore.QRect(50, 565, 300, 30))
        self.errorLabelPublic.setStyleSheet("color: red;")
        self.errorLabelPublic.setFont(QtGui.QFont("Arial", 12))

        # 如果存在公钥文件，则加载数据
        if os.path.exists('publicKeyRing.json'):
            self.load_data()

    def load_data(self):

        with open('publicKeyRing.json', 'r') as file:
            self.data = json.load(file)

        public_key_data = self.data
        self.populate_table(self.publicKeyTable, public_key_data)

        with open('privateKeyRing.json', 'r') as file:
            self.data = json.load(file)

        private_key_data = self.data
        self.populate_table(self.privateKeyTable, private_key_data)

    def populate_table(self, table, data):
        table.setRowCount(len(data))
        for row, item in enumerate(data):
            key = list(item.keys())[0]
            values = item[key]

            username = values.get('username', '')
            email = values.get('email', '')
            key_id = values.get('public_key_ID', '')

            table.setItem(row, 0, QtWidgets.QTableWidgetItem(username))
            table.setItem(row, 1, QtWidgets.QTableWidgetItem(email))
            table.setItem(row, 2, QtWidgets.QTableWidgetItem(key_id))

        table.itemClicked.connect(self.highlight_row)

    def highlight_row(self, item):
        row = item.row()
        table = item.tableWidget()
        table.selectRow(row)

    def encodePrivateKey(self, private_key, password):

        password_bytes = password.encode('utf-8')

        sha1_hash = hashlib.sha1()
        sha1_hash.update(password_bytes)
        key = sha1_hash.digest()

        key = key[:16]
        print("key: ", key, "len: ", len(key))

        iv = Random.new().read(CAST.block_size)
        cipher = CAST.new(key, CAST.MODE_OPENPGP, iv)
        # private_key_pem = private_key.save_pkcs1().decode()
        # print(private_key)
        private_key_encrypted = cipher.encrypt(private_key)

        print("ENKODOVANA: ", private_key_encrypted)
        return private_key_encrypted.hex()

    def import_key_private(self):
        self.reset_errors()
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getOpenFileName(None, "Select PEM File", "", "PEM Files (*.pem)")

        if file_path:
            print("Selected file:", file_path)

            with open(file_path, "rb") as file:
                pem_data = file.read()
                print(pem_data)

                try:
                    private_key = serialization.load_pem_private_key(pem_data, password=None)
                    public_key = private_key.public_key()

                    n = public_key.public_numbers().n
                    e = public_key.public_numbers().e

                    public_key_original = rsa.key.PublicKey(n, e)
                except Exception:
                    self.errorLabelPrivate.setText("PRIVATE key not in right format.")
                    return
                self.errorLabelPrivate.setText("")
                print(public_key_original)

                keyId = (hex(n)[2:])[-16:]
                if self.keyAlreadyExists("private",keyId):
                    self.errorLabelPrivate.setText("Private key already exists.")
                    return

                dialog = ImportDialogPrivate()
                if dialog.exec_() == QDialog.Accepted:
                    username = dialog.username_line_edit.text()
                    email = dialog.email_line_edit.text()
                    password = dialog.email_line_edit.text()

                    userID = username + "[0x" + keyId[-8:] + "]"

                    key_pairs = {
                        userID: {
                            "username": username,
                            "email": email,
                            "public_key": public_key_original.save_pkcs1().decode(),
                            "private_key": self.encodePrivateKey(pem_data, password),
                            "public_key_ID": keyId
                        }
                    }
                    file_path = "privateKeyRing.json"

                    if os.path.exists(file_path):
                        with open(file_path, "r") as file:
                            existing_data = json.load(file)

                        existing_data.append(key_pairs)
                    else:
                        existing_data = [key_pairs]

                    with open(file_path, "w") as file:
                        json.dump(existing_data, file, indent=4)
                self.load_data()

    def import_key_public(self):

        self.reset_errors()
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getOpenFileName(None, "Select PEM File", "", "PEM Files (*.pem)")

        if file_path:
            print("Selected file:", file_path)

            with open(file_path, "rb") as file:
                pem_data = file.read()
            print(pem_data)
            try:
                public_key = serialization.load_pem_public_key(pem_data)

                n = public_key.public_numbers().n
                e = public_key.public_numbers().e

                public_key_original = rsa.key.PublicKey(n, e)
            except Exception:
                    self.errorLabelPublic.setText("PUBLIC key not in right format.")
                    return

            self.errorLabelPublic.setText("")

            keyId = (hex(n)[2:])[-16:]
            if self.keyAlreadyExists("public", keyId):
                self.errorLabelPrivate.setText("Public key already exists.")
                return
            print(keyId)

            dialog = ImportDialog()
            if dialog.exec_() == QDialog.Accepted:
                username = dialog.username_line_edit.text()
                email = dialog.email_line_edit.text()

                if not username or not email:
                    print("Please enter both username and email.")
                else:
                    userID = username + "[0x" + keyId[-8:] + "]"
                    key_pairs = {
                        userID: {
                            "username": username,
                            "email": email,
                            "public_key": public_key_original.save_pkcs1().decode(),
                            "public_key_ID": keyId
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
            self.load_data()
        else:
            print("File selection canceled.")

    def keyAlreadyExists(self,type,keyId):
        if type == "public":
            with open('publicKeyRing.json', 'r') as file:
                publicKeyRing = json.load(file)
                for key, item in enumerate(publicKeyRing):
                    key = list(item.values())[0]
                    print(keyId)
                    if key['public_key_ID'] == keyId:
                        return True
        else:
            with open('privateKeyRing.json', 'r') as file:
                privateKeyRing = json.load(file)
                for key, item in enumerate(privateKeyRing):
                    key = list(item.values())[0]
                    print(keyId)
                    if key['public_key_ID'] == keyId:
                        return True

    def reset_errors(self):
        self.errorLabelPublic.setText("")
        self.errorLabelPrivate.setText("")


    def passwordCorrect(self, private_key, password):

        self.reset_errors()
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
            return True
        except ValueError as e:
            return False

    def delete_key(self, keyType):

        self.reset_errors()
        if keyType == "public":
            table = self.publicKeyTable
        else:
            table = self.privateKeyTable

        selected_items = table.selectedItems()
        if selected_items:
            row = selected_items[0].row()
            username = table.item(row, 0).text()
            email = table.item(row, 1).text()
            key_id = table.item(row, 2).text()

            key_to_find = username + "[0x" + key_id[-8:] + "]"
            result = None

            if keyType == "public":
                with open('publicKeyRing.json', 'r') as file:
                    self.data = json.load(file)
                    for item in self.data:
                        if key_to_find in item:
                            self.data.remove(item)
                            break
            else:
                with open('privateKeyRing.json', 'r') as file:
                    self.data = json.load(file)
                private_key = None
                for item in self.data:
                    if key_to_find in item:
                        private_key = item[key_to_find]['private_key']
                        break
                dialog = PrivateKeyPassDialog()
                if dialog.exec_() == QDialog.Accepted:
                    password = dialog.password_line_edit.text()

                    if self.passwordCorrect(private_key, password):
                        for item in self.data:
                            if key_to_find in item:
                                self.data.remove(item)
                                break
                    else:
                        self.errorLabelPrivate.setText("Incorect password for: " + username)

        if keyType == "public":
            with open('publicKeyRing.json', "w") as file:
                json.dump(self.data, file, indent=4)
        else:
            with open('privateKeyRing.json', "w") as file:
                json.dump(self.data, file, indent=4)

        self.load_data()

    def fomHexToPam(self, hex_data, password):
        password_bytes = password.encode('utf-8')

        sha1_hash = hashlib.sha1()
        sha1_hash.update(password_bytes)
        key = sha1_hash.digest()
        key = key[:16]

        msg = bytes.fromhex(hex_data)

        try:
            eiv = msg[:CAST.block_size + 2]
            ciphertext = msg[CAST.block_size + 2:]
            cipher = CAST.new(key, CAST.MODE_OPENPGP, eiv)

            k = cipher.decrypt(ciphertext)

            kljuc = k.decode('utf-8')
            return kljuc
        except ValueError as e:
            return False

    def export_key(self, keyType):

        self.reset_errors()
        if keyType == "public":
            table = self.publicKeyTable
        else:
            table = self.privateKeyTable

        selected_items = table.selectedItems()
        if selected_items:
            row = selected_items[0].row()
            username = table.item(row, 0).text()
            email = table.item(row, 1).text()
            key_id = table.item(row, 2).text()

            key_to_find = username + "[0x" + key_id[-8:] + "]"
            result = None

            if keyType == "public":
                with open('publicKeyRing.json', 'r') as file:
                    self.data = json.load(file)
            else:
                with open('privateKeyRing.json', 'r') as file:
                    self.data = json.load(file)

            for item in self.data:
                if key_to_find in item:
                    result = item[key_to_find]
                    break

            if result is not None:
                if keyType == "public":
                    pem_data = result['public_key']
                else:
                    hex_data = result['private_key']
                    dialog = PrivateKeyPassDialog()
                    if dialog.exec_() == QDialog.Accepted:
                        password = dialog.password_line_edit.text()
                        if not self.passwordCorrect(hex_data, password):
                            self.errorLabelPrivate.setText("Incorect password for: " + username)
                            return
                        else:
                            pem_data = self.fomHexToPam(hex_data, password)

                self.errorLabelPrivate.setText("")
                file_dialog = QFileDialog()
                folder_path = file_dialog.getExistingDirectory(None, "Select Folder", "")

                if folder_path:
                    if keyType == "public":
                        file_path = os.path.join(folder_path, key_to_find + "PUBLIC.pem")
                    else:
                        file_path = os.path.join(folder_path, key_to_find + "PRIVATE.pem")
                    with open(file_path, "w") as file:
                        file.write(pem_data)

                    print("File saved:", file_path)
                else:
                    print("No folder selected.")

            else:
                print("Dictionary not found.")
        else:
            print("No row selected")


class ImportDialog(QDialog):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Import Key")
        self.username_label = QLabel("Username:")
        self.username_label.setFont(QFont("Arial", 12))
        self.username_line_edit = QLineEdit()
        self.username_line_edit.setFont(QFont("Arial", 12))
        self.email_label = QLabel("Email:")
        self.email_label.setFont(QFont("Arial", 12))
        self.email_line_edit = QLineEdit()
        self.email_line_edit.setFont(QFont("Arial", 12))
        self.import_button = QPushButton("Import")
        self.import_button.setFont(QFont("Arial", 12))
        self.error_label = QLabel()
        self.error_label.setStyleSheet("color: red")
        self.error_label.setFont(QFont("Arial", 12))

        layout = QVBoxLayout()
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_line_edit)
        layout.addWidget(self.email_label)
        layout.addWidget(self.email_line_edit)
        layout.addWidget(self.error_label)

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.import_button)
        layout.addLayout(button_layout)

        self.setLayout(layout)

        self.import_button.clicked.connect(self.import_button_clicked)

    def import_button_clicked(self):
        username = self.username_line_edit.text()
        email = self.email_line_edit.text()

        if not username or not email:
            self.error_label.setText("Please enter both username and email.")
        else:
            self.accept()


class PrivateKeyPassDialog(QDialog):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Export private key")
        self.password_label = QLabel("Password:")
        self.password_label.setFont(QtGui.QFont("Arial", 12))
        self.password_line_edit = QLineEdit()
        self.password_line_edit.setFont(QtGui.QFont("Arial", 12))
        self.export_button = QPushButton("Done")
        self.export_button.setFont(QtGui.QFont("Arial", 12))
        self.error_label = QLabel()
        self.error_label.setStyleSheet("color: red")
        self.error_label.setFont(QtGui.QFont("Arial", 12))

        layout = QVBoxLayout()
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_line_edit)
        layout.addWidget(self.error_label)

        button_layout = QHBoxLayout()
        layout.addWidget(self.export_button)
        layout.addLayout(button_layout)

        self.setLayout(layout)

        self.export_button.clicked.connect(self.export_button_clicked)

    def export_button_clicked(self):
        password = self.password_line_edit.text()

        self.accept()


class ImportDialogPrivate(QDialog):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Import Key")
        self.username_label = QLabel("Username:")
        self.username_label.setFont(QtGui.QFont("Arial", 12))
        self.username_line_edit = QLineEdit()
        self.username_line_edit.setFont(QtGui.QFont("Arial", 12))
        self.email_label = QLabel("Email:")
        self.email_label.setFont(QtGui.QFont("Arial", 12))
        self.email_line_edit = QLineEdit()
        self.email_line_edit.setFont(QtGui.QFont("Arial", 12))
        self.password_label = QLabel("Password:")
        self.password_label.setFont(QtGui.QFont("Arial", 12))
        self.password_line_edit = QLineEdit()
        self.password_line_edit.setFont(QtGui.QFont("Arial", 12))
        self.import_button = QPushButton("Import")
        self.import_button.setFont(QtGui.QFont("Arial", 12))
        self.error_label = QLabel()
        self.error_label.setStyleSheet("color: red")
        self.error_label.setFont(QtGui.QFont("Arial", 12))

        layout = QVBoxLayout()
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_line_edit)
        layout.addWidget(self.email_label)
        layout.addWidget(self.email_line_edit)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_line_edit)
        layout.addWidget(self.error_label)

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.import_button)
        layout.addLayout(button_layout)

        self.setLayout(layout)

        self.import_button.clicked.connect(self.import_private_button_clicked)

    def import_private_button_clicked(self):
        username = self.username_line_edit.text()
        email = self.email_line_edit.text()
        password = self.password_line_edit.text()

        if not username or not email or not password:
            self.error_label.setText("Please enter username, email and password.")
        else:
            self.accept()
