import json
import os
from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtWidgets import QPushButton, QLabel, QCheckBox, QLineEdit, QComboBox, QRadioButton, QFileDialog


class EncryptorUI(object):

    def __init__(self):
        # 初始化时定义的一些变量，用于存储目录路径、私钥、公钥和文件路径
        self.directory_path_output = 'F:/PGPGUI_gcV1'
        self.dataPrivateKeys = None
        self.dataPublicKeys = None
        self.file_path_input = 'F:/PGPGUI_gcV1/tina.txt'

    def setupUi(self, EncryptorWindow):
        # 设置加密窗口
        self.EncryptorWindow = EncryptorWindow
        
        # 复选框 - 加密/签名
        self.checkbox_encrypt = QCheckBox("加密/签名", EncryptorWindow)
        self.checkbox_encrypt.setFont(QtGui.QFont("Arial", 12))
        self.checkbox_encrypt.move(20, 20)

        # 标签 - 加密算法
        self.label_algorithm = QLabel("加密算法：", EncryptorWindow)
        self.label_algorithm.setFont(QtGui.QFont("Arial", 12))
        self.label_algorithm.move(20, 60)

        # 单选按钮 - AES128 和 CAST5
        self.radio_button_triple_des = QRadioButton("AES128", EncryptorWindow)
        self.radio_button_triple_des.setFont(QtGui.QFont("Arial", 12))
        self.radio_button_triple_des.move(20, 90)
        self.radio_button_triple_des.setChecked(True)
        self.radio_button_triple_des.setEnabled(False)
        self.radio_button_cast5 = QRadioButton("CAST5", EncryptorWindow)
        self.radio_button_cast5.setFont(QtGui.QFont("Arial", 12))
        self.radio_button_cast5.move(20, 110)
        self.radio_button_cast5.setEnabled(False)  # 初始禁用

        self.radio_button_sm4 = QRadioButton("SM4", EncryptorWindow)
        self.radio_button_sm4.setFont(QtGui.QFont("Arial", 12))
        self.radio_button_sm4.move(200, 110)
        self.radio_button_sm4.setEnabled(False)  

        # 下拉菜单 - 公钥选择
        self.dropdown_public_key = QComboBox(EncryptorWindow)
        self.dropdown_public_key.setFont(QtGui.QFont("Arial", 12))
        self.dropdown_public_key.move(20, 150)
        with open('publicKeyRing.json', 'r') as file:
            self.dataPublicKeys = json.load(file)
            for item in self.dataPublicKeys:
                key = list(item.keys())[0]
                self.dropdown_public_key.addItem(key)
        self.dropdown_public_key.setEnabled(False)  # 初始禁用

        # 分隔线
        self.line1 = QLabel(EncryptorWindow)
        self.line1.setStyleSheet("background-color: black")
        self.line1.setGeometry(20, 190, 491, 2)

        # 复选框 - 签名
        self.checkbox_sign = QCheckBox("签名", EncryptorWindow)
        self.checkbox_sign.setFont(QtGui.QFont("Arial", 12))
        self.checkbox_sign.move(20, 200)

        # 下拉菜单 - 私钥选择
        self.dropdown_privateKey = QComboBox(EncryptorWindow)
        self.dropdown_privateKey.setFont(QtGui.QFont("Arial", 12))
        self.dropdown_privateKey.move(20, 240)
        with open('privateKeyRing.json', 'r') as file:
            self.dataPrivateKeys = json.load(file)
            for item in self.dataPrivateKeys:
                key = list(item.keys())[0]
                self.dropdown_privateKey.addItem(key)
        self.dropdown_privateKey.setEnabled(False)  # 初始禁用

        # 文本框 - 输入私钥密码
        self.textbox_password = QLineEdit(EncryptorWindow)
        self.textbox_password.setFont(QtGui.QFont("Arial", 12))
        self.textbox_password.move(20, 280)
        self.textbox_password.setPlaceholderText("请输入私钥密码")
        self.textbox_password.setEnabled(False)

        # 分隔线
        self.line2 = QLabel(EncryptorWindow)
        self.line2.setStyleSheet("background-color: black")
        self.line2.setGeometry(20, 320, 491, 2)

        # 复选框 - 压缩
        self.checkbox_compress = QCheckBox("压缩", EncryptorWindow)
        self.checkbox_compress.setFont(QtGui.QFont("Arial", 12))
        self.checkbox_compress.move(20, 330)

        # 分隔线
        self.line3 = QLabel(EncryptorWindow)
        self.line3.setStyleSheet("background-color: black")
        self.line3.setGeometry(20, 370, 491, 2)

        # 复选框 - Radix-64 转换
        self.checkbox_radix64 = QCheckBox("Base-64 转换", EncryptorWindow)
        self.checkbox_radix64.setFont(QtGui.QFont("Arial", 12))
        self.checkbox_radix64.move(20, 380)

        # 标签 - 选择要加密的文件
        self.label_choose_file = QLabel("选择要加密的文件：", EncryptorWindow)
        self.label_choose_file.setFont(QtGui.QFont("Arial", 12))
        self.label_choose_file.move(20, 430)

        # 按钮 - 选择文件
        self.button_choose_file_input = QPushButton("选择文件", EncryptorWindow)
        self.button_choose_file_input.setFont(QtGui.QFont("Arial", 12))
        self.button_choose_file_input.move(20, 460)

        # 标签 - 选择输出目录
        self.label_choose_directory = QLabel("选择输出目录：", EncryptorWindow)
        self.label_choose_directory.setFont(QtGui.QFont("Arial", 12))
        self.label_choose_directory.move(20, 500)

        # 按钮 - 选择文件
        self.button_choose_file_output = QPushButton("选择文件", EncryptorWindow)
        self.button_choose_file_output.setFont(QtGui.QFont("Arial", 12))
        self.button_choose_file_output.move(20, 530)

        # 按钮 - 加密
        self.encrypt_sign = QPushButton("加密", EncryptorWindow)
        self.encrypt_sign.setFont(QtGui.QFont("Arial", 12))
        self.encrypt_sign.move(20, 570)
        self.encrypt_sign.setEnabled(False)


        self.label_selected_file_input = QLabel("", EncryptorWindow)
        self.label_selected_file_input.setFont(QtGui.QFont("Arial", 12))
        self.label_selected_file_input.move(120, 460)
        self.label_selected_file_input.setFixedWidth(500)
        # self.label_selected_file_input.setStyleSheet("color: blue;")

        # 标签 - 已选择的输出目录
        self.label_selected_directory_output = QLabel("", EncryptorWindow)
        self.label_selected_directory_output.setFont(QtGui.QFont("Arial", 12))
        self.label_selected_directory_output.move(120, 530)
        self.label_selected_directory_output.setFixedWidth(500)
        # self.label_selected_directory_output.setStyleSheet("color: blue;")

        self.errorLabel = QLabel("", EncryptorWindow)
        self.errorLabel.setFont(QtGui.QFont("Arial", 12))
        self.errorLabel.setStyleSheet("color: red;")
        self.errorLabel.move(20, 600)
        self.errorLabel.setFixedWidth(500)

        self.successLabel = QLabel("", EncryptorWindow)
        self.successLabel.setFont(QtGui.QFont("Arial", 12))  # 增加字号至 16
        # self.successLabel.setStyleSheet("color: green;")
        self.successLabel.setGeometry(20, 600, 500, 100)  # 调整几何形状以设置所需的宽度和高度

        # 连接按钮信号
        self.button_choose_file_input.clicked.connect(lambda: self.choose_file_input(EncryptorWindow))
        self.button_choose_file_output.clicked.connect(lambda: self.choose_directory_output(EncryptorWindow))
        self.encrypt_sign.clicked.connect(self.checkInputEmpty)

        # 连接复选框信号
        self.checkbox_encrypt.stateChanged.connect(self.toggle_encrypt_options)
        self.checkbox_sign.stateChanged.connect(self.toggle_sign_options)

        self.checkbox_encrypt.stateChanged.connect(self.toggle_encrypt_decript_options)
        self.checkbox_sign.stateChanged.connect(self.toggle_encrypt_decript_options)

        # 返回按钮
        self.back_button = QtWidgets.QPushButton("返回", EncryptorWindow)
        self.back_button.setStyleSheet("background-color: black; color: white;")
        self.back_button.setFont(QtGui.QFont("Arial", 12))
        self.back_button.setGeometry(430, 640, 90, 30)

        self.back_button.clicked.connect(lambda: self.backtoStart(EncryptorWindow))

    # ssh连接到目标主机
    def connect(self):
        print("connect to the target machine")
    
    # 传输文件到目标主机
    def transfer(self):
        print("transfer file to the target machine")


    def backtoStart(self, EncryptorWindow):
        # 返回起始菜单
        from controllers.start_menu import StartMenu
        EncryptorWindow.hide()
        startMenu = StartMenu()
        startMenu.exec_()

    def toggle_encrypt_options(self, state):
        # 根据状态启用或禁用加密选项
        encrypt_enabled = state == QtCore.Qt.Checked
        self.radio_button_triple_des.setEnabled(encrypt_enabled)
        self.radio_button_cast5.setEnabled(encrypt_enabled)
        self.radio_button_sm4.setEnabled(encrypt_enabled)
        self.dropdown_public_key.setEnabled(encrypt_enabled)

    def toggle_sign_options(self, state):
        # 根据状态启用或禁用签名选项
        sign_enabled = state == QtCore.Qt.Checked
        self.textbox_password.setEnabled(sign_enabled)
        self.dropdown_privateKey.setEnabled(sign_enabled)

    def set_default_inoroutput(self):
        default_input_path = os.path.expanduser("F:/OpenPGP_Crypto_GUI/tina.txt")
        default_output_path = os.path.expanduser("F:/OpenPGP_Crypto_GUI")
        self.label_selected_file_input.setText(default_input_path)
        self.label_selected_file_output.setText(default_output_path)
        
    def choose_file_input(self, EncryptorWindow):
            # 选择输入文件
            file_dialog_input = QFileDialog(EncryptorWindow)
            self.file_path_input = file_dialog_input.getOpenFileName(EncryptorWindow, "选择文件")[0]
            self.label_selected_file_input.setText(self.file_path_input)

    def choose_directory_output(self, EncryptorWindow):
        # 选择输出目录
        file_dialog_output = QFileDialog(EncryptorWindow)
        self.directory_path_output = file_dialog_output.getExistingDirectory(EncryptorWindow, "选择目录")
        self.label_selected_directory_output.setText(self.directory_path_output)

    def toggle_encrypt_decript_options(self, state):
        # 根据状态启用或禁用加密按钮
        encrypt_enabled = state == QtCore.Qt.Checked
        self.encrypt_sign.setEnabled(encrypt_enabled)

    def checkInputEmpty(self):
        # 检查必要的输入是否为空
        if self.checkbox_sign.isChecked():
            if self.textbox_password.text() == "":
                self.errorLabel.setText("缺少私钥密码。")
                return

        if self.file_path_input is None:
            self.errorLabel.setText("缺少输入文件。")
            return

        if self.directory_path_output is None:
            self.errorLabel.setText("缺少输出目录。")
            return

        self.errorLabel.setText("")
        self.EncryptorWindow.getDataAndStartEncrypt()
