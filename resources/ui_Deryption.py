from PyQt5 import QtWidgets, QtGui
from PyQt5.QtWidgets import QFileDialog, QDialog, QVBoxLayout, QLabel, QLineEdit, QDialogButtonBox


class DecryptorUI(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.file_path_input = None
        self.setWindowTitle("解密器/验证器")  # 设置窗口标题
        self.resize(531, 700)  # 设置窗口大小

    def setupUi(self, DecryptorWindow):
        # 标签：“选择要解密/验证的文件”
        choose_file_label = QtWidgets.QLabel("选择要解密/验证的文件", DecryptorWindow)
        choose_file_label.setFont(QtGui.QFont("Arial", 16))
        choose_file_label.setGeometry(20, 20, 491, 30)

        # 分割线
        line = QtWidgets.QFrame(DecryptorWindow)
        line.setGeometry(20, 60, 491, 1)
        line.setFrameShape(QtWidgets.QFrame.HLine)
        line.setFrameShadow(QtWidgets.QFrame.Sunken)

        # 标签：“已选择的文件：”
        chosen_file_label = QtWidgets.QLabel("已选择的文件：", DecryptorWindow)
        chosen_file_label.setFont(QtGui.QFont("Arial", 12))
        chosen_file_label.setGeometry(20, 70, 100, 30)

        # 显示路径的标签
        self.file_path_label = QtWidgets.QLabel("", DecryptorWindow)
        self.file_path_label.setFont(QtGui.QFont("Arial", 10))
        self.file_path_label.setGeometry(130, 70, 381, 30)
        self.file_path_label.setWordWrap(True)

        # 选择文件的按钮
        self.choose_file_button = QtWidgets.QPushButton("选择文件", DecryptorWindow)
        self.choose_file_button.setFont(QtGui.QFont("Arial", 12))
        self.choose_file_button.setGeometry(20, 110, 120, 30)
        self.choose_file_button.clicked.connect(lambda: self.choose_file(DecryptorWindow))

        # “解密/验证”按钮
        self.decrypt_verify_button = QtWidgets.QPushButton("解密/验证", DecryptorWindow)
        self.decrypt_verify_button.setFont(QtGui.QFont("Arial", 12))
        self.decrypt_verify_button.setGeometry(140, 110, 120, 30)
        self.decrypt_verify_button.setEnabled(False)
        self.decrypt_verify_button.clicked.connect(lambda: self.decrypt_verify_file(DecryptorWindow))

        # 分割线
        line2 = QtWidgets.QFrame(DecryptorWindow)
        line2.setGeometry(20, 160, 491, 1)
        line2.setFrameShape(QtWidgets.QFrame.HLine)
        line2.setFrameShadow(QtWidgets.QFrame.Sunken)

        # 标签：“状态”
        status_label = QtWidgets.QLabel("状态", DecryptorWindow)
        status_label.setFont(QtGui.QFont("Arial", 16))
        status_label.setGeometry(20, 170, 491, 30)

        # 分割线
        line3 = QtWidgets.QFrame(DecryptorWindow)
        line3.setGeometry(20, 210, 491, 1)
        line3.setFrameShape(QtWidgets.QFrame.HLine)
        line3.setFrameShadow(QtWidgets.QFrame.Sunken)

        self.decryption_status_label = QtWidgets.QLabel("解密状态：", DecryptorWindow)
        self.decryption_status_label.setFont(QtGui.QFont("Arial", 12))
        self.decryption_status_label.setGeometry(20, 220, 491, 30)

        # 设置标签的调色板颜色
        # palette = self.decryption_status_label.palette()
        # palette.setColor(QtGui.QPalette.WindowText, QtGui.QColor(0, 0, 0, 128))
        # self.decryption_status_label.setPalette(palette)

        # 显示解密消息的标签
        self.decryption_message_label = QtWidgets.QLabel("", DecryptorWindow)
        self.decryption_message_label.setFont(QtGui.QFont("Arial", 10))
        self.decryption_message_label.setGeometry(20, 260, 491, 30)
        self.decryption_message_label.setWordWrap(True)
        self.decryption_message_label.setStyleSheet("color: green;")

        # 显示解密错误信息的标签
        self.decryption_error_message_label = QtWidgets.QLabel("", DecryptorWindow)
        self.decryption_error_message_label.setFont(QtGui.QFont("Arial", 10))
        self.decryption_error_message_label.setGeometry(20, 260, 491, 30)
        self.decryption_error_message_label.setWordWrap(True)
        self.decryption_error_message_label.setStyleSheet("color: red;")

        self.verification_status_label = QtWidgets.QLabel("验证状态：", DecryptorWindow)
        self.verification_status_label.setFont(QtGui.QFont("Arial", 12))
        self.verification_status_label.setGeometry(20, 320, 491, 30)

        # 设置调色板颜色
        # palette = self.decryption_status_label.palette()
        # palette.setColor(QtGui.QPalette.WindowText, QtGui.QColor(0, 0, 0, 128))
        # self.verification_status_label.setPalette(palette)

        # 显示验证消息的标签
        self.verification_message_label = QtWidgets.QLabel("", DecryptorWindow)
        self.verification_message_label.setFont(QtGui.QFont("Arial", 10))
        self.verification_message_label.setGeometry(20, 360, 491, 60)  # 增加高度到60
        self.verification_message_label.setWordWrap(True)
        self.verification_message_label.setStyleSheet("color: green;")

        # 显示验证错误信息的标签
        self.verification_error_message_label = QtWidgets.QLabel("", DecryptorWindow)
        self.verification_error_message_label.setFont(QtGui.QFont("Arial", 10))
        self.verification_error_message_label.setGeometry(20, 360, 491, 60)  # 增加高度到60
        self.verification_error_message_label.setWordWrap(True)
        self.verification_error_message_label.setStyleSheet("color: red;")

        # 保存原始文件的按钮
        self.save_original_button = QtWidgets.QPushButton("保存原文件", DecryptorWindow)
        self.save_original_button.setGeometry(20, 440, 120, 30)
        self.save_original_button.setFont(QtGui.QFont("Arial", 12))
        self.save_original_button.clicked.connect(lambda: self.save_original(DecryptorWindow))

        # 警告标签
        self.warning_label = QtWidgets.QLabel("", DecryptorWindow)
        self.warning_label.setGeometry(20, 480, 491, 30)
        self.warning_label.setFont(QtGui.QFont("Arial", 12))
        self.warning_label.setStyleSheet("background-color: rgb(255, 0, 0, 0);")

        # 返回按钮
        self.back_button = QtWidgets.QPushButton("返回", DecryptorWindow)
        self.back_button.setStyleSheet("background-color: black; color: white;")
        self.back_button.setFont(QtGui.QFont("Arial", 12))
        self.back_button.setGeometry(430, 520, 90, 30)

        self.back_button.clicked.connect(lambda: self.backtoStart(DecryptorWindow))

        # 初始时禁用部分控件
        self.disable_widgets()


    def backtoStart(self, DecryptorWindow):
        from controllers.start_menu import StartMenu
        DecryptorWindow.hide()
        startMenu = StartMenu()
        startMenu.exec_()

    def choose_file(self, DecryptorWindow):
        self.file_path_input, _ = QtWidgets.QFileDialog.getOpenFileName(DecryptorWindow, "选择文件")
        self.file_path_label.setText(self.file_path_input)

        if self.file_path_input:
            self.enable_widgets()

    def decrypt_verify_file(self, DecryptorWindow):
        DecryptorWindow.decrypt_verify_file()

    def save_original(self, DecryptorWindow):
        DecryptorWindow.saveOriginalMess()

    def enable_widgets(self):
        self.decrypt_verify_button.setEnabled(True)
        self.decryption_message_label.setText("")
        self.verification_message_label.setText("")

    def enable_verify(self):
        palette = self.decryption_status_label.palette()
        palette.setColor(QtGui.QPalette.WindowText, QtGui.QColor(0, 0, 0))
        self.verification_status_label.setPalette(palette)
        self.save_original_button.setEnabled(True)

    def enable_decrypt(self):
        palette = self.decryption_status_label.palette()
        palette.setColor(QtGui.QPalette.WindowText, QtGui.QColor(0, 0, 0))
        self.decryption_status_label.setPalette(palette)
        self.save_original_button.setEnabled(True)

    def disable_widgets(self):
        self.decrypt_verify_button.setEnabled(False)
        self.decryption_status_label.setStyleSheet("background-color: rgba(255, 255, 255, 0.5);")
        self.verification_status_label.setStyleSheet("background-color: rgba(255, 255, 255, 0.5);")
        self.save_original_button.setEnabled(False)

    def enableWarning(self, text):
        self.warning_label.setText(text)
        self.warning_label.setStyleSheet("background-color: rgb(255, 0, 0, 128);")

    def disableWarning(self):
        print("t")
        self.warning_label.setText("")
        self.warning_label.setStyleSheet("background-color: rgb(255, 0, 0, 0);")


class PasswordDialog(QDialog):
    def __init__(self):
        super().__init__()

    def setupUI(self, userID):
        self.setWindowTitle("私钥密码")
        self.layout = QVBoxLayout()
        self.label = QLabel("文件已被加密。请输入密码: " + userID)
        self.label.setFont(QtGui.QFont("Arial", 12))
        self.textbox = QLineEdit()
        self.button_box = QDialogButtonBox(QDialogButtonBox.Ok)
        self.button_box.accepted.connect(self.accept)
        self.errorlabel = QLabel("")
        self.errorlabel.setFont(QtGui.QFont("Arial", 12))
        self.errorlabel.setStyleSheet("color:red")

        self.layout.addWidget(self.label)
        self.layout.addWidget(self.textbox)
        self.layout.addWidget(self.button_box)
        self.layout.addWidget(self.errorlabel)
        self.setLayout(self.layout)
