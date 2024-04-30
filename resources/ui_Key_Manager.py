from PyQt5 import QtWidgets, QtCore, QtGui

class KeyManagerUI(object):
    # 初始化密钥大小下拉菜单变量
    dropdown_KeySize = None

    def __init__(self):
        # 初始化组件变量
        self.backButton = None
        self.error_label = None
        self.dropdown_KeySize = None
        self.dropdown_ALG = None
        self.textbox_Email = None
        self.textbox_Username = None
        self.textbox_Password = None
        self.generate_key_button = None

    def setupUi(self, KeyManagerWindow):
        # 设置窗口属性
        KeyManagerWindow.setObjectName("KeyManagerWindow")
        KeyManagerWindow.resize(531, 531)
        KeyManagerWindow.setWindowTitle("密钥管理器")

        # 设置字体
        font = QtGui.QFont()
        font.setPointSize(12)

        # 用户名输入框
        self.textbox_Username = QtWidgets.QLineEdit(KeyManagerWindow)
        self.textbox_Username.setGeometry(200, 50, 200, 30)
        self.textbox_Username.setFont(font)

        # 邮箱输入框
        self.textbox_Email = QtWidgets.QLineEdit(KeyManagerWindow)
        self.textbox_Email.setGeometry(200, 100, 200, 30)
        self.textbox_Email.setFont(font)

        # 密钥算法下拉菜单
        self.dropdown_ALG = QtWidgets.QComboBox(KeyManagerWindow)
        self.dropdown_ALG.setGeometry(200, 150, 200, 30)
        self.dropdown_ALG.setFont(font)

        # 密钥大小下拉菜单
        self.dropdown_KeySize = QtWidgets.QComboBox(KeyManagerWindow)
        self.dropdown_KeySize.setGeometry(200, 200, 200, 30)
        self.dropdown_KeySize.setFont(font)

        # 密码输入框
        self.textbox_Password = QtWidgets.QLineEdit(KeyManagerWindow)
        self.textbox_Password.setGeometry(200, 250, 200, 30)
        self.textbox_Password.setEchoMode(QtWidgets.QLineEdit.Password)
        self.textbox_Password.setFont(font)

        # 生成密钥按钮
        self.generate_key_button = QtWidgets.QPushButton(KeyManagerWindow)
        self.generate_key_button.setGeometry(200, 300, 200, 30)
        self.generate_key_button.setText("生成密钥")
        self.generate_key_button.setFont(font)

        # 向下拉菜单中添加选项
        self.dropdown_ALG.addItems(["RSA", "DSA + ElGamal"])
        self.dropdown_KeySize.addItems(["1024", "2048"])

        # 设置标签
        username = QtWidgets.QLabel("用户名", KeyManagerWindow)
        username.setGeometry(20, 50, 150, 30)
        username.setFont(font)

        email = QtWidgets.QLabel("邮箱", KeyManagerWindow)
        email.setGeometry(20, 100, 150, 30)
        email.setFont(font)

        ALG = QtWidgets.QLabel("非对称密钥算法", KeyManagerWindow)
        ALG.setGeometry(20, 150, 150, 30)
        ALG.setFont(font)

        key_size = QtWidgets.QLabel("密钥大小", KeyManagerWindow)
        key_size.setGeometry(20, 200, 150, 30)
        key_size.setFont(font)

        password = QtWidgets.QLabel("密码", KeyManagerWindow)
        password.setGeometry(20, 250, 150, 30)
        password.setFont(font)

        # 错误信息标签
        self.error_label = QtWidgets.QLabel("", KeyManagerWindow)
        self.error_label.setGeometry(200, 350, 200, 30)
        self.error_label.setStyleSheet("color: red")
        self.error_label.setFont(font)

        # 取消按钮
        self.backButton = QtWidgets.QPushButton("取消", KeyManagerWindow)
        self.backButton.setGeometry(QtCore.QRect(350, 450, 150, 30))
        self.backButton.setStyleSheet("background-color: black; color: white;")
        self.backButton.setFont(font)

        # 连接生成密钥按钮的信号
        self.generate_key_button.clicked.connect(KeyManagerWindow.generate_key)


class KeyManagerWindow(QtWidgets.QDialog):
    def __init__(self):
        super().__init__()
        self.resize(600, 400)

        # 实例化 KeyManagerUI 并设置界面
        self.ui = KeyManagerUI()
        self.ui.setupUi(self)


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)

    # 设置应用字体
    font = QtGui.QFont()
    font.setPointSize(12)
    app.setFont(font)

    # 显示窗口并运行应用
    key_manager_window = KeyManagerWindow()
    key_manager_window.show()

    sys.exit(app.exec_())
