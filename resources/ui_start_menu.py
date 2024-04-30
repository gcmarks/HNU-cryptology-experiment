from PyQt5 import QtCore, QtGui, QtWidgets
# import qdarkstyle

class Ui_Start_menu(object):
    def setupUi(self, Start_menu):
        Start_menu.setObjectName("开始菜单")
        Start_menu.resize(531, 700)

        self.title_label = QtWidgets.QLabel(Start_menu)
        self.title_label.setGeometry(QtCore.QRect(0, 20, 531, 41))
        font = QtGui.QFont()
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.title_label.setFont(font)
        self.title_label.setAlignment(QtCore.Qt.AlignCenter)
        self.title_label.setObjectName("title_label")
        self.title_label.setText("密码实验")

        font.setPointSize(12)

        self.key_manager = QtWidgets.QPushButton(Start_menu)
        self.key_manager.setGeometry(QtCore.QRect(27, 80, 141, 321))
        self.key_manager.setObjectName("密钥管理器")
        self.key_manager.setFont(font)

        self.encryptor = QtWidgets.QPushButton(Start_menu)
        self.encryptor.setGeometry(QtCore.QRect(187, 80, 141, 321))
        self.encryptor.setObjectName("加密")
        self.encryptor.setFont(font)

        self.decryptor = QtWidgets.QPushButton(Start_menu)
        self.decryptor.setGeometry(QtCore.QRect(347, 80, 141, 321))
        self.decryptor.setObjectName("解密")
        self.decryptor.setFont(font)

        self.file_transfer = QtWidgets.QPushButton(Start_menu)
        self.file_transfer.setGeometry(QtCore.QRect(27, 480, 461, 160))
        self.file_transfer.setObjectName("文件发送和接收")
        self.file_transfer.setFont(font)

        self.retranslateUi(Start_menu)
        QtCore.QMetaObject.connectSlotsByName(Start_menu)

    def retranslateUi(self, Start_menu):
        _translate = QtCore.QCoreApplication.translate
        Start_menu.setWindowTitle(_translate("Start_menu", "python"))
        self.key_manager.setText(_translate("Start_menu", "密钥管理器"))
        self.encryptor.setText(_translate("Start_menu", "加密"))
        self.decryptor.setText(_translate("Start_menu", "解密"))
        self.file_transfer.setText(_translate("Start_menu", "文件发送和接收"))
    

    
if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    

    font = QtGui.QFont()
    font.setPointSize(12)
    app.setFont(font)
    # app.setStyleSheet(qdarkstyle.load_stylesheet_pyqt5())
    # app.setStyleSheet(qdarkstyle.load_stylesheet(qt_api='pyqt5'))
    start_menu = QtWidgets.QDialog()
    ui = Ui_Start_menu()
    ui.setupUi(start_menu)
    start_menu.show()

    sys.exit(app.exec_())
