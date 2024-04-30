from PyQt5 import QtWidgets
from resources.ui_Key_RIngs import KeyRingsUI
from controllers.key_manager import KeyManagerWindow


class KeyRingWindow(QtWidgets.QDialog):
    def __init__(self):
        super().__init__()
        self.resize(531, 700)

        self.ui = KeyRingsUI()
        self.ui.setupUi(self)

        self.ui.generateKeyButton.clicked.connect(self.open_key_manager)
        self.ui.backButton.clicked.connect(self.goToMain)

    def open_key_manager(self):
        self.hide()
        key_manager_window = KeyManagerWindow()
        key_manager_window.exec_()

    def goToMain(self):
        from controllers.start_menu import StartMenu
        self.hide()
        start_menu = StartMenu()
        start_menu.exec_()
