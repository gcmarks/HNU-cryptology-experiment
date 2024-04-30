from PyQt5 import QtWidgets

from controllers.encryptor import EncryptWindow
from controllers.key_rings import KeyRingWindow
from controllers.decryptor import DecryptorWindow
from controllers.transfer import FileTransferWindow
from resources.ui_start_menu import Ui_Start_menu


class StartMenu(QtWidgets.QDialog):
    def __init__(self):
        super().__init__()

        self.ui = Ui_Start_menu()
        self.ui.setupUi(self)

        # Connect signals and slots
        self.ui.key_manager.clicked.connect(self.open_key_ring)
        self.ui.encryptor.clicked.connect(self.open_encryptor)
        self.ui.decryptor.clicked.connect(self.open_decryptor)
        self.ui.file_transfer.clicked.connect(self.open_file_transfer)

    def open_key_ring(self):
        self.hide()
        key_manager_window = KeyRingWindow()
        key_manager_window.exec_()

    def open_encryptor(self):
        self.hide()
        encryptor_window = EncryptWindow()
        encryptor_window.exec_()

    def open_decryptor(self):
        self.hide()
        decryptor_window = DecryptorWindow()
        decryptor_window.exec_()

    def open_file_transfer(self):
        self.hide()
        file_transfer_window = FileTransferWindow()
        file_transfer_window.exec_()

    