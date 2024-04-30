from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtWidgets import QVBoxLayout, QLineEdit, QLabel
import csv

class IPWhiteListManagerUI(object):
    def __init__(self):
        super().__init__()
        # 初始化错误标签
        # self.errorLabelPrivate = None
        # self.errorLabelPublic = None
        # self.data = None
        # self.init_ui()

    def init_ui(self, IPWhiteListManagerWindow):

        self.selected_row = -1

        layout = QVBoxLayout()
        self.IPWhiteListManagerWindow = IPWhiteListManagerWindow
        self.IPWhiteListManagerWindow.load_data()

        IPWhiteListManagerWindow.setObjectName("IPWhiteListManagerWindow")
        IPWhiteListManagerWindow.resize(531, 700)
        IPWhiteListManagerWindow.setWindowTitle("IP白名单管理")

        self.backButton = QtWidgets.QPushButton("返回", IPWhiteListManagerWindow)
        self.backButton.setStyleSheet("background-color: black; color: white;")
        self.backButton.setFont(QtGui.QFont("Arial", 12))
        self.backButton.clicked.connect(lambda: self.back_to_file_transfer_menu(IPWhiteListManagerWindow))

        self.IPWhiteListLabel = QtWidgets.QLabel("ip白名单列表", IPWhiteListManagerWindow)
        self.IPWhiteListLabel.setFont(QtGui.QFont("Arial", 12))

        self.IPWhiteListTable = QtWidgets.QTableWidget(IPWhiteListManagerWindow)
        self.IPWhiteListTable.setColumnCount(2)
        self.IPWhiteListTable.setHorizontalHeaderLabels(["ip_start_from", "ip_end_on"])
        self.IPWhiteListTable.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.IPWhiteListTable.setVerticalScrollMode(QtWidgets.QAbstractItemView.ScrollPerPixel)
        self.IPWhiteListTable.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.IPWhiteListTable.itemClicked.connect(self.highlight_row)
        self.populate_table(self.IPWhiteListTable, self.IPWhiteListManagerWindow.ip_list)

        self.IPWhiteListAddButton = QtWidgets.QPushButton("添加", IPWhiteListManagerWindow)
        self.IPWhiteListAddButton.setFont(QtGui.QFont("Arial", 12))
        self.IPWhiteListDeleteButton = QtWidgets.QPushButton("删除", IPWhiteListManagerWindow)
        self.IPWhiteListDeleteButton.setFont(QtGui.QFont("Arial", 12))

        self.IPWhiteListAddButton.clicked.connect(self.add_ip_white_list)
        self.IPWhiteListDeleteButton.clicked.connect(self.IPWhiteListManagerWindow.delete_ip_white_list)

        self.new_ip_start_from_label = QLabel("新白名单最小ip")
        self.new_ip_start_from = QLineEdit()
        self.new_ip_end_on_label = QLabel("新白名单最大ip")
        self.new_ip_end_on = QLineEdit()

        layout.addWidget(self.IPWhiteListLabel)
        layout.addWidget(self.IPWhiteListTable)
        layout.addWidget(self.new_ip_start_from_label)
        layout.addWidget(self.new_ip_start_from)
        layout.addWidget(self.new_ip_end_on_label)
        layout.addWidget(self.new_ip_end_on)
        layout.addWidget(self.IPWhiteListAddButton)
        layout.addWidget(self.IPWhiteListDeleteButton)
        layout.addWidget(self.backButton)

        self.IPWhiteListManagerWindow.setLayout(layout)


    def populate_table(self, table, data):
        table.setRowCount(len(data))
        for row, item in enumerate(data):
            table.setItem(row, 0, QtWidgets.QTableWidgetItem(self.IPWhiteListManagerWindow.decimal_to_ip(item[0])))
            table.setItem(row, 1, QtWidgets.QTableWidgetItem(self.IPWhiteListManagerWindow.decimal_to_ip(item[1])))

    def highlight_row(self, item):
        row = item.row()
        table = item.tableWidget()
        table.selectRow(row)
        self.selected_row = row

    def add_ip_white_list(self):
        new_ip_start_from = self.IPWhiteListManagerWindow.ip_to_decimal(self.new_ip_start_from.text())
        new_ip_end_on = self.IPWhiteListManagerWindow.ip_to_decimal(self.new_ip_end_on.text())
        self.IPWhiteListManagerWindow.add_to_csv(new_ip_start_from, new_ip_end_on)

    def back_to_file_transfer_menu(self, IPWhiteListManagerWindow):
        from controllers.transfer import FileTransferWindow
        IPWhiteListManagerWindow.hide()
        file_transfer_menu = FileTransferWindow()
        file_transfer_menu.exec_()