from PyQt5.QtWidgets import QVBoxLayout, QLabel, QPushButton, QFileDialog, QLineEdit, QProgressBar, QHBoxLayout, QFrame, QComboBox
import json

class FileTransferUI(object):
    def __int__(self):
        super().__init__()
        # self.init_ui()

    def init_ui(self, FileTransferWindow):

        self.FileTransferWindow = FileTransferWindow
        self.FileTransferWindow.setObjectName("传输菜单")
        # 创建平铺图
        layout = QVBoxLayout()

        self.send_file_path = None
        self.dst_ip = None
        self.dst_port = None
        self.dst_directory = None
        # self.dst_file_name = None

        # 设置传输模式的部件
        self.file_label = QLabel("选择文件:")
        self.file_button = QPushButton("浏览")
        self.file_button.clicked.connect(lambda: self.select_file(FileTransferWindow))
        self.send_label = QLabel("")
        self.dest_ip_label = QLabel("目的IP:")
        self.dest_ip_input = QLineEdit("localhost")
        self.dest_port_label = QLabel("目的端口号:")
        self.dest_port_input = QLineEdit("12345")
        self.send_button = QPushButton("发送")
        self.send_button.clicked.connect(self.FileTransferWindow.start_sending)
        self.quit_sending_button = QPushButton("强制中断传输")
        self.quit_sending_button.clicked.connect(self.FileTransferWindow.quit_sending)
        self.back_button = QPushButton("返回")
        self.back_button.clicked.connect(lambda: self.back_to_main_menu(FileTransferWindow))
        self.password_input =QLineEdit("123")
        self.password_input_label=QLabel("密码")

        layout2 = QHBoxLayout()
        layout3 = QHBoxLayout()
        layout4 = QHBoxLayout()
        layout5 = QHBoxLayout()

        self.send_progress_bar = QLabel()
        # self.send_progress_bar.setMaximum(100)  # 进度条最大值设为100
        self.receive_progress_bar = QLabel()
        # self.receive_progress_bar.setMaximum(100)

        # 设置接收模式的部件
        self.port_label = QLabel("开放接收端口:")
        self.port_input = QLineEdit("12345")
        self.start_listen_button = QPushButton("开始监听")
        self.start_listen_button.clicked.connect(self.FileTransferWindow.start_listening)

        line = QFrame(FileTransferWindow)
        line.setFrameShape(QFrame.HLine)
        line.setFrameShadow(QFrame.Sunken)

        line2 = QFrame(FileTransferWindow)
        line2.setFrameShape(QFrame.HLine)
        line2.setFrameShadow(QFrame.Sunken)

        self.directory_label = QLabel("选择输出目录:")
        self.directory_button = QPushButton("浏览")
        self.receive_label = QLabel("")
        self.directory_button.clicked.connect(lambda: self.select_directory(FileTransferWindow))
        # self.file_name_label = QLabel("设置接收文件名")
        # self.file_name = QLineEdit("test.txt")
        self.ip_white_list_manager_button = QPushButton("ip白名单管理")
        self.receiver_id = QComboBox()
        with open('privateKeyRing.json', 'r') as file:
            self.receiver_json = json.load(file)
            for item in self.receiver_json:
                key = list(item.keys())[0]
                self.receiver_id.addItem(key)##############
        self.ip_white_list_manager_button.clicked.connect(self.FileTransferWindow.open_ip_white_list_manager)
        self.quit_listening_button = QPushButton("强行中断接收")
        self.quit_listening_button.clicked.connect(self.FileTransferWindow.quit_listening)
        self.ip_white_list_manager_button.clicked.connect(self.FileTransferWindow.open_ip_white_list_manager)
        self.quit_listening_button = QPushButton("强行中断接收")
        self.quit_listening_button.clicked.connect(self.FileTransferWindow.quit_listening)

        # 把部件添加到平铺图
        layout.addWidget(self.file_label)
        layout4.addWidget(self.file_button)
        layout4.addWidget(self.send_label)
        layout.addLayout(layout4)
        layout.addWidget(self.dest_ip_label)
        layout.addWidget(self.dest_ip_input)
        layout.addWidget(self.dest_port_label)
        layout.addWidget(self.dest_port_input)
        layout2.addWidget(self.send_button)
        layout2.addWidget(self.quit_sending_button)
        layout2.addWidget(self.send_progress_bar)
        layout.addLayout(layout2)
        layout.addWidget(line)
        layout.addWidget(self.port_label)
        layout.addWidget(self.port_input)
        layout.addWidget(self.directory_label)
        layout5.addWidget(self.directory_button)
        layout5.addWidget(self.receive_label)
        layout.addLayout(layout5)
        # layout.addWidget(self.file_name_label)
        # layout.addWidget(self.file_name)
        layout.addWidget(self.receiver_id)
        layout.addWidget(self.password_input_label)
        layout.addWidget(self.password_input)
        layout3.addWidget(self.start_listen_button)
        layout3.addWidget(self.quit_listening_button)
        layout3.addWidget(self.receive_progress_bar)
        layout.addLayout(layout3)
        layout.addWidget(line2)
        layout.addWidget(self.ip_white_list_manager_button)
        layout.addWidget(self.back_button)

        # 将平铺图固定到窗口中间
        self.FileTransferWindow.setLayout(layout)

    def select_file(self, FileTransferWindow):
        # 打开文件浏览器选择需要传输的文件
        file_dialog_input = QFileDialog(FileTransferWindow)
        file_path, _ = file_dialog_input.getOpenFileName(FileTransferWindow, "选择文件", "", "All Files (*)")
        self.file_label.setText(f"选择了文件: {file_path}")
        self.send_file_path = file_path

    def select_directory(self, FileTransferWindow):
        # 打开文件浏览器选择输出目录
        dir_path = QFileDialog.getSaveFileName(None, "选择输出为", "test.txt")
        self.directory_label.setText(f"选择了输出目录: {dir_path[0]}")
        self.dst_directory = dir_path[0]

    def back_to_main_menu(self, FileTransferWindow):
        from controllers.start_menu import StartMenu
        FileTransferWindow.hide()
        startMenu = StartMenu()
        startMenu.exec_()

    def update_send_progress_bar(self, received_blocks, total_blocks):
        # self.ui.update_progress.connect(self.update_progress_bar) # 连接信号到槽
        progress = (received_blocks / total_blocks) * 100 if total_blocks else 0
        # self.send_progress_bar.setValue(progress)
        self.send_progress_bar.setText(f"{received_blocks}/{total_blocks} b | {progress:.2f}%")

    def update_receive_progress_bar(self, received_blocks, total_blocks):
        # self.ui.update_progress.connect(self.update_progress_bar) # 连接信号到槽
        progress = (received_blocks / total_blocks) * 100
        self.receive_progress_bar.setText(f"{received_blocks}/{total_blocks} b | {progress:.2f}%")