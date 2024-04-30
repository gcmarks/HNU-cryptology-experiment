from PyQt5 import QtWidgets
from datetime import datetime
import socket
import threading
from resources.ui_Transfer import FileTransferUI
import csv
import os
import struct
import time
import zlib
from PyQt5.QtCore import pyqtSlot, QThread, pyqtSignal
import hashlib
import jsonpath
from Crypto.PublicKey import RSA
import base64
from Crypto.Cipher import CAST
from Crypto.Cipher import PKCS1_v1_5 
from Crypto.Cipher import CAST
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
ip_white_list = ['127.0.0.1']


class FileTransferWindow(QtWidgets.QDialog):
    def __init__(self):
        super().__init__()

        self.force_sender_shutdown = False
        self.force_receiver_shutdown = False
        self.ip_white_list_path = "ip_white_list.csv"
        self.ip_list = []
        self.load_data()
        self.block_num = 0

        self.ui = FileTransferUI()
        self.ui.init_ui(self)
        self.resize(531, 400)
        self.first_package ={}
        self.first_package_bytes=None
        self.key =None
    def ip_to_decimal(self, ip_address):
        # 将点分十进制表示的字符串转换为十进制表示的IP地址
        decimal_ip = int.from_bytes(socket.inet_aton(ip_address), 'big')
        return decimal_ip

    def is_ip_between(self, ip, data):
        for row in data:
            if row[0] <= ip <= row[1]:
                return True
        return False

    def load_data(self):
        self.ip_list = self.read_from_csv()

    def read_from_csv(self):
        data = []
        with open(self.ip_white_list_path, 'r') as csvfile:
            reader = csv.reader(csvfile)
            for row in reader:
                if row != []:
                    data.append([int(row[0]), int(row[1])])
        return data

    def open_ip_white_list_manager(self):
        from controllers.ip_white_list_manager import IPWhiteListManagerWindow
        self.hide()
        ip_white_list_window = IPWhiteListManagerWindow()
        ip_white_list_window.exec_()

    def start_sending(self):
        # 获取目标ip和端口
        if self.ui.dest_ip_input is None or self.ui.dest_port_input is None:
            return
        dst_ip = self.ui.dest_ip_input.text()
        dst_port = int(self.ui.dest_port_input.text())

        # 用新线程来传输文件（异步
        threading.Thread(target=self.send_file, args=(dst_ip, dst_port)).start()

    
    # 设计大文件分割传输
    # |块总数|块序号|块数据长度|块MD5|块数据|
    # |  4B  |  4B  |  4B  |  32B  | 1MB  |
    
    def file_chunker(self,encryption_key,block_size=1048576):  # 默认块大小为1MB
        """将文件分割成1MB大小的块，每个块带有额外的头信息"""
        total_size = os.path.getsize(self.ui.send_file_path)
        # print(total_size)
        total_blocks = (total_size + block_size - 1) // block_size  # 计算总块数
        self.block_num = total_blocks
        # print(total_blocks)

        with open(self.ui.send_file_path, 'rb') as f:
            block_number = 0
            while True:
                data = f.read(block_size)
                if not data:
                    break
                md5 = hashlib.md5(data).hexdigest()  # 计算MD5
                # data_len = len(data)
                # 对数据进行AES加密
                data=self.encrypt_data(data, encryption_key)
                # print("''''''''''''''''''''''")
                # print(data)
                # print("''''''''''''''''''''''")
                data_len = len(data)
                
                # 打包格式：块总数(4B)，块序号(4B)，数据长度(4B)，块MD5(32字节)，块数据
                block_format = '!III32s{}s'.format(data_len)
                yield struct.pack(block_format, total_blocks, block_number, data_len, md5.encode('utf-8'), data)

                block_number += 1
                # print(f"{block_number} {total_blocks}")

    
    def send_file(self, dest_ip, dest_port):
        try:
            # 创建传输套接字
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((dest_ip, dest_port))
            self.ui.send_label.setText("")
            # self.ui.send_progress_bar.reset()
            for receiver_key, item in enumerate(self.ui.receiver_json): # 遍历公钥列表
                receiver_key = list(item.keys())[0] # 获取公钥ID
                # print(receiver_key)
                # print(self.ui.receiver_id.currentText())
                if receiver_key == self.ui.receiver_id.currentText(): # 如果私钥ID与选择的私钥ID相同

                    value = item[receiver_key] # 获取私钥信息
                    public_key = value['public_key'] # 获取公钥
                    # print(public_key)
                    from Crypto.Random import get_random_bytes
                    encryption_key = get_random_bytes(16)
                    # print("''''''''''''''''''''''")
                    # print(encryption_key)
                    # print("''''''''''''''''''''''")
                    self.first_package["num"] = encryption_key # 0是num，1是timestamp
                    self.first_package["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    # print(self.first_package["num"])
                    # print(self.first_package["timestamp"])
                    
                    # 将密钥进行base64编码并转换为字节
                    encryption_key_base64 = base64.b64encode(encryption_key).decode('utf-8')
                    first_package_bytes = encryption_key_base64.encode('utf-8')
                    self.first_package_bytes = first_package_bytes # 设置签名信息字节
                    # print(self.first_package_bytes)
                    # print(public_key)
                    
                    # 创建 RSA 密钥对象并使用 PKCS1_v1_5 加密器
                    rsakey = RSA.import_key(public_key)
                    cipher = PKCS1_v1_5.new(rsakey)
                    
                    # 对加密后的密钥进行base64编码并转换为字节
                    encrypted_key_bytes = base64.b64encode(cipher.encrypt(self.first_package_bytes))
                    
                    # 发送加密后的密钥
                    # print("''''''''''''''''''''''")
                    # print(len(encrypted_key_bytes))
                    # print("''''''''''''''''''''''")
                    s.send(encrypted_key_bytes)
            cnt = 0
            # 发送文件
            for block in self.file_chunker(encryption_key):
                cnt += 1
                if cnt != self.block_num:
                    self.ui.update_send_progress_bar(1048576  *(cnt+1), 1048576 * self.block_num)
                if self.force_sender_shutdown:
                    # print("传输被强制中断")
                    self.ui.send_label.setText("传输被强制中断")
                    s.close()
                    self.force_sender_shutdown = False
                    break
                s.send(block)
            # print("文件传输成功")
            self.ui.send_label.setText("文件传输成功")
            # time.sleep(1)
            # self.ui.send_progress_bar.reset()
            s.close()

        except Exception as e:
            # print(f"文件传输失败: {e}")
            self.ui.send_label.setText(f"文件传输失败: {e}")

    def start_listening(self):
        # 获取监听端口
        dst_port = int(self.ui.port_input.text())
        # 创造接收线程（异步
        threading.Thread(target=self.listen_for_file, args=(dst_port,)).start()

    def listen_for_file(self, listen_port):
        if self.ui.dst_directory == None:
            self.ui.receive_label.setText("请先选择目录")
            return
        try:
            # dst_file_name = self.ui.file_name.text()
            dst_directory = self.ui.dst_directory
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(("", listen_port))
            s.listen(1)

            self.ui.receive_label.setText(f"端口{listen_port}正在监听...")
            # print(f"端口{listen_port}正在监听...")
            conn, addr = s.accept()
            # print("连接建立，开始接收文件...")
            self.ui.receive_label.setText("连接建立，开始接收文件...")
            first_package = conn.recv(172)


            for receiver_key, item in enumerate(self.ui.receiver_json): # 遍历公钥列表
                receiver_key = list(item.keys())[0] # 获取公钥ID
                if receiver_key == self.ui.receiver_id.currentText(): # 如果私钥ID与选择的私钥ID相同
                    value = item[receiver_key] # 获取私钥信息
                    private_key = value['private_key'] # 获取私钥
                    real_private_key = self.passwordCorrect(private_key, self.ui.password_input.text())
                    if real_private_key:
                        break

            # 创建 RSA 密钥对象并使用 PKCS1_v1_5 解密器
            rsakey = RSA.import_key(real_private_key)
            cipher = PKCS1_v1_5.new(rsakey)
            decrypted_key_bytes = cipher.decrypt(base64.b64decode(first_package),None)
            # print(decrypted_key_bytes)

            # base64解密后的密钥
            encryption_key = base64.b64decode(decrypted_key_bytes)
            # encryption_key = decrypted_key_bytes
            #打印解密后的密钥
            # print(encryption_key)
            # print("===============")
            with open(f"{dst_directory}", "wb") as f:
                while True:
                
                    header = conn.recv(44)

                    if not header:
                        break

                    total_blocks, block_number, data_len = struct.unpack('!III', header[:12])
                    self.ui.update_receive_progress_bar(1048576 * (block_number + 1), 1048576 * total_blocks)

                    md5_received = header[12:44].decode('utf-8')
                    data = b''
                    while len(data) < data_len:
                        packet = conn.recv(data_len - len(data))
                        if not packet:
                            break
                        data += packet

                    if len(data) != data_len:
                        # print(f"数据块{block_number+1}接收不完整")
                        self.ui.receive_label.setText(f"数据块{block_number+1}接收不完整")
                        continue
                    # 对数据进行RSA解密
                    data = self.decrypt_data(data, encryption_key)
                #  print(data)
                    md5_calculated = hashlib.md5(data).hexdigest()
                    if md5_calculated != md5_received:
                        self.ui.receive_label.setText(f"块{block_number} MD5校验失败")
                        continue
                    # print("]]]]]]]]]]]]]]]]")
                    # print(data)
                    f.write(data)

            self.ui.receive_label.setText("文件接收成功，监听结束")
            conn.close()
            s.close()

        except Exception as e:
            # print(f"文件接收失败: {e}")
            self.ui.receive_label.setText(f"文件接收失败: {e}")
            s.close()


    def quit_listening(self):
        self.force_receiver_shutdown = True

    def quit_sending(self):
        self.force_sender_shutdown = True

    def passwordCorrect(self, private_key, password):
        # print("检验密码1")
        # print(password)
        password_bytes = password.encode('utf-8')
        # print("检验密码2")
        sha1_hash = hashlib.sha1()
        sha1_hash.update(password_bytes)
        key = sha1_hash.digest()
        key = key[:16]
        # print("检验密码2")
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

    def encrypt_data(self,data, key):
        cipher = CAST.new(key, CAST.MODE_CBC, iv=get_random_bytes(8))  # 使用CBC模式和随机IV
        encrypted_data = cipher.encrypt(pad(data, CAST.block_size))
        return cipher.iv + encrypted_data  # 将IV和加密数据一起返回

    def decrypt_data(self,encrypted_data, key):
        iv = encrypted_data[:8]  # 提取IV
        encrypted_data = encrypted_data[8:]  # 提取加密数据
        cipher = CAST.new(key, CAST.MODE_CBC, iv=iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), CAST.block_size)
        return decrypted_data