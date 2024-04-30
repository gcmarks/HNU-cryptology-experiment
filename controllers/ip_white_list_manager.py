from PyQt5 import QtWidgets
import socket
import csv
from resources.ui_IP_White_List_manager import IPWhiteListManagerUI
ip_white_list_path = 'ip_white_list.csv'


def is_crossed(a, b):
    if (a[0] < b[0] and a[1] < b[1]) or (a[0] > b[1] and a[1] > b[1]):
        return False
    return True

class IPWhiteListManagerWindow(QtWidgets.QDialog):
    def __init__(self):
        super().__init__()
        self.resize(531, 700)
        self.ip_white_list_path = ip_white_list_path
        self.ip_list = []
        self.ui = IPWhiteListManagerUI()
        self.ui.init_ui(self)

    def read_from_csv(self):
        data = []
        with open(self.ip_white_list_path, 'r') as csvfile:
            reader = csv.reader(csvfile)
            for row in reader:
                if row != []:
                    data.append([row[0], row[1]])
        return data

    def decimal_to_ip(self, ip_str):
        # 将字符串转换为整数
        ip_int = int(ip_str)

        # 提取每个字节的值
        byte1 = (ip_int >> 24) & 255
        byte2 = (ip_int >> 16) & 255
        byte3 = (ip_int >> 8) & 255
        byte4 = ip_int & 255

        # 将每个字节转换为点分十进制字符串
        ip_str = f"{byte1}.{byte2}.{byte3}.{byte4}"
        return ip_str

    def ip_to_decimal(self, ip_address):
        # 将点分十进制表示的字符串转换为十进制表示的IP地址
        decimal_ip = int.from_bytes(socket.inet_aton(ip_address), 'big')
        return decimal_ip

    def load_data(self):
        self.ip_list = self.read_from_csv()

    def add_to_csv(self, ip_from, ip_to):
        if ip_from == None or ip_to == None:
            print("无输入 不合标准")
            return

        if ip_from > ip_to:
            print("大小相反 不合标准")
            return

        new_data = [ip_from, ip_to]
        is_cross = False
        for rows, row in enumerate(self.ip_list):
            if is_crossed(new_data, [int(x) for x in row]):
                is_cross = True
                break

        if is_cross:
            print("ip有重合 不合标准")
            return
        self.ip_list.append(new_data)

        # 写入到新的 CSV 文件
        with open(self.ip_white_list_path, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerows(self.ip_list)

        self.ui.IPWhiteListTable.insertRow(0)
        self.ui.IPWhiteListTable.setItem(0, 0, QtWidgets.QTableWidgetItem(self.decimal_to_ip(ip_from)))
        self.ui.IPWhiteListTable.setItem(0, 1, QtWidgets.QTableWidgetItem(self.decimal_to_ip(ip_to)))

    def delete_ip_white_list(self):
        row = self.ui.selected_row
        with open(self.ip_white_list_path, 'r') as iplist:
            reader = csv.reader(iplist)
            rows = list(reader)

        if row != -1:
            del rows[row]
            self.ip_list = rows
        else:
            return

        with open(self.ip_white_list_path, 'w') as iplist:
            writer = csv.writer(iplist)
            writer.writerows(rows)

        self.remove_empty_lines()
        self.ui.IPWhiteListTable.removeRow(row)

    def remove_empty_lines(self):
        # 读取文件内容并过滤空行
        with open(self.ip_white_list_path, 'r') as file:
            lines = file.readlines()
            non_empty_lines = [line for line in lines if line.strip()]
            sorted_csv = sorted(non_empty_lines, key=lambda x: int(x[0]))


        # 将更新后的内容写回到文件中
        with open(self.ip_white_list_path, 'w', newline='') as file:
            file.writelines(sorted_csv)
