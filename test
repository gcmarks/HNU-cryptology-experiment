from PyQt5 import QtWidgets
import sys
from controllers.start_menu import StartMenu


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)

    start_menu = StartMenu()
    start_menu.show()

    sys.exit(app.exec_())

# 我现在想让你用pythonQT写一个能够使用tcp传输文件的UI 其中需要包括两种模式
# 第一种是发送模式 在这种模式下 我们需要能选择需要传递的文件 以及需要传输到的目的ip和端口号 以及最后还需要有一个发送按钮用于开始发送
# 第二种是接受模式 在这种模式下 我们需要能选择接收端口号 以及需要一个按钮 这个按钮点击一次将开启这个端口的监听用于接收文件 再按一次用于结束监听