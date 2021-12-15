from scapy.config import conf
from scapy.themes import BrightTheme

from main import Main

if __name__ == '__main__':
    """使用带色彩的主题"""
    conf.color_theme = BrightTheme()
    main = Main.Main(log=False)
    main.start(type='master')  # or slave

