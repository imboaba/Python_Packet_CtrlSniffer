from scapy.config import conf
from scapy.themes import BrightTheme

from main import Main

if __name__ == '__main__':
    conf.color_theme = BrightTheme()
    main = Main.Main()
    main.start()

