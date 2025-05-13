import tkinter as tk
import logging
from gui import PortScannerGUI

def main():
    logging.basicConfig(
        level=logging.INFO, 
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('port_scanner.log'),
            logging.StreamHandler()
        ]
    )
    root = tk.Tk()
    root.title("Advanced Port Scanner")
    root.minsize(800, 900)
    app = PortScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()