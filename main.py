import threading
import tkinter

from GUI import Adder


def create_window():
    root = tkinter.Tk()
    Adder(root)
    root.mainloop()


def main():
    threading.Thread(target=create_window).start()


if __name__ == "__main__":
    main()
