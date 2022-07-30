import _appendpath  # noqa: F401

import sw_luadocs.capture
import tkinter
import tkinter.ttk


def main():
    def tk_cts_button_command():
        hwnd = tk_root.winfo_id()
        point = sw_luadocs.capture.client_to_screen(hwnd)
        tk_cts_label.configure(text=repr(point))

    def tk_gss_button_command():
        scr_size = sw_luadocs.capture.get_screen_size()
        tk_gss_label.configure(text=repr(scr_size))

    tk_root = tkinter.Tk()
    tk_cts_frame = tkinter.ttk.Frame(tk_root)
    tk_cts_button = tkinter.ttk.Button(
        tk_cts_frame, text="client_to_screen", command=tk_cts_button_command
    )
    tk_cts_label = tkinter.ttk.Label(tk_cts_frame)
    tk_gss_frame = tkinter.ttk.Frame(tk_root)
    tk_gss_button = tkinter.ttk.Button(
        tk_gss_frame, text="get_screen_size", command=tk_gss_button_command
    )
    tk_gss_label = tkinter.ttk.Label(tk_gss_frame)

    tk_cts_frame.pack(side="top")
    tk_cts_button.pack(side="left")
    tk_cts_label.pack(side="left")
    tk_gss_frame.pack(side="top")
    tk_gss_button.pack(side="left")
    tk_gss_label.pack(side="left")

    tk_root.mainloop()


if __name__ == "__main__":
    main()
