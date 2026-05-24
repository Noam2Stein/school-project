import os
import tkinter as tk
import tkinter.filedialog as fd
from datetime import datetime
from uuid import UUID as Uuid
from lib.client_backend import ClientBackend

backend = ClientBackend()

root = tk.Tk()
root.title("Group Encryption Client")
root.geometry("900x600")

current_screen = None

def show_login_screen():
    global current_screen

    if current_screen is not None:
        current_screen.destroy()

    current_screen = tk.Frame(root)
    current_screen.pack(fill="both", expand=True)

    exit_button = tk.Button(current_screen, text="X")
    exit_button.place(relx=0.98, rely=0.02, anchor="ne")

    email_label = tk.Label(current_screen, text="Email")
    email_label.pack()
    email_entry = tk.Entry(current_screen, width=30)
    email_entry.pack()

    password_label = tk.Label(current_screen, text="Password")
    password_label.pack()
    password_entry = tk.Entry(current_screen, show="*", width=30)
    password_entry.pack()

    description_label = tk.Label(current_screen, text="Signup User Description")
    description_label.pack()
    description_entry = tk.Entry(current_screen, width=30)
    description_entry.pack()

    login_button = tk.Button(current_screen, text="Login", width=12)
    login_button.pack()

    signup_button = tk.Button(current_screen, text="Sign Up", width=12)
    signup_button.pack()

    status_label = tk.Label(current_screen, text="")
    status_label.pack()

    def on_login_pressed():
        email = email_entry.get()
        password = password_entry.get()

        def poll():
            status_label.config(text="Logging In...")
            exit_button.config(state="disabled")
            login_button.config(state="disabled")
            signup_button.config(state="disabled")

            result = backend.login(email, password)

            if result == "wait":
                root.after(100, poll)
            elif result == "done":
                show_item_screen()
            else:
                status_label.config(text=f"cant login: {result}")
                exit_button.config(state="normal")
                login_button.config(state="normal")
                signup_button.config(state="normal")

        poll()

    def on_signup_pressed():
        email = email_entry.get()
        password = password_entry.get()
        description = description_entry.get()

        def poll():
            status_label.config(text="Signing Up...")
            exit_button.config(state="disabled")
            login_button.config(state="disabled")
            signup_button.config(state="disabled")

            result = backend.signup(email, password, description)

            if result == "wait":
                root.after(100, poll)
            elif result == "done":
                show_item_screen()
            else:
                status_label.config(text=f"cant signup: {result}")
                exit_button.config(state="normal")
                login_button.config(state="normal")
                signup_button.config(state="normal")

        poll()

    exit_button.config(command=show_item_screen)
    login_button.config(command=on_login_pressed)
    signup_button.config(command=on_signup_pressed)

def show_item_screen():
    global current_screen

    if current_screen:
        current_screen.destroy()

    current_screen = tk.Frame(root)
    current_screen.pack(fill="both", expand=True)

    status_label = tk.Label(current_screen, text="Loading items...")
    status_label.pack()

    login_button = tk.Button(current_screen, text="Login", command=show_login_screen)
    login_button.pack()

    if backend.logged_into_email() == "not logged in":
        status_label.config(text="Not logged in")
        return

    create_button = tk.Button(current_screen, text="Create Item", command=show_create_item_screen)
    create_button.pack()

    items_frame = tk.Frame(current_screen)
    items_frame.pack(pady=5, fill="x")

    tk.Label(items_frame, text="Name", font=("Arial", 10, "bold")).grid(row=0, column=0, padx=5)
    tk.Label(items_frame, text="Size", font=("Arial", 10, "bold")).grid(row=0, column=1, padx=5)
    tk.Label(items_frame, text="Encryption Method", font=("Arial", 10, "bold")).grid(row=0, column=2, padx=5)

    my_items = backend.my_item_ids()
    if isinstance(my_items, list):
        for item_idx, item in enumerate(my_items):
            row = item_idx + 1
            tk.Label(items_frame, text=backend.item_name(item), font=("Arial", 8)).grid(row=row, column=0, padx=5)
            tk.Label(items_frame, text=f"{backend.item_size(item)} bytes.", font=("Arial", 8)).grid(row=row, column=1, padx=5)
            tk.Label(items_frame, text=backend.item_encryption_method(item), font=("Arial", 8)).grid(row=row, column=2, padx=5)
            tk.Button(items_frame, text="Invite", command=lambda item=item: show_invite_screen(item)).grid(row=row, column=3, padx=5)
            tk.Button(items_frame, text="Release Key", command=lambda item=item: show_release_item_screen(item)).grid(row=row, column=4, padx=5)
            tk.Button(items_frame, text="Leave", command=lambda item=item: show_leave_screen(item)).grid(row=row, column=5, padx=5)
            tk.Button(items_frame, text="Delete", command=lambda item=item: show_delete_screen(item)).grid(row=row, column=6, padx=5)

    invites_frame = tk.Frame(current_screen)
    invites_frame.pack(pady=5, fill="x")

    tk.Label(invites_frame, text="Name", font=("Arial", 10, "bold")).grid(row=0, column=0, padx=5)
    tk.Label(invites_frame, text="Size", font=("Arial", 10, "bold")).grid(row=0, column=1, padx=5)
    tk.Label(invites_frame, text="Encryption Method", font=("Arial", 10, "bold")).grid(row=0, column=2, padx=5)

    invite_items = backend.my_item_invitation_ids()
    if isinstance(invite_items, list):
        for item_idx, item in enumerate(invite_items):
            row = item_idx + 1
            tk.Label(invites_frame, text=backend.item_name(item), font=("Arial", 8)).grid(row=row, column=0, padx=5)
            tk.Label(invites_frame, text=f"{backend.item_size(item)} bytes.", font=("Arial", 8)).grid(row=row, column=1, padx=5)
            tk.Label(invites_frame, text=backend.item_encryption_method(item), font=("Arial", 8)).grid(row=row, column=2, padx=5)
            tk.Button(invites_frame, text="Join", command=lambda item=item: show_join_screen(item)).grid(row=row, column=3, padx=5)
            tk.Button(invites_frame, text="Reject", command=lambda item=item: show_reject_screen(item)).grid(row=row, column=4, padx=5)

    status_label.config(text="")

def show_invite_screen(item: Uuid):
    global current_screen

    if current_screen is not None:
        current_screen.destroy()

    current_screen = tk.Frame(root)
    current_screen.pack(fill="both", expand=True)

    exit_button = tk.Button(current_screen, text="X", command=show_item_screen)
    exit_button.place(relx=0.98, rely=0.02, anchor="ne")

    email_listbox = tk.Listbox(current_screen, height=10, width=50)
    email_listbox.pack()

    invite_button = tk.Button(current_screen, text="Invite", width=12)
    invite_button.pack()

    status_label = tk.Label(current_screen, text="")
    status_label.pack()

    def poll_fetch():
        status_label.config(text="Fetching users...")
        exit_button.config(state="disabled")
        invite_button.config(state="disabled")

        result = backend.fetch_from_server()

        if result == "wait":
            root.after(100, poll_fetch)
        elif result == "done":
            emails = backend.global_user_emails()
            if isinstance(emails, list):
                email_listbox.delete(0, tk.END)
                for email in emails:
                    description = backend.global_user_description(email)
                    email_listbox.insert(tk.END, f"{email}: {description}")

                status_label.config(text="Select a user to invite")
                exit_button.config(state="normal")
                invite_button.config(state="normal")
            else:
                status_label.config(text="Error fetching users")
        else:
            status_label.config(text=f"Fetch error: {result}")

    poll_fetch()

    def on_invite_pressed():
        selection = email_listbox.curselection()
        if not selection:
            status_label.config(text="Select a user to invite")
            return

        selected_email = email_listbox.get(selection[0]).split(":")[0]

        def poll_invite():
            status_label.config(text=f"Inviting {selected_email}...")
            exit_button.config(state="disabled")
            invite_button.config(state="disabled")

            result = backend.invite_user_to_item(selected_email, item)

            if result == "wait":
                root.after(100, poll_invite)
            elif result == "done":
                status_label.config(text=f"User {selected_email} invited!")
                exit_button.config(state="normal")
                invite_button.config(state="normal")
            else:
                status_label.config(text=f"Invite failed: {result}")
                exit_button.config(state="normal")
                invite_button.config(state="normal")

        poll_invite()

    invite_button.config(command=on_invite_pressed)

def show_release_item_screen(item: Uuid):
    global current_screen

    if current_screen is not None:
        current_screen.destroy()

    current_screen = tk.Frame(root)
    current_screen.pack(fill="both", expand=True)

    exit_button = tk.Button(current_screen, text="X", command=show_item_screen)
    exit_button.place(relx=0.98, rely=0.02, anchor="ne")

    until_label = tk.Label(current_screen, text="Until Date (YYYY-MM-DD HH:MM)")
    until_label.pack()
    until_entry = tk.Entry(current_screen, width=30)
    until_entry.pack()

    release_button = tk.Button(current_screen, text="Release", width=12)
    release_button.pack()

    status_label = tk.Label(current_screen, text="")
    status_label.pack()

    def on_release_pressed():
        until_str = until_entry.get()
        try:
            until = datetime.strptime(until_str, "%Y-%m-%d %H:%M")
        except ValueError:
            status_label.config(text="Invalid date format! Use YYYY-MM-DD HH:MM")
            return

        def poll():
            status_label.config(text="Releasing item...")
            exit_button.config(state="disabled")
            release_button.config(state="disabled")

            result = backend.release_item(item, until)

            if result == "wait":
                root.after(100, poll)
            elif result == "done":
                show_item_screen()
            else:
                status_label.config(text=f"Error releasing item: {result}")
                exit_button.config(state="normal")
                release_button.config(state="normal")

        poll()

    release_button.config(command=on_release_pressed)

def show_create_item_screen():
    global current_screen

    if current_screen is not None:
        current_screen.destroy()

    current_screen = tk.Frame(root)
    current_screen.pack(fill="both", expand=True)

    exit_button = tk.Button(current_screen, text="X", command=show_item_screen)
    exit_button.place(relx=0.98, rely=0.02, anchor="ne")

    file_var = tk.StringVar()
    file_label = tk.Label(current_screen, text="File path")
    file_label.pack()
    file_entry = tk.Entry(current_screen, textvariable=file_var, width=30)
    file_entry.pack()
    browse_button = tk.Button(current_screen, text="Browse", width=12)
    browse_button.pack()

    create_button = tk.Button(current_screen, text="Create", width=12)
    create_button.pack()

    status_label = tk.Label(current_screen, text="")
    status_label.pack()

    def on_browse_pressed():
        filename = fd.askopenfilename()
        if filename:
            file_var.set(filename)

    def on_create_pressed():
        file_path = file_var.get()

        try:
            with open(file_path, "rb") as file:
                file_bytes = file.read()
        except Exception as exp:
            status_label.config(text=f"Failed to read file: {exp}")
            return

        def poll():
            status_label.config(text="Creating Item...")
            exit_button.config(state="disabled")
            create_button.config(state="disabled")

            result = backend.create_item(os.path.basename(file_path), file_bytes)

            if result == "wait":
                root.after(100, poll)
            elif result == "done":
                show_item_screen()
            else:
                status_label.config(text=f"error creating: {result}")
                exit_button.config(state="normal")
                create_button.config(state="normal")

        poll()

    browse_button.config(command=on_browse_pressed)
    create_button.config(command=on_create_pressed)

def show_leave_screen(item: Uuid):
    global current_screen

    if current_screen is not None:
        current_screen.destroy()

    current_screen = tk.Frame(root)
    current_screen.pack(fill="both", expand=True)

    status_label = tk.Label(current_screen, text="Leaving and Releasing Item...")
    status_label.pack()

    def poll():
        status_label.config(text="Leaving and Releasing Item...")

        result = backend.leave_and_release_item(item)

        if result == "wait":
            root.after(100, poll)
        elif result == "done":
            status_label.config(text="Done")
            root.after(1000, show_item_screen)
        else:
            status_label.config(text=f"error leaving item: {result}")
            root.after(1000, show_item_screen)

    poll()

def show_delete_screen(item: Uuid):
    global current_screen

    if current_screen is not None:
        current_screen.destroy()

    current_screen = tk.Frame(root)
    current_screen.pack(fill="both", expand=True)

    status_label = tk.Label(current_screen, text="Deleting Item...")
    status_label.pack()

    def poll():
        status_label.config(text="Deleting Item...")

        result = backend.delete_item(item)

        if result == "wait":
            root.after(100, poll)
        elif result == "done":
            status_label.config(text="Done")
            root.after(1000, show_item_screen)
        else:
            status_label.config(text=f"error deleting item: {result}")
            root.after(1000, show_item_screen)

    poll()

def show_join_screen(item: Uuid):
    global current_screen

    if current_screen is not None:
        current_screen.destroy()

    current_screen = tk.Frame(root)
    current_screen.pack(fill="both", expand=True)

    status_label = tk.Label(current_screen, text="Joining Item...")
    status_label.pack()

    def poll():
        status_label.config(text="Joining Item...")

        result = backend.join_item(item)

        if result == "wait":
            root.after(100, poll)
        elif result == "done":
            status_label.config(text="Done")
            root.after(1000, show_item_screen)
        else:
            status_label.config(text=f"error joining item: {result}")
            root.after(1000, show_item_screen)

    poll()

def show_reject_screen(item: Uuid):
    global current_screen

    if current_screen is not None:
        current_screen.destroy()

    current_screen = tk.Frame(root)
    current_screen.pack(fill="both", expand=True)

    status_label = tk.Label(current_screen, text="Rejecting Item...")
    status_label.pack()

    def poll():
        status_label.config(text="Rejecting Item...")

        result = backend.reject_item(item)

        if result == "wait":
            root.after(100, poll)
        elif result == "done":
            status_label.config(text="Done")
            root.after(1000, show_item_screen)
        else:
            status_label.config(text=f"error rejecting item: {result}")
            root.after(1000, show_item_screen)

    poll()

show_login_screen()
root.mainloop()