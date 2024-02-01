
from tkinter import *
import hashlib
import re
import pyperclip
import random
import string

try:
    import requests
except ModuleNotFoundError:
    print("Need to pip install requests")
    quit()

main_win = Tk()
main_win.title("CheCK YoUr PaSs")
main_win.geometry("800x650")
main_win.configure(bg='gray')
frame = Frame(main_win)
frame.configure(bg='gray')
output = Label(main_win)
pwned_output = Label(main_win)
strength_label = Label(main_win)


def check_pwned_status(password_input):
    pattern = re.compile(r'[:\s]\s*')
    password = password_input
    website = "https://api.pwnedpasswords.com/range/"

    final_Hash_hex = hashlib.sha1(password.encode()).hexdigest()
    hash_prefix = final_Hash_hex[:5]

    r = requests.get(website + hash_prefix, headers={"Add-Padding": "true"})
    status = r.status_code

    api_hash_output = r.text
    split_list = re.split(pattern, api_hash_output)
    pass_hash_suffix = final_Hash_hex[5:].upper()

    try:
        index = split_list.index(pass_hash_suffix)
        return split_list[index + 1]
    except ValueError:
        return "This password isn't in the list"


def check_password_strength(password_input):
    # Password strength criteria:
    # At least 8 characters
    # At least one uppercase letter
    # At least one lowercase letter
    # At least one digit
    # At least one special character

    if len(password_input) < 8:
        return "Weak: Password should be at least 8 characters long"
    if not re.search(r"[A-Z]", password_input):
        return "Weak: Password should contain at least one uppercase letter"
    if not re.search(r"[a-z]", password_input):
        return "Weak: Password should contain at least one lowercase letter"
    if not re.search(r"\d", password_input):
        return "Weak: Password should contain at least one digit"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password_input):
        return "Weak: Password should contain at least one special character"

    return "Strong Password"


def clear_output_labels():
    pwned_output.destroy()
    output.destroy()
    strength_label.destroy()


def check_pass():
    global output, pwned_output, strength_label
    clear_output_labels()
    pswd = password.get()
    response = check_pwned_status(pswd)

    if response == "This password isn't in the list":
        # Password is not pwned, check its strength
        pswd_strength = check_password_strength(pswd)

        pwned_output = Label(frame, text="Good news! - No results found.", fg="#69FF69", bg="#383B40",
                             font=('Arial', 16))
        output = Label(frame,
                       text="This password wasn't found in any of the sources loaded into Have I been pwned.",
                       fg="#69FF69", bg="#383B40", wraplength=400, font=('Arial', 14))
        pwned_output.grid(row=4, column=0, columnspan=2, pady=10)
        output.grid(row=5, column=0, columnspan=2, pady=0)

        # Display password strength
        strength_label = Label(frame, text=pswd_strength, fg="#69FF69", bg="#383B40", font=('Arial', 16))
        strength_label.grid(row=6, column=0, columnspan=2, pady=0)

    else:
        pwned_output = Label(frame, text="Your Password has been leaked!", fg="#FF5A5A", bg="#383B40",
                             font=('Arial', 16))
        output = Label(frame,
                       text="This password has previously appeared in a data breach and should never be used. There is " + response + " instances of this password in the Have I been pwned database.",
                       fg="#FF5A5A", bg="#383B40", wraplength=500, font=('Arial', 16))
        pwned_output.grid(row=4, column=0, columnspan=2, pady=10)
        output.grid(row=5, column=0, columnspan=2, pady=10)

        # Display password strength
        strength_label = Label(frame, text="", fg="#FF5A5A", bg="#383B40", font=('Arial', 16))
        strength_label.grid(row=0, column=0, columnspan=9, pady=0)


def show_password():
    if var1.get() == 1:
        password.config(show="")
    else:
        password.config(show="*")


def copy_to_clipboard():
    result = pwned_output.cget("text") + "\n" + output.cget("text")
    pyperclip.copy(result)


def generate_password():
    password_length = 12
    password_characters = string.ascii_letters + string.digits + string.punctuation
    generated_password = ''.join(random.choice(password_characters) for i in range(password_length))
    password.delete(0, END)
    password.insert(0, generated_password)


title_label = Label(frame, text="CheCK YoUr PaSs", fg="#F08080", bg="#383B40", font=('Arial', 40))
password_label = Label(frame, text="Password: ", fg="white", bg="#383B40", font=('Arial', 14))
password = Entry(frame, show="*", font=('Arial', 14), width=30)
password.focus_set()
var1 = IntVar()
show_pass = Checkbutton(frame, text='Show Password?', font=('Arial', 12), selectcolor="", fg="white",
                        bg="#383B40", activeforeground="white",
                        variable=var1, onvalue=1, offvalue=0, command=show_password)
check_button = Button(frame, text="Check Password", fg="white", bg="#4CAF50", activebackground="#45a049",
                      font=('Arial', 14), command=check_pass)
copy_button = Button(frame, text="Copy Result", fg="white", bg="#4CAF50", activebackground="#45a049",
                     font=('Arial', 14), command=copy_to_clipboard)
generate_button = Button(frame, text="Generate Password", fg="white", bg="#4CAF50", activebackground="#45a049",
                         font=('Arial', 14), command=generate_password)

title_label.grid(row=0, column=0, columnspan=2, sticky="news", pady=40)
password_label.grid(row=1, column=0)
password.grid(row=1, column=1)
show_pass.grid(row=2, column=1, pady=10)
check_button.grid(row=3, column=0, columnspan=2, pady=20)
copy_button.grid(row=7, column=0, pady=10)
generate_button.grid(row=7, column=1, pady=10)

frame.pack()

main_win.mainloop()
