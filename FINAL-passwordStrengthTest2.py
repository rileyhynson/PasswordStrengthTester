# loading libraries, etc
import tkinter as tk
from tkinter import filedialog, messagebox
import hashlib
import requests
import string
import os

# function to load common passwords
def load_common_passwords(file_path):
    try:
        with open(file_path, 'r') as file:
            return set(file.read().splitlines())
    except Exception as e:
        messagebox.showerror("Error", f"Could not load file: {e}")
        return set()

# check if the password is pwned by accessing the api
def check_pwned_password(password):
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}" # url for api
    try:
        response = requests.get(url, timeout=5) # getting response
        if response.status_code == 200:
            hashes = (line.split(':') for line in response.text.splitlines())
            for hash_suffix, count in hashes:
                if hash_suffix == suffix:
                    return int(count)
    except requests.RequestException: # err
        result_label.config(text="Error: Could not complete breach check. Check your internet connection.")
        return -1
    return 0

# function to check strength
def assess_password_strength(password):
    strength = "Weak" # default values
    feedback = []
    estimated_time = "Instantly"

    if password.lower() in COMMON_PASSWORDS: # if its common its easy to guess
        return "Very Weak", "Instantly", "Password is too common"

    length = len(password)
    if length < 8: # too short
        feedback.append("Password is too short (min 8 characters)")
    elif length <= 10: # long enough but could be better by adding more chars
        feedback.append("Try using more characters")
    else: # meets length recommendation
        feedback.append("Good length")

    has_upper = any(c.isupper() for c in password) # check for uppercase
    has_lower = any(c.islower() for c in password) # check for lowercase
    has_digit = any(c.isdigit() for c in password) # check for numbers
    has_symbol = any(c in string.punctuation for c in password) # check for symbols

    if not has_upper: feedback.append("Add uppercase letters") # add uppercase
    if not has_lower: feedback.append("Add lowercase letters") # add lowercase
    if not has_digit: feedback.append("Add numbers") # add numbers
    if not has_symbol: feedback.append("Add symbols (!, @, #)") # add symbols

    # calc entropy
    keyspace = sum([26 for x in [has_upper, has_lower] if x] + 
                   [10 for x in [has_digit] if x] + 
                   [len(string.punctuation) for x in [has_symbol] if x])
    entropy = (keyspace ** length) if keyspace > 0 else 0

    if entropy > 10**15:
        strength, estimated_time = "Very Strong", "Centuries"
    elif entropy > 10**12:
        strength, estimated_time = "Strong", "Decades"
    elif entropy > 10**9:
        strength, estimated_time = "Moderate", "Years"
    elif entropy > 10**6:
        strength, estimated_time = "Weak", "Months"
    else:
        strength, estimated_time = "Very Weak", "Minutes or less"

    if any(password == c * length for c in set(password)): # repeating chars
        feedback.append("Avoid repeating characters")
    if password.lower() in {"abcdef", "qwerty", "123456"}: # sequence
        feedback.append("Avoid sequences") 

    if length >= 12 and all([has_upper, has_lower, has_digit, has_symbol]): # if pw is long and has met all criteria
        feedback.append("Password is very strong!")

    return strength, estimated_time, "\n".join(feedback) or "Good password complexity"

# function to check the password
def analyze_password():
    global COMMON_PASSWORDS
    password = entry.get() # password to check is the entry by the user
    pwned_count = check_pwned_password(password) # no of times its been pwned
    if pwned_count == -1:
        return

    strength, time_to_crack, feedback_text = assess_password_strength(password)
    if pwned_count > 0: # if pwned count is more than 1 then its easy to crack
        strength, time_to_crack = "Very Weak", "Instantly"
        feedback_text = f"Password is compromised! Found {pwned_count} times." # shows how many times its been pwned

    result_label.config(text=f"Pwned {pwned_count} times\nStrength: {strength}\n"
                             f"Estimated Time to Crack: {time_to_crack}\n\nFeedback:\n{feedback_text}")

# the function that lets you pick the file to load passwords from
def select_file():
    global COMMON_PASSWORDS
    file_path = filedialog.askopenfilename(
        title="Select Common Passwords File",
        filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
    )
    if file_path:
        COMMON_PASSWORDS = load_common_passwords(file_path)
        file_label.config(text=f"Loaded file: {os.path.basename(file_path)}")

# UI Setup with buttons, etc
root = tk.Tk()
root.title("Password Strength Tester")
root.geometry("600x400")

tk.Label(root, text="Enter Password:", font=("Arial", 12)).grid(row=0, column=0, padx=10, pady=20, sticky='e')
entry = tk.Entry(root, width=30, show="*", font=("Arial", 12))
entry.grid(row=0, column=1, padx=10, pady=20)

analyze_button = tk.Button(root, text="Analyze", command=analyze_password, font=("Arial", 12))
analyze_button.grid(row=1, column=0, columnspan=2, pady=10)

file_button = tk.Button(root, text="Select Password File", command=select_file, font=("Arial", 12))
file_button.grid(row=2, column=0, pady=10, sticky='e')
file_label = tk.Label(root, text="No file selected", font=("Arial", 10), fg="blue")
file_label.grid(row=2, column=1, padx=10, sticky='w')

result_label = tk.Label(root, text="Strength: \nEstimated Time to Crack: ", font=("Arial", 12), justify='left')
result_label.grid(row=3, column=0, columnspan=2, padx=10, pady=10, sticky='w')

COMMON_PASSWORDS = set()

root.mainloop()
