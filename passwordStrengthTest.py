## PASSWORD STRENGTH TESTER - PROJECT
import tkinter as tk
import hashlib
import requests
import string

## list of commonly used passwords (small but can easily be added to, this is more for an example to show it works)
COMMON_PASSWORDS = {
    "passwords", "123456", "123456789", "12345678", "12345",
    "111111", "1234567", "sunshine", "qwerty", "iloveyou",
    "princess", "admin", "welcome", "666666", "abc123",
    "football", "123123", "monkey", "654321", "!@#$%^&*",
    "charlie", "aa123456", "donald", "password1", "qwerty123"
}

## function to check if password has been pwned through the api
def checkPwnedPassword(password):
    sha1Hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1Hash[:5]
    suffix = sha1Hash[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}" ## api link
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200: ## check the result from contacting api
            hashes = (line.split(':') for line in response.text.splitlines())
            for hashSuffix, count in hashes:
                if hashSuffix == suffix:
                    return int(count)
    except requests.RequestException:
        ## if internet error, pwnedCount will have to be 0 - no access to the api
        pass
    return 0

## function to assess strength
def assessPasswordStrength(password):
    strength = "Weak" ## default strength
    feedback = []
    estimatedTime = "Instantly" ## default estimated crack time

    ## check if the password is in common list
    if password.lower() in COMMON_PASSWORDS:
        return "Very Weak", "Instantly", "Password is too common" ## if password is in the table of common passwords then it must be weak

    ## check for minimum password length
    length = len(password) ## checking length of entered password
    if length < 8: ## if the length is not 8 characters then it is not long enough to be checked
        feedback.append("Password is too short (need 8 characters)")
    elif 8 <= length <= 10: ## if the password is between 8 and 10 characters then it is suggested to add more characters
        feedback.append("Try using more characters for a stronger password")
    else:
        feedback.append("Good length for a strong password") ## if it is longer than 10 characters then it is a good length

    ## checking if password has any of these
    hasUpper = any(c.isupper() for c in password) ## checking for uppercase
    hasLower = any(c.islower() for c in password) ## checking for lowercase
    hasDigit = any(c.isdigit() for c in password) ## checking for numbers
    hasSymbol = any(c in string.punctuation for c in password) ## checking for special characters like ! ? $

    ## feedback for missing character types
    if not hasUpper: ## if it doesnt have uppercase letters then suggests for you to add some
        feedback.append("Add uppercase letters")
    if not hasLower:  ## if it doesnt have lowercase letters then suggests for you to add some
        feedback.append("Add lowercase letters")
    if not hasDigit:  ## if it doesnt have numbers letters then suggests for you to add some
        feedback.append("Add numbers")
    if not hasSymbol:  ## if it doesnt have symbols or special characters then suggests for you to add some
        feedback.append("Add symbols (!, @, #)")

    ## calc entropy based on character types and length - like a score for the password
    keyspace = 0
    if hasLower: ## if hasLower is true then add 26 to keyspace 
        keyspace += 26
    if hasUpper: ## if hasUpper is true then add 26 to keyspace
        keyspace += 26
    if hasDigit: ## if hasDigit is true then add 10 to keyspace
        keyspace += 10
    if hasSymbol: 
        keyspace += len(string.punctuation)

    ## calculation for cracking time
    entropy = (keyspace ** length) if keyspace > 0 else 0

    ## cracking time estimates based on entropy
    if entropy > 10**15:
        estimatedTime = "Centuries"
        strength = "Very Strong"
    elif entropy > 10**12:
        estimatedTime = "Decades"
        strength = "Strong"
    elif entropy > 10**9:
        estimatedTime = "Years"
        strength = "Moderate"
    elif entropy > 10**6:
        estimatedTime = "Months"
        strength = "Weak"
    else:
        estimatedTime = "Minutes or less"
        strength = "Very Weak"

    ## check for patterns in the password
    if any(password == c * length for c in set(password)) or password.lower() in ["123456", "abcdef", "qwerty"]: ## can add more sequences here if needed
        feedback.append("Avoid repeating characters or sequences like 1234")

    ## very strong strength based on passing all checks
    if length >= 12 and hasUpper and hasLower and hasDigit and hasSymbol: ## if the password has over 12 characters, has uppercase, lowercase, numbers and symbols then it is a very strong password
        strength = "Very Strong"
        estimatedTime = "Centuries"
        feedback.append("Password is very strong!")

    ## feedback string
    feedbackText = "\n".join(feedback) if feedback else "Good password complexity"

    return strength, estimatedTime, feedbackText ## return the stength, time and feedback for it to be placed into the strings on the UI

## function to check password
def analysePassword():
    password = entry.get()
    pwnedCount = checkPwnedPassword(password) ## get the result from the function checkin if password has been pwned

    ## strength check
    strength, timeToCrack, feedbackText = assessPasswordStrength(password) ## getting the text for the ui from what the function returns

    ## password compromised = strength very weak
    if pwnedCount > 0: ## if the password has been compromised it cannot be a safe password therefore it is very weak
        strength = "Very Weak"
        timeToCrack = "Instantly"
        feedbackText = f"Password is compromised! It has been pwned {pwnedCount} times. Choose a stronger password" ## shows the number of time it has been compromised

    ## show pwned count - strength assessment - estimated time to crack - password feedback
    resultLabel.config(text=f"Pwned {pwnedCount} times\nStrength: {strength}\nEstimated Time to Crack: {timeToCrack}\n\nFeedback:\n{feedbackText}")

## ui setup
root = tk.Tk()
root.title("Password Strength Tester - 22603VIC")

## ui layout
root.geometry("500x300")
root.resizable(True, True)

tk.Label(root, text="Enter Password:", font=("Arial", 12)).grid(row=0, column=0, padx=10, pady=20, sticky='e')
entry = tk.Entry(root, width=30, show="*", font=("Arial", 12))
entry.grid(row=0, column=1, padx=10, pady=20)

analyzeButton = tk.Button(root, text="Analyse", command=analysePassword, font=("Arial", 12))
analyzeButton.grid(row=1, column=0, columnspan=2, pady=10)

resultLabel = tk.Label(root, text="Strength: \nEstimated Time to Crack: ", font=("Arial", 12), justify='left')
resultLabel.grid(row=2, column=0, columnspan=2, padx=10, pady=10, sticky='w')

feedbackLabel = tk.Label(root, text="", font=("Arial", 10), justify='left', fg="blue")
feedbackLabel.grid(row=3, column=0, columnspan=2, padx=10, pady=10, sticky='w')

root.mainloop()