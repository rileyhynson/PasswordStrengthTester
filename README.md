# PasswordStrengthTester

# About the Project
The chosen case study for the project is the Password Strength Tester. 
The Password Strength Tester will help show users how secure their password is by analysing the characters used, for example, symbols and numbers as well as the character length of the password. 
It also compares the password to a list of commonly used passwords and compromised passwords to inform the user of how secure their passwords are based on a ‘weak’ - ‘moderate’ - ‘strong’ or ‘very strong’ result. 
This will tell users how they can improve their password to reach the very strong result and if the password they are currently using could easily be compromised. 
The overall objective of the project is to increase the users cyber security awareness and basics by improving how secure their passwords are and how secure their accounts are. 

Team Structure and Roles -

Riley – Role – Design Implementation Programming Documentation 

Kieran – Role – Pseudocode Programming Documentation 

Noorullah – Role – Testing Programming Documentation 

Josh – Role – Analysis Programming Documentation 

# User Guide - How to Use the Program

# Problem Analysis
The issue that is presented in the case study is that passwords could be guessable, meaning that the user’s accounts could be compromised. 
To help with preventing this issue, the user could use this program to help them improve their passwords and in turn help them to improve the security of their accounts and make them less vulnerable to an attack from a malicious user. 

# Requirements
The automation solution must be able to provide the user on how secure their accounts by telling them how secure and safe the password is that you are using by providing a result as mentioned above.

# Conceptual Design
The initial ideas of the program will be that the Password Strength Tester will include: 

- Strength indicator (weak, moderate, strong, very strong) 
- Compare the password based on a list of compromised passwords and commonly used passwords 
- Compare the strength of the password based on characters used and the length of the password 
- Use the ‘Have I Been Pwned’ API to check if password is compromised 
- Estimate the time it would take for a malicious attacker to guess the password 
- Accept user input to put the password in 
- Use TKinter UI 

  # Software Design
The programming language chosen is Python.  

The program will be contacting the ‘Have I Been Pwned’ password checking API to see if the password entered has been compromised. 

The program will use TKinter for UI. This will make it easier to use and more visually appealing. 

The code is separated into functions. The functions are separated by their functionality, for example, the assessPasswordStrength function is strictly only for checking how strong the password is and the checkPwnedPassword function is strictly for checking if the password is compromised, then the data and information produced by these functions are combined into the UI to display the message to the user. 

The architecture of the program can be split into four main parts and functions: 

- Password Analysis (assessPasswordStrength) – Evaluates the strength of the password that was entered by the user based on the length, character types and the complexity of the password. 
- Pwned Password Check (checkPwnedPassword) – Checks if the password is compromised by utilising the ‘Have I Been Pwned’ API to check the password against their database and their information. 
- Password Feedback – Provides feedback based on the password analysis. Informs the user on how they can improve their password, for example add numbers or symbols. 
- UI Setup (TKinter) - Responsible for handling the user’s input, starts the password analysis and displays the feedback in an interactive form that is easy to use. 
