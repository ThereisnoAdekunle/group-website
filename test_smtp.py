import smtplib
from ssl import create_default_context

try:
    print("Attempting to connect to smtp.gmail.com:465...")
    server = smtplib.SMTP_SSL('smtp.gmail.com', 465, timeout=10, context=create_default_context())
    server.set_debuglevel(1)
    print("Connected! Logging in...")
    server.login('westkhalifahninety7@gmail.com', 'gdnzdvuzfcosizpu')
    print("Logged in successfully!")
    server.quit()
except Exception as e:
    print(f"Failed: {str(e)}")