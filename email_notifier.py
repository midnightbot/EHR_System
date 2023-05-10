import smtplib
from email.message import EmailMessage
import time

def send_email_notification(email_subject, email_content):
    sender_email = 'ehrsystem.notifications@gmail.com'
    to_email = ['adnani@usc.edu','patilsup@usc.edu']
    sender_email_pass = ""

    msg = EmailMessage()
    msg.set_content(email_content)

    msg['Subject'] = email_subject
    msg['From'] = sender_email
    msg['To'] = to_email
    
    with smtplib.SMTP('smtp.gmail.com', 587) as smtp:
        smtp.ehlo()
        smtp.starttls()
        smtp.ehlo()
        smtp.login(sender_email, sender_email_pass)
        smtp.send_message(msg)
        return True

    return False
