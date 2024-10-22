import sendgrid
from sendgrid.helpers.mail import Mail
from dotenv import load_dotenv
import os 
load_dotenv()

# Function to send email using SendGrid
def send_email(to_email, subject, content,SENDGRID_API_KEY):
    sg = sendgrid.SendGridAPIClient(api_key=SENDGRID_API_KEY)
    from_email = os.getenv('MAIL_DEFAULT_SENDER')  # Use your SendGrid verified email
    mail = Mail(
        from_email=from_email,
        to_emails=to_email,
        subject=subject,
        html_content=content
    )
    try:
        response = sg.send(mail)
        print(response.status_code)
        print(response.body)
        print(response.headers)
    except Exception as e:
        print(e)
