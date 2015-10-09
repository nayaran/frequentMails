# frequentMails
A web app to let users analyze whom they are communicating with the most in gmail

Overview:
We always want to analyze everything that we do. So, we have set out to analyze
whom we are communicating with the most and how often in the past 3 months. This web app helps to analyze this data by generating a report of most frequently communicated contacts.
What this app does:
- Allows users to connect or disconnect their gMail account
with the app.
- If the user disconnects his account, the app will not be able to read the
email information any longer.
- Gets read-only permissions to read emails for a connected gmail account using OAuth.
- This means that by giving OAuth permissions, the app is able to
read the emails of any account.
- Analyzes all the email conversations within the given time period
- Gives users the option to select the fromDate and toDate 
- Sorts the emails based on the most conversations in the descending order.
- So, emails with the most conversations come on top.
- Generates a report in the following format
--------------------------------------------------
Name: awesome
Email: awesome@gmail.com
abc@gmail.com- 23
def@yahoo.com- 12
xyz@outlook.com- 1
--------------------------------------------------
- If there are multiple email addresses in to, cc or bcc, counts them as individual
conversations. For example; if the same email is sent to abc@gmail.com and
def@yahoo.com, treats it as separate conversations with both of them and increment
their conversations count.
API Info:
GMail API - https://developers.google.com/gmail/api/
