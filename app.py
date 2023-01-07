from flask import Flask, render_template, request
import requests
from bs4 import BeautifulSoup
import re

app = Flask(__name__)

@app.route('/')
def security_checker():
   return render_template('security_checker.html')

@app.route('/check', methods=['POST'])
def check():
   url = request.form['url']
   result = check_security(url)
   return render_template('result.html', result=result)

def check_security(url):
   result = "Secure"
   try:
      response = requests.get(url)
   except:
      return "Error: Unable to reach URL"

   # check for XSS vulnerabilities
   if "Content-Security-Policy" not in response.headers:
      result = "Insecure: Content-Security-Policy header not found"
   elif "script-src 'self'" not in response.headers['Content-Security-Policy']:
      result = "Insecure: Content-Security-Policy header does not allow scripts from self"
   else:
      soup = BeautifulSoup(response.text, 'html.parser')
      for script in soup.find_all('script'):
         if script.get('src') is None:
            result = "Insecure: Inline script found"
            break

   # check for CSRF vulnerabilities
   soup = BeautifulSoup(response.text, 'html.parser')
   for form in soup.find_all('form'):
      if form.get('method') == "post" and form.get('action') != url:
         result = "Insecure: Form with POST method found with external action"
         break
   if "X-CSRF-TOKEN" not in response.headers:
      result = "Insecure: X-CSRF-TOKEN header not found"

   # check for SQL injection vulnerabilities
   if "?" in url:
      # check GET request parameters
      params = url.split("?")[1]
      if "=" in params:
         for param in params.split("&"):
            if "=" in param:
               key, value = param.split("=")
               if any(char in value for char in ["'", '"', "\\"]):
                  result = "Insecure: Suspicious character found in GET parameter value"
                  break
   else:
      # check POST request data
      soup = BeautifulSoup(response.text, 'html.parser')
      for form in soup.find_all('form'):
         if form.get('method') == "post":
            for input_tag in form.find_all('input'):
               if input_tag.get('type') == "text":
                  result = "Insecure: Input field with text type found in POST form"
                  break

   return result

if __name__ == '__main__':
   app.run()
