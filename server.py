from flask import Flask
from flask import redirect
from flask import url_for
from flask import render_template
from flask import request

import json
import os
from datetime import datetime

from verification_backend import check_patient_logs, check_all_logs
from verification_backend import aes_encrypt, aes_decrypt
from verification_backend import compute_signature_for_log
import hashlib
from verification_backend import compute_complete_file_sign, verify_complete_file_sign

app = Flask(__name__)


@app.route("/register")
def register():
    return render_template('register.html')
 
@app.route("/login", methods=['POST', 'GET'])
def login():
    if request.method == 'GET':
        return render_template('login.html', user_status='Login into your account')

    else: ## request is coming from register.html after registration
        name = request.form['name']
        user_name = request.form['username']
        user_pass = request.form['password']
        company_login = request.form.get('company')

        if company_login == None:
            company_login = "no"
        else:
            company_login = "yes"

        create_new_user(name, user_name, user_pass, company_login)  ## encryption here

        return render_template('login.html', user_status='Registration successful! Login into your account')

@app.route("/")
def home():
    return redirect(url_for("login", method='GET'))

@app.route("/home_page", methods=['POST', 'GET'])
def home_page_user():
    user_name = request.form['username']
    user_pass = request.form['password']
    company_login = request.form.get('company')

    if company_login == None:
        company_login = "no"
    else:
        company_login = "yes"

    ## user_name, user_pass, company_login   -> encrypt and check

    ## just check here is user_name, user_pass is valid
    ans = check_user_password(user_name, user_pass, company_login)

    if ans: ## if username password combination is correct - login the user
        ## user is logging in just show him his logs
        if company_login == "no":
            user_logs = retrieve_logs(user_name)

            #data_check, changed_logs = check_patient_logs(user_name)
            data_check, changed_logs = check_all_logs()  ## checking all logs for the normal patient also

            if data_check:
                all_logs_present = verify_complete_file_sign()
                data_check = data_check and all_logs_present
            

        ## company is logging in, show them all logs
        if company_login == "yes":
            #user_logs = get_logs_audit_company(user_name)
            user_logs = get_audit_company_logs()
            data_check, changed_logs = check_all_logs()
            if data_check:
                all_logs_present = verify_complete_file_sign()
                data_check = data_check and all_logs_present

        user_id = find_user_id(user_name)
        #user_id = 4
        table_header = ['LOG_ID', 'USER_NAME','USER_ID', 'AUDITOR_ID', 'ACTION_TYPE', 'TABLE AFFECTED IN EHR', 'TIMESTAMP', 'NOTES']
        
        ## do not show signature
        for x in user_logs:
            x.pop()

        for it1 in range(len(user_logs)):
            for it2 in range(len(user_logs[0])):
                user_logs[it1][it2] = aes_decrypt(str(user_logs[it1][it2]))

        user_logs = sorted(user_logs, key= lambda x:x[6], reverse=True)  ## show logs in descending order
        ## if all audit records are verified display them
        if data_check:
            return render_template('home_page.html', headings = table_header, data = user_logs, username=user_name, userid=user_id, data_status='verified')
        ## show an error message saying data was sacrificed
        else:
            return render_template('home_page.html', headings = [], data = [], username=user_name, userid=user_id, data_status='data compromised', login_notes='Admins have been notified about the unauthorized audit record change')
    
    else: ## if username password combination is not correct, do not login the user
        return render_template('login.html', user_status='Username-password combination is wrong for your user type :(   Try logging in again')
    
    
def check_user_password(user_name, user_password, company_login):
    user_name = aes_encrypt(user_name)
    user_password = hashlib.sha256(user_password.encode('utf-8')).hexdigest() ## hash the user password and then check
    user_password = aes_encrypt(user_password)
    company_login = aes_encrypt(company_login)

    with open('user_credentials.json', 'r') as f:
        data = json.load(f)
        
        data = data['username_password']
        if user_name in data:
            this_user_data = data[user_name]
            if this_user_data[2] == user_name and this_user_data[3] == user_password and this_user_data[4] == company_login:
                return True
            else:
                return False

        return False

def create_new_user(name, user_name, user_password, company_login):

    name = aes_encrypt(name)  ## encrypt
    user_name = aes_encrypt(user_name)  ## encrypt
    user_password = hashlib.sha256(user_password.encode('utf-8')).hexdigest() ## hash the password
    user_password = aes_encrypt(user_password)  ## encrpyt
    company_login = aes_encrypt(company_login)  ## encrypt

    this_user_id = -1
    with open('user_credentials.json', 'r+') as file:
    
        data = json.load(file)

        this_user_id = data[aes_encrypt('total_user_count')] + 1
        data[aes_encrypt('total_user_count')]+=1
        data['username_password'][user_name] = [aes_encrypt(str(this_user_id)), name, user_name, user_password, company_login]

        file.seek(0)
        json.dump(data, file, indent=4)

    

    if company_login == aes_encrypt('no'):
        gen_log_id = generate_log_id()
        with open('user_logs.json', 'r+') as file:
            data = json.load(file)

            now = datetime.now()
            dt_string = now.strftime("%m-%d-%Y %H:%M:%S")
            usr_log_data = [gen_log_id, aes_decrypt(user_name), this_user_id, 'self', 'account created', 'user_credentials', dt_string, 'user created a new account']
            usr_log_data = [aes_encrypt(str(x)) for x in usr_log_data]
            log_sign = compute_signature_for_log(usr_log_data)
            usr_log_data.append(log_sign)
            data.update({user_name:{"logs": [usr_log_data]}})

            file.seek(0)
        
            json.dump(data, file, indent=4)

    compute_complete_file_sign()
    
def retrieve_logs(username):
    username = aes_encrypt(username)  ## encrypt
    with open('user_logs.json', 'r') as file:
        data = json.load(file)

    if username in data:
        return data[username]['logs']

def update_logs(username, new_log):
    username = aes_encrypt(username)  ## encrypt
    new_log = [aes_encrypt(x) for x in new_log]  ## encrypt
    with open('user_logs.json', 'r+') as file:
        data = json.load(file)

        if username in data:
            data[username]['logs'].append(new_log)
        file.seek(0)
        json.dump(data, file, indent=4)

def generate_log_id():
    with open('user_logs.json', 'r+') as file:
        data = json.load(file)

        new_log_id = data[aes_encrypt('total_logs_count')]

        data[aes_encrypt('total_logs_count')]+=1
        file.seek(0)
        json.dump(data, file, indent=4)

        return new_log_id+1

def retrieve_logs_no_enc(username):
    with open('user_logs.json', 'r') as file:
        data = json.load(file)

    if username in data:
        return data[username]['logs']

def get_audit_company_logs():
    with open('user_logs.json', 'r') as file:
        data = json.load(file)
        user_list_access = []
        for it in data.keys():
            if type(data[it]) == type({1:1}):
                if 'logs' in data[it]:
                    user_list_access.append(it)

    ans = []
    for it in user_list_access:
        this_user_log = retrieve_logs_no_enc(it)
        ans+=this_user_log

    return ans

def get_logs_audit_company(admin_name):
    admin_name = aes_encrypt(admin_name)  ## encrypt
    with open('user_logs.json', 'r+') as file:
        data = json.load(file)
        user_list_access = data[admin_name]['access_users'][0]

    ans = []
    for it in user_list_access:
        this_user_log = retrieve_logs(it)
        ans+=this_user_log

    return ans

def find_user_id(user_name):
    user_name = aes_encrypt(user_name)  ## encrypt
    with open('user_credentials.json', 'r') as file:
        data = json.load(file)
        user_id = data['username_password'][user_name][0]

    return aes_decrypt(user_id)

if __name__ == "__main__":
    app.run(debug=True)