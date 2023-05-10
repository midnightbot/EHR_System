import rsa
import json
import codecs
from email_notifier import send_email_notification
import time
import aes.aesencrypt
import aes.aesdecrypt
import os
from datetime import datetime

def generate_keys():
    (pub_key, pvt_key) = rsa.newkeys(2048)

    with open('publickey.key', 'wb') as f:
        f.write(pub_key.save_pkcs1('PEM'))

    with open('privatekey.key', 'wb') as f:
        f.write(pvt_key.save_pkcs1('PEM'))

def read_contents(filename):
    f = open(filename, 'rb')
    data = f.read()
    f.close()
    return data

def compute_sign(message):
    pvt_key = rsa.PrivateKey.load_pkcs1(read_contents('privatekey.key'))
    signature = rsa.sign(message.encode(), pvt_key, 'SHA-512')
    ans = signature.hex()
    return ans

def verify_sign(message, sign):
    pub_key = rsa.PublicKey.load_pkcs1(read_contents('publickey.key'))

    try:
        rsa.verify(message.encode(), bytearray.fromhex(sign), pub_key)
        return True
    except:
        return False

def compute_signature_for_log(arr):
    overall_message = ','.join([str(x) for x in arr])
    return compute_sign(overall_message)

def create_log_signature_for_patient(user_name):
    with open('user_logs.json', 'r+') as file:
        data = json.load(file)
        for x in range(len(data[user_name]['logs'])):
            this_arr = data[user_name]['logs'][x]
            this_arr.append(compute_signature_for_log(this_arr))

        file.seek(0)
        json.dump(data, file, indent=4)

def send_email(changed_logs):
    subject = 'Data integrity compromised'
    content = '[Unauthorized Log Modifications] Unauthorized modifications have been made to the audit records' + '\n'
    content+= 'Immediate action needs to be taken' + '\n'
    content+= 'Compromised log_ids: ' + ",".join([aes_decrypt(str(x[0])) for x in changed_logs]) + '\n'
    msg_sent = send_email_notification(subject, content)
    if msg_sent:
        return True

def check_log_of_this_patient(user_name):
    with open('user_logs.json', 'r+') as file:
        data = json.load(file)
        changed_logs = []
        for it in data[user_name]['logs']:
            this_arr = it
            overall_message = ','.join([str(x) for x in this_arr[:-1]])
            verification = verify_sign(overall_message, this_arr[-1])

            if verification == False:
                changed_logs.append([this_arr[0], this_arr[2]])
                
    if len(changed_logs) != 0:
        return False, changed_logs

    return True,[]

def check_patient_logs(user_name):
    user_name = aes_encrypt(user_name)  ## encrypt
    this_user_verfiy, changed_logs = check_log_of_this_patient(user_name)

    if this_user_verfiy!=True:
        msg_sent = send_email(changed_logs)
        return False, changed_logs

    return True, []

def check_all_logs():
    with open('user_logs.json', 'r') as file:
        data = json.load(file)
        users = []
        for it in data.keys():
            if type(data[it]) == type({1:1}):
                if 'logs' in data[it]:
                    users.append(it)

    ## now for all users verfiy their logs
    overall = []
    for usr in users:
        this_user_verfiy, changed_logs = check_log_of_this_patient(usr)
        if this_user_verfiy == False:   
            overall+= changed_logs

    if len(overall)!=0:
        msg_sent = send_email(overall)
        return False, overall

    return True, []

def gen_aes_key():
    cipher_key = os.urandom(16).hex()
    with open('./aes_key.key', 'w+') as f:
        f.write(cipher_key)

def aes_encrypt(msg):
    key = ''
    with open('./aes_key.key', 'r') as f:
        key = f.read()

    encrypted_message = aes.aesencrypt.main(msg, key)
    return encrypted_message

def aes_decrypt(msg):
    key = ''
    with open('./aes_key.key', 'r') as f:
        key = f.read()
    
    hex_msg, plain_msg = aes.aesdecrypt.main(msg, key)
    return plain_msg

def generate_log_id():
    with open('user_logs.json', 'r+') as file:
        data = json.load(file)

        new_log_id = data[aes_encrypt('total_logs_count')]

        data[aes_encrypt('total_logs_count')]+=1
        file.seek(0)
        json.dump(data, file, indent=4)

        return new_log_id+1
        
def add_log_for_patient(user_name, this_user_id):
    gen_log_id = generate_log_id()
    with open('user_logs.json', 'r+') as file:
        data = json.load(file)

        now = datetime.now()
        dt_string = now.strftime("%m-%d-%Y %H:%M:%S")
        usr_log_data = [gen_log_id, user_name, this_user_id, '100', 'MODIFY : bill', 'user_bills', dt_string, 'User bill was modified']
        usr_log_data = [aes_encrypt(str(x)) for x in usr_log_data]
        log_sign = compute_signature_for_log(usr_log_data)
        usr_log_data.append(log_sign)

        data[aes_encrypt(user_name)]['logs'].append(usr_log_data)
        file.seek(0)
    
        json.dump(data, file, indent=4)

def compute_complete_file_sign():
    with open('user_logs.json', 'r+') as f:
        lines = f.readlines()

    all_logs = ",,".join(lines)
    overall_sign = compute_sign(all_logs)

    with open('overall_sign.json', 'r+') as file:
        data = json.load(file)

        data['overall_sign'] = overall_sign
        file.seek(0)
    
        json.dump(data, file, indent=4)


def verify_complete_file_sign():
    with open('user_logs.json', 'r+') as f:
        lines = f.readlines()

    all_logs = ",,".join(lines)

    with open('overall_sign.json', 'r+') as f:
        data = json.load(f)
        stored_sign = data['overall_sign']

    verified = verify_sign(all_logs, stored_sign)
    if verified:
        return True
    else:
        subject = 'Data integrity compromised'
        content = '[Unauthorized Log Deletions] Some Logs missing in the audit database' + '\n'
        content+= 'Unauthorized deletions have been made to the audit records' + '\n'
        content+= 'Immediate action needs to be taken' + '\n'
        msg_sent = send_email_notification(subject, content)
        return False