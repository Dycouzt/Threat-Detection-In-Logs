import paramiko

ip = "127.0.0.1"
user = "test"
passwords = ["123456", "password", "test123"]

for pwd in passwords:
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=user, password=pwd)
    except Exception as e:
        print(f"Failed login with {pwd}")