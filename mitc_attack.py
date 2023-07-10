import time
import subprocess

def simulate_mitc_attack():

    def upload_file(file_name, content):
        print(f"Uploading file: {file_name}")
        subprocess.run(['scp', file_name, 'ec2-user@ec2-54-210-196-203.compute-1.amazonaws.com:~/'])

    def download_file(file_name):
        print(f"Downloading file: {file_name}")

        subprocess.run(['scp', 'ec2-user@ec2-54-210-196-203.compute-1.amazonaws.com:~/' + file_name, './'])

    def synchronize():
        print("Synchronizing files...")
        time.sleep(2)  # Simulate synchronization time

    user_id = "testuser"
    file_name = "important_document.txt"
    content = "Confidential information"

    upload_file(file_name, content)
    synchronize()
    downloaded_content = download_file(file_name)
    print("Downloaded content:", downloaded_content)

    print("Simulating MITC attack...")
    attacker_id = "attacker"
    modified_content = "Modified data"

    # Unauthorized modification by the attacker
    upload_file(file_name, modified_content)
    synchronize()
    downloaded_content = download_file(file_name)
    print("Downloaded content after attack:", downloaded_content)

# Run the simulation
simulate_mitc_attack()
