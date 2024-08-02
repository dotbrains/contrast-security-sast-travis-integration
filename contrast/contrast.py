#! /usr/bin/env python3
#Python3
#Script to Group Details
from ast import Continue, Or
from base64 import decode
import json
import requests
import platform
import os
import csv
from datetime import datetime
import time
import sys


# Global variables
args_auth = ()
args_error = ()
args_groups = ()
args_api_key = ()
args_orgs = ()
args_quiet = ()
args_url = ()
today_date = datetime.now()
date_time = today_date.strftime('%Y-%m-%d %H:%M')
MIN_SEVERITY = "low" # set the initial min_severity in case it is not specified on the command line
current_directory = os.getcwd()
reports_folder_name = "REPORTS"
full_path_to_dir = current_directory + "/" + reports_folder_name

# Initialize global output array
global_json_output = {
    'logs' : []
}

# Append data to output
def log(entry):
    '''
    Append new log entries
    '''
    global_json_output['logs'].append(entry)

# Exit and print output
def exit(status):
    '''
    Print output object as JSON
    '''
    print(json.dumps(global_json_output, indent = 4))

    with open("output.json", "w") as outfile:
        json.dump(global_json_output, outfile)

    sys.exit(status)


def check_output_directory():
    if not os.path.exists(full_path_to_dir):
        os.makedirs(full_path_to_dir)
    pass

with open('auth.conf') as f:
    data = json.load(f)

for result in data["default"]:
    API = os.getenv("CONTRAST__API__API_KEY",result['api_key'])
    BASE_URL = os.getenv("CONTRAST__API__URL",result['base_url'])
    AUTH = os.getenv("CONTRAST__AUTH__TOKEN",result['auth'])
    ORG  = os.getenv("CONTRAST__API__ORGANIZATION",result['org_id'])
    USER_NAME= os.getenv("CONTRAST__API__USER_NAME",result['user_name'])
    SERVICE_KEY= os.getenv("CONTRAST__API__SERVICE_KEY",result['service_key'])
    CONTRAST_SCAN_PAT = os.getenv("CONTRAST_PAT",result["contrast_pat"])
    PRO_NAME = os.getenv("CONTRAST_PROJECT_NAME",result['project_name'])
    FILE_TO_BE_SCANNED = os.getenv("CUST_FILE_TO_BE_SCANNED",result['file_to_be_scanned'])
    CONTRAST_AGENT = os.getenv("CONTRAST_LOCAL_SCANNER_AGENT",result["contrast_local_scanner_agent"])
    LOCAL_PATH = os.getenv("CUST_LOCAL_PATH",result["local_path"])

def check_env_variables():
    if API == "":
        print("Please set CONTRAST__API__API_KEY env variable")
        sys.exit()

    if BASE_URL == "":
        print("Please set CONTRAST__API__URL env variable")
        sys.exit()

    if AUTH == "":
        print("Please set CONTRAST__AUTH__TOKEN env variable")
        sys.exit()

    if ORG == "":
        print("Please set CONTRAST__API__ORGANIZATION env variable")
        sys.exit()

    if SERVICE_KEY == "":
        print("Please set CONTRAST__API__SERVICE_KEY env variable")
        sys.exit()

    # Needed for Windows with Docker approach
    if platform.system() == "Windows":
        if CONTRAST_SCAN_PAT == "":
            print("Please set CONTRAST__API__SERVICE_KEY env variable")
            sys.exit()

    if PRO_NAME == "":
        print("Please set CONTRAST_PROJECT_NAME env variable")
        sys.exit()

    if FILE_TO_BE_SCANNED == "":
        print("Please set CUST_FILE_TO_BE_SCANNED env variable")
        sys.exit()

    # Windows will be using Docker. Only need for Linux.
    if platform.system() != "Windows":
        if CONTRAST_AGENT == "":
            print("Please set CONTRAST_LOCAL_SCANNER_AGENT env variable")
            sys.exit()

    # Needed for Windows with Docker approach
    if platform.system() == "Windows":
        if LOCAL_PATH == "":
            print("Please set CUST_LOCAL_PATH env variable")
            sys.exit()

def call_url(url, headers={'Accept':"application/json", 'Authorization': AUTH, 'API-Key': API}):

    #print(headers)
    response = requests.get(url, headers=headers, allow_redirects=True, timeout=5)
    #print(response.text)

    if response.status_code == 200:
        Continue
    elif response.status_code > 399:
        if (not args_quiet) or (args_error):
            print(f"\nWe were unable to successfully pull information from this endpoint because of HTTP error {response.status_code}\n")
            log (f"{date_time} URL: {url}")
            log (f"{date_time} URL: {headers}")
            log (f"{date_time} HTTP error: {response.status_code}")
            log (response.text)
        sys.exit()
    else:
        if (not args_quiet) or (args_error):
            raise Exception("Error while getting data.", response.status_code, response.text)
        else:
            raise Exception("Error while getting data.", response.status_code, response.text)

    return response


def run_local_scan(target_file, agent_file, project_name=PRO_NAME):
    print(f"Scanning for file: {target_file}")
    cmd =  (""" export CONTRAST__API__URL='%s'
            export CONTRAST__API__USER_NAME='%s'
            export CONTRAST__API__API_KEY='%s'
            export CONTRAST__API__SERVICE_KEY='%s'
            export CONTRAST__API__ORGANIZATION='%s'
            java -jar  %s %s --project-name %s --label %s """
            %(BASE_URL,USER_NAME,API,SERVICE_KEY,ORG,agent_file,target_file,project_name,USER_NAME)
            )


    if platform.system() == "Windows":
        dir_path = str(LOCAL_PATH).replace("C:", "//c")
        target_file = f"{dir_path}/{target_file}"

        os.system(f"set LOCAL_TARGET_LOCATION={dir_path}")
        os.system(f"set LOCAL_TARGET_OUTPUT_LOCATION={dir_path}")
        os.system(f"set LOCAL_ARTIFACT_LOCATION={dir_path}")
        os.system(f"set LOCAL_OUTPUT_LOCATION={dir_path}")
        os.system(f"set CONTRAST_PAT={CONTRAST_SCAN_PAT}")

        os.system(f"docker login ghcr.io/contrast-security-inc -u local-scanner -p {CONTRAST_SCAN_PAT}")
        os.system("docker pull ghcr.io/contrast-security-inc/contrast-sast-scanner-java:latest")

        cmd = f"docker run -v {dir_path}:{dir_path} -v {dir_path}:{dir_path} --env CONTRAST__API__URL=\"{BASE_URL}\" --env CONTRAST__API__USER_NAME=\"{USER_NAME}\" --env CONTRAST__API__API_KEY=\"{API}\" --env CONTRAST__API__SERVICE_KEY=\"{SERVICE_KEY}\" --env CONTRAST__API__ORGANIZATION=\"{ORG}\" ghcr.io/contrast-security-inc/contrast-sast-scanner-java:latest --project-name \"{project_name}\" --label \"{USER_NAME}\" {target_file} -o {dir_path}/results.sarif"

    scan_out_put = os.system(cmd)

    return scan_out_put


def get_projects(proj_name=PRO_NAME):

    print("Scan Report is Uploading.......")
    # Waiting here to finish upload in the TS/UI.
    time.sleep(60)

    url = "%s/v1/organizations/%s/projects?name=%s" % (BASE_URL,ORG,proj_name)

    results=call_url(url, headers={'Accept':"application/json", 'Authorization': AUTH, 'API-Key': API})

    result = results.json()
    check_output_directory()
    with open(full_path_to_dir+"/scan_report.json", "w") as outfile:
        json.dump(result, outfile, indent = 4)

    count = 0

    if result["numberOfElements"] > 0 :
        for project_info in result["content"]:
            project_id = str(project_info["id"])
            project_name = str(project_info["name"])

            if (project_name == proj_name):
                get_scan_report(project_id, proj_name)
                count = count + 1

        if count == 0:
            print("No matching project found")

    else:
        print("No SCAN project found")


def get_scan_report(project_id, project_name):

    url = "%s/organizations/%s/projects/%s/results/csv" % (BASE_URL,ORG,project_id)
    results=call_url(url, headers={'Accept':"application/json", 'Authorization': AUTH, 'API-Key': API})
    if os.path.isfile(full_path_to_dir+"/scan_report.json"):
        os.remove(full_path_to_dir+"/scan_report.json")

    filename = f"{full_path_to_dir}/{project_name}-{datetime.timestamp(today_date)}.csv"
    with open(filename, "w", encoding="utf-8") as f:
        writer = csv.writer(f, delimiter=",", quotechar="\"", quoting=csv.QUOTE_MINIMAL)
        for line in results.iter_lines():
            writer.writerow(str(line).strip().split(","))


def main():
    # check file exist
    if not os.path.isfile(FILE_TO_BE_SCANNED):
        print("[ERROR] file not found. Please provide correct file location for the compiled source code.")
        sys.exit()
    # Windows will be using Docker. Only need for Linux.
    if platform.system() != "Windows":
        if not os.path.isfile(CONTRAST_AGENT):
            print("[ERROR] file not found. Please provide correct file location for the contrast agent.")
            sys.exit()

    # check validate env variables
    check_env_variables()

    # Create project name
    filename = FILE_TO_BE_SCANNED.split('/')[-1]
    unique_proj_name = f"{PRO_NAME}-{filename}"

    # run the scan
    run_local_scan(FILE_TO_BE_SCANNED, CONTRAST_AGENT, project_name=unique_proj_name)

    # download report once all files are scanned
    get_projects(proj_name=unique_proj_name)

if __name__ == "__main__":
    main()
