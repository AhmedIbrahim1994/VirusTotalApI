import sys
import requests
import json
import argparse
parser = argparse.ArgumentParser()



API_URL = 'https://www.virustotal.com/api/v3/files/'

# pass the api key from the cmd line




# Get a file report 
# https://developers.virustotal.com/reference/file-info
def get_file_report_api(sha256,api_key):
    headers = {"accept": "application/json",
            "x-apikey": api_key
            }
    file_url = API_URL+""+sha256 # we can do string concatenate
    response = requests.get(file_url, headers=headers)
    return response.text
    


#json parsing;
#a list of detection engine and detection name
#list of name of the program
# name of each singer and whether thay are still valid at this time
#based on the, decided the file legitimate or not and explain the reasons in case of malicious
def json_parsing(json_file):
    # Internal Program Name
    json_dict = json.loads(json_file)
    internal_name = json_dict['data']['attributes']['signature_info']['internal name']
    print("> Internal Name:\t"+internal_name)
    
    # List All Singers    
    signers = json_dict['data']['attributes']['signature_info']['signers']
    signers = signers.split("; ")
    print("> Signer", *signers, sep="\n\t- ")
    
    # Name of each Singers and whether they are valid or not
    signers_details = json_dict['data']['attributes']['signature_info']['signers details']
    for i in range (len(signers_details)):   
        print("> Singer Name: "+ signers_details[i]['name'] + " Signer Status: " + signers_details[i]['status'])
    
    # A list of detection engine and detection name
    detection_result = json_dict['data']['attributes']['last_analysis_results']
    number_of_detection = len(detection_result.keys())
    print("***** Sample has been evaluated against "+str(number_of_detection)+" Engine *****")
    list_detection_engine_detection_name(detection_result)
    print("***** Summay of Malicious Detection *****")
    list_detection_engine_detection_name_malicious(detection_result)
    

# list malicious Detection Engine and Detection Name
def list_detection_engine_detection_name_malicious(json_dict):
    for key,value in json_dict.items():
        if value['result'] != "NONE":
            if value['category'] == "malicious":
                    print ("Detection Engine: "+key+" --- Detection Name: " + value['result'])
        
# list Detection Engine and Detection Name
def list_detection_engine_detection_name(json_dict):
    for key,value in json_dict.items():
        if value['result'] is None:
            print ("Detection Engine: "+value['engine_name']+" --- Detection Name: None")
        else:
            print ("Detection Engine: "+value['engine_name']+" --- Detection Name: "+value['result'])
  




def main():
    parser.add_argument('--API_KEY', help='API Key')
    parser.add_argument('--SHA265', help='SHA-265 Hash of the Sample')
    args = parser.parse_args()
    print("==============\nSummay of the Sample\n==============")
    print("SHA256:\t\t\t"+args.SHA265)
    print("Query Virus Total API...")
    result_json = get_file_report_api(args.SHA265,args.API_KEY)
    json_parsing(result_json)
    
    
if __name__ == "__main__":
    main()
