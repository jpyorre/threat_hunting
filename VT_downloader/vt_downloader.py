import requests
import sys, os.path
import logging

with open('virustotal_token.txt') as API_KEY:
    api = API_KEY.read()

vt_notification_URL = 'https://www.virustotal.com/intelligence/hunting/notifications-feed/?key=e8bfb2f7fefde0ec05a83e9b4b6c97758066a0c129760492c462f400354568eb'

# This will be the list of MD5's that we're going to download from VT
md5_list = 'md5_list.txt'

# Last MD5 downloaded, used to know where to start downloading next time this is run
last_md5 = 'last_md5.txt'

# Logging will write to log_file
log_file = 'VT_Download.log'
logging.basicConfig(filename=log_file,
                    level=logging.INFO,
                    format='%(asctime)s %(levelname)-8s %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S') # Put ,stream=sys.stdout after datefmt if you want to see it in a terminal
  
# Loads the list of MD5's for processing:      
def load_md5s(index):
    global md5_list
    with open(md5_list, 'r') as f:
        md5_list = f.read().splitlines()
        f.close()
 
# Write the MD5's to a text file as they're downloaded. While this will write each MD5 to last_md5.txt, it keeps writing them and then overwriting with the next one. When processing of the current downloads is done, the very last MD5 that was downloaded will be the only MD5 in last_md5.txt. last_md5.txt is read to pick up where it left off next time this script runs.
def write_last_md5(md5):
        f = open(last_md5,'w')
        f.write(md5)
        f.close

    # Delete the hunting notifications that have been processed
def delete_completed_hunts():
    params = {'apikey': api}
    response = requests.get('https://www.virustotal.com/intelligence/hunting/delete-notifications/programmatic/', params=params)
    # Have to get the ID's from json and submit via a POST. It will delete all samples between the ID's. Example: [5278074110738432, 6402641302650880]
              
# Download the files, one at a time. Also logs each download and saves the last MD5 that was downloaded to a text file:   
def downloadFile():
    for md5 in md5_list:
        name = md5 + '.exe'
        params = {'apikey': api, 'hash': md5}
        response = requests.get('https://www.virustotal.com/vtapi/v2/file/download', params=params)
        downloadedfile = response.content
        logging.info('Downloading %s', name)
        fo = open(name,"wb")
        fo.write(downloadedfile + '.exe')
        fo.close()
        
        # Write the last MD5 to a file as a placeholder for the next time this is run. See function for more info
        write_last_md5(md5)

def main():
# Get the json containing the hunting report, parse md5's out of it and save to md5_list_temp.txt

# Read the last md5 from last_md5.txt, take all md5's after that last md5 from md5_list_temp and write them to md5_list.txt

# Load the md5_list:
    load_md5s(1)
# Parse through md5_list, find the last md5 downloaded and download everything since then.
    downloadFile()
    
if __name__ == '__main__':
    main()
    


    