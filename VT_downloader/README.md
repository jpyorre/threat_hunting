VT Downloader:

Put your VT API key in virustotal_token.txt, removing the existing text.
Open vt_downloader.py and add your URI key to the end of the vt_notification_URL variable.
Open md5_list.txt and enter a list of MD5's or SHA5's that you want to download.

Run like this:

python vt_downloader.py
All the md5's/sha5's will download right into the same directory with .exe extensions for analysis. These are live malware samples (hopefully), so be careful!