#
# SQL Aggressive v0.0.10

```plaintext

              __                                                   
.-----.-----.|  |.--------.---.-.-----.______.---.-.-----.--.--.--.
|__ --|  _  ||  ||        |  _  |  _  |______|  _  |__ --|  |  |  |
|_____|__   ||__||__|__|__|___._|   __|      |___._|_____|________|
         |__|                   |__|                               

```
# We need a list of domains to scan
https://github.com/danielmiessler/SecLists/raw/master/Miscellaneous/top-domains-majestic.csv.zip

# unzip the file and sort the entirety of the list *** This is to process the list of domains and save it to your own list ***
unzip top-domains-majestic.csv.zip ; tail -n +2 top-domains-majestic.csv|head| cut -f3 -d, > majic.pre

# now we can run surface.py to get a list of ips *** this script will read top-domains-majestic.csv and sort it so no need for pre processing ***
# 999986 will scan 20 domains 
python surface.py --input_file top-domains-majestic.csv --start_line 999986

# once we get the attack_surface.txt file we can sort it to remove duplicates
python surface.py --sort_file

# Now we can turn on the sqlmap api so that we can run sqlscan.py
sqlmapapi -s -H "0.0.0.0"

# running sqlscan.py will run sqlmap scans with the arguments you decide to use
python sqlscan.py --input_file attack_surface.txt --args_file arguments/sqlmap_args.txt


```