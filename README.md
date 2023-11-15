# SQL  Aggressive v0.0.10
```
Wrapper for SQLMAP utilizing sqlmapapi and advanced attack surface generation techniques.
```
```plaintext

              __                                                   
.-----.-----.|  |.--------.---.-.-----.______.---.-.-----.--.--.--.
|__ --|  _  ||  ||        |  _  |  _  |______|  _  |__ --|  |  |  |
|_____|__   ||__||__|__|__|___._|   __|      |___._|_____|________|
         |__|                   |__|                               


# We need a list of domains to scan
https://github.com/danielmiessler/SecLists/raw/master/Miscellaneous/top-domains-majestic.csv.zip

#unzip the file and sort the entirety of the list *** This is to process the list of domains and save it to your own list ***
unzip top-domains-majestic.csv.zip ; tail -n +2 top-domains-majestic.csv|head| cut -f3 -d, > majic.pre

# now we can run surface.py to get a list of ips *** this script will read top-domains-majestic.csv and sort it so no need for pre processing ***
# 999986 will scan 20 domains 
blackline@blacklinecyber:$ python surface.py --input_file top-domains-majestic.csv --start_line 999986

# once we get the attack_surface.txt file we can sort it to remove duplicates
blackline@blacklinecyber:$ python surface.py --sort_file

# after we get attack_surface.txt we have to run it through httpx and save the output
blackline@blacklinecyber:$ cat surface_output/attack_surface.txt | httpx -o surface_output/alive.txt

# now we can use filterx.py to sort the results so we dont have any duplicates
blackline@blacklinecyber:$ python filterx.py --input_file surface_output/alive.txt --output_file sqlmap_targets/sorted.txt

# Now we can turn on the sqlmap api so that we can run sqlscan.py
blackline@blacklinecyber:$ sqlmapapi -s -H "0.0.0.0"

# running sqlscan.py will run sqlmap scans with the arguments you decide to use
blackline@blacklinecyber:$ python sqlscan.py --input_file sqlmap_targets/sorted.txt --args_file arguments/sqlmap_args.txt


```