*** 1: Catch packets on realtime and save those packets into a CSV file ***
```
python live2csv.py -i [Network Interface Name] -f [output-csv-filename.csv]
```
```
Example: python live2csv.py -i "VMware Virtual Ethernet Adapter for VMnet8" -f result.csv
```
```
TO GET EXACT Network Interface Name, RUN COMMAND ON CMD: "wmic nicconfig get description"
```



*** 2: Start running (exploiting) the system between attacker and victim machines  ***



*** 3: Analyze catched packets in CSV file to detect Brute-Force Attack - Run below command in parallel with the above command ***
```
python detect.py -i [interval] -t [threshold] -f [output-csv-filename.csv]
```
```
Example Correct Syntax: python detect.py -i 5 -t 5 -f result.csv
```