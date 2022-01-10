import argparse
import sys
import csv
from decimal import Decimal
from time import sleep
from datetime import datetime
from pathlib import Path

CODE_TYPE = "UTF-8"
LOG_FILE = "logs.csv"

SIGNATURE = {
    "key": "Trans2 Secondary Request",
    "trigger": 40004,
    "proto": "SMB",
    "descript": "User Password Brute-force Attempt"
}

class Packet:
    def __init__(self, number, time, source, destination, protocol, length, info):
        self.number = number
        self.time = time
        self.source = source
        self.destination = destination
        self.protocol = protocol
        self.length = length
        self.info = info
#--------------------------------------------------        
 
def inInterval(start, end, now):
    if end <= start:      
        # End time must be larger than start time  
        return False
    else:
        if now >= start and now < end:
            return True
        else:
            return False
#--------------------------------------------------            
 
def init_log():
    # open the file in the write mode
    outfile = open(LOG_FILE, 'w', newline = '', encoding = CODE_TYPE)
    # create the csv writer
    writer = csv.writer(outfile)
    # save header of csv file
    header = ['Trigger', 'DetectionTime', 'From', 'Protocol', 'Description']
    writer.writerow(header)
    # close the file
    outfile.close()
#--------------------------------------------------

def save_log(data):
    outfile = open(LOG_FILE, 'a', newline = '', encoding = CODE_TYPE)
    writer = csv.writer(outfile)
    # save a row of data into csv
    writer.writerow(data)
    outfile.close()
#--------------------------------------------------    

def searchForSignature(filename, interval, threshold):
    while 1:
        if not Path(filename).is_file():
            pass
        else:
            time_i = 1
            src_i = 2
            protocol_i = 6    
            info_i = 8
            count = 0 
            
            init_log()

            print("--- SMB BruteForce Attack List ---")
            
            while 1:
                with open(filename) as file:
                    packets = []
                    for line_no, line in enumerate(csv.reader(file), 0):
                        if line_no != 0:
                            packets.append(line)

                    if len(packets) > 0:
                        ip_list = []
                        startTime = Decimal(packets[0][time_i])
                        for packet in packets:
                            current = Decimal(packet[time_i])      
                            isInInterval = inInterval(startTime, startTime + interval, current)     
                            if (packet[protocol_i] == 'SMB' or packet[protocol_i] == 'SMB Pipe') and isInInterval:
                                count += 1          
                                if (SIGNATURE['key'] in packet[info_i]) and (packet[src_i] not in ip_list):
                                    ip_list.append(packet[src_i])              
                            if not isInInterval:
                                if count > threshold:
                                    time = datetime.now().strftime("%d/%m/%Y %H:%M:%S")                        
                                    for ip in ip_list:
                                        print('\t' + ip)         
                                        data = [
                                            SIGNATURE['trigger'],
                                            time,
                                            ip,
                                            SIGNATURE['proto'],
                                            SIGNATURE['descript'] 
                                        ]
                                        save_log(data)                
                                sleep(interval)
                                startTime = current
                    else:
                        pass
                                
            break                                
    return count
#--------------------------------------------------
 
def get_args():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-i', metavar='<Interval>',
                        help='interval to detect', required=True)
    parser.add_argument('-t', metavar='<Threshold>',
                        help='threshold to detect', required=True)
    parser.add_argument('-f', metavar='<Output CSV File>',
                        help='csv file to create', required=True)
    args = parser.parse_args()
    return args
#--------------------------------------------------    
 
def main():
    args = get_args()

    if not args.i.isnumeric():
        print('\n\tInterval value must be integer!')
        sys.exit(-1)
    if not args.t.isnumeric():
        print('\n\tThreshold value must be integer!')
        print('\n\tExample Correct Syntax: python detect.py -i 5 -t 5 -f result.csv')
        sys.exit(-1)

    searchForSignature(args.f, int(args.i), int(args.t))
#--------------------------------------------------    
 
if __name__ == '__main__':
    main()