import argparse
import os.path
import json
import sys
import re

import csv
import pyshark

CODE_TYPE = "UTF-8"

def render_csv_row_data(packet, out_csv):
    pkt = json.loads(packet)

    pkt['info'] = pkt['info'].replace("\u2192", "->")
    
    src_port = None
    dst_port = None
    if pkt['protocol'] == 'TCP' or pkt['protocol'] == 'UDP':
        src_port = pkt['info'].split()[0]
        dst_port = pkt['info'].split()[2]
    

    data = [pkt['no'],
            pkt['time'],
            pkt['source'],
            src_port,
            pkt['destination'],
            dst_port,
            pkt['protocol'],
            pkt['length'],
            pkt['info']]

    save_data(out_csv, data)
#--------------------------------------------------

def live2csv(sys_interface, out_csv):
    init_header_csv(out_csv)
    capture = pyshark.LiveCapture(interface='\\Device\\NPF_{' + sys_interface + '}', only_summaries=True)
    try:
        for packet in capture.sniff_continuously():            
            try:
                pkt_raw = json.dumps(packet.__dict__)                                        
                render_csv_row_data(pkt_raw, out_csv)                
            except StopIteration:
                pass           
    except Exception as ex:
        print("\nError while capturing live packets!")
        print(ex)
        # Program does not require TShark, any error related to TShark belongs to user's computer environment        
        if 'TShark' in str(ex):
            print("\n\tRecommended Wireshark version is 3.0.0.")
            print("\n\tPlease check in the installation folder of Wireshark must has 'tshark.exe' file!")
            print("\n\tFor example: C:\\Program Files\\Wireshark\\tshark.py")
#--------------------------------------------------

def init_header_csv(filepath):
    # open the file in the write mode
    outfile = open(filepath, 'w', newline = '', encoding = CODE_TYPE)
    # create the csv writer
    writer = csv.writer(outfile)
    # save header of csv file
    header = ['no', 'time', 'src', 'src_port', 'dst', 'dst_port', 'protocol', 'length', 'info']
    writer.writerow(header)
    # close the file
    outfile.close()
#--------------------------------------------------

def save_data(filepath, data):
    outfile = open(filepath, 'a', newline = '', encoding = CODE_TYPE)
    writer = csv.writer(outfile)
    # save a row of data into csv
    writer.writerow(data)
    outfile.close()
#--------------------------------------------------

def install_Scapy_2_4_0():
    print("\nChecking Scapy version ...")    
    result = os.popen("pip freeze").read().split("\n")  
    if 'scapy==2.4.0' in result:        
        print("Checking Scapy version DONE") 
        return True        
    if 'scapy==2.4.0' not in result:
        print("Installing Scapy version 2.4.0 ...")
        os.popen("pip install scapy==2.4.0").read()
        print("Checking Scapy version DONE")
        return True
    return False
#--------------------------------------------------

def get_args():    
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-i', metavar='<Network Interface Name>',
                        help='network interface to catch', required=True)
    parser.add_argument('-f', metavar='<Output CSV File>',
                        help='csv file to create', required=True)    
    args = parser.parse_args()
    return args
#--------------------------------------------------

def get_NIC_ID(interface_name):
    result = os.popen("wmic nicconfig get description,settingid").read().split("\n")
    for i in result:
        nic = i.split('         ')
        if interface_name == nic[0]:               
            result = re.search('{(.*)}', nic[1])
            return result.group(1)
    return None

def main():    
    args = get_args()
    
    if len(args.i) > 0 and len(args.f) > 0:
        NIC_ID = get_NIC_ID(args.i)
        if not NIC_ID:
            print('\n\tNetwork Interface Name "{}" does not exist!!!'.format(args.i))        
            print('\n\tTO GET EXACT Network Interface Name, RUN BELOW COMMAND ON CMD:\n\t\twmic nicconfig get description')
            sys.exit(-1)   

        # if os.path.exists(args.f):
        #     print('\n\tOutput csv file "{}" already exists, '
        #         'won\'t overwrite.'.format(args.f),
        #         file=sys.stderr)
        #     sys.exit(-1)

        if install_Scapy_2_4_0() == True:
            print("\nCatching packets livetime...") 
            live2csv(NIC_ID, args.f)
    else:
        print('\n\tNetwork Interface Name & Output CSV File must not be empty!')            
#--------------------------------------------------

if __name__ == '__main__':
    main()