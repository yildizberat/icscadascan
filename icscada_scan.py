import nmap
import sys
import inquirer
import scapy.all as scapy
import pandas as pd
import shodan
import os
import csv
import requests
from requests.exceptions import RequestException


ACD_ADAPTED_SHODAN_QUERY_FILE_NAME = "ACD_ADAPTED_SHODAN_QUERY_FILE.txt"
SHODAN_API_KEY = ""
SHODAN_OUTPUT_FILES_LOCATION = "./shodan_output_files"

def banner():
    font="""
              _____ _____  _____    _______  _____          _____             _____  _____          _   _ _   _ ______ _____  
             |_   _/ ____|/ ____|  / / ____|/ ____|   /\   |  __ \   /\      / ____|/ ____|   /\   | \ | | \ | |  ____|  __ \ 
               | || |    | (___   / / (___ | |       /  \  | |  | | /  \    | (___ | |       /  \  |  \| |  \| | |__  | |__) |
               | || |     \___ \ / / \___ \| |      / /\ \ | |  | |/ /\ \    \___ \| |      / /\ \ | . ` | . ` |  __| |  _  / 
              _| || |____ ____) / /  ____) | |____ / ____ \| |__| / ____ \   ____) | |____ / ____ \| |\  | |\  | |____| | \ \ 
             |_____\_____|_____/_/  |_____/ \_____/_/    \_\_____/_/    \_\ |_____/ \_____/_/    \_\_| \_|_| \_|______|_|  \_\

             Created by Bandini                                                                           Github:/yildizberat                                                                               
                                                                                                                  

        """
    print(font)
banner()
def list_ICSProtoPort():
    df = pd.read_csv('./icsprotoport2.csv',sep=';')
    pd.set_option('display.max_rows', df.shape[0]+1)
    print(df)
    return 0

def get_ipaddress():
    sys.stdout.write("Enter IP Address For Scan:")
    sys.stdout.flush()
    ip=sys.stdin.readline()
    print("the IP Address you Entered:"+ip)
    return ip

def sniff():
   import sniffer
   return sniffer

def get_port():
    sys.stdout.write("Enter Port For Check:")
    sys.stdout.flush()
    port=sys.stdin.readline()
    print("the Port you Entered:"+port)
    return port

def CheckPort():
    ip_address = get_ipaddress()
    port= get_port()
    nmScan = nmap.PortScanner()
    nmScan.scan(ip_address, port)
    for host in nmScan.all_hosts():
        print('Host : %s (%s)' % (host, nmScan[host].hostname()))
        print('State : %s' % nmScan[host].state())
        for proto in nmScan[host].all_protocols():
            print('----------')
            print('Protocol : %s' % proto)
 
            lport = nmScan[host][proto].keys()
      
            for port in lport:
                print('port : %s\tstate : %s' % (port, nmScan[host][proto][port]['state']))

def netDiscover():
    ip_address= get_ipaddress()
    arp_req = scapy.ARP(pdst=ip_address)
    broadcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_broadcast= broadcast /arp_req
    answ_list= scapy.srp(arp_req_broadcast, timeout=1,verbose=False)[0] 
    clients_list=[]
    for listelement in answ_list:
        client_dict={"ip": listelement[1].psrc, "mac": listelement[1].hwsrc}
        clients_list.append(client_dict)
    print("IP\t\t\tMAC Address\n-----------------------------------------------")
    for client in clients_list:
        print(client["ip"] + "\t\t" + client["mac"])
    return 0

def shodan_fnc():
    print("Please Enter the Shodan API KEY")
    SHODAN_API_KEY=input()
    ip_list = input("Please enter ip(s) sperated by commas: ")
    ips = ip_list.split(',')
    api=shodan.Shodan(SHODAN_API_KEY)
    for ip in ips:
        try:
            resutls=api.host(ip)
            print("Open Port for %s:" %ip)
            for port in resutls['ports']:
                print(port)
        except shodan.APIError as e:
            print("Error: %s" %e) 
    return 0


def acd_adapted_read_shodan_query_file():
    splitted_list_data = []
    with open(ACD_ADAPTED_SHODAN_QUERY_FILE_NAME, "r") as file_data:
        file_data_lines = file_data.readlines()
        for file_data_line in file_data_lines:
            splitted_list_data.append(file_data_line.split("|"))
    return splitted_list_data


def acd_adapted_query_shodan(splitted_list_data):
    shodan_query_data_row = {}
    shodan_output_file_names = []


    for splitted_list_data_part in splitted_list_data:
        shodan_query_data_row["Vendor"] = splitted_list_data_part[0]
        shodan_query_data_row["Query"] = splitted_list_data_part[1].rstrip("\n")
        os.system(f'shodan init {SHODAN_API_KEY}')
        os.system(f'shodan download {shodan_query_data_row["Vendor"]} {shodan_query_data_row["Query"]}')
        os.system(f'shodan convert --fields ip_str,port,transport {shodan_query_data_row["Vendor"]}.json.gz csv')

        df = pd.read_csv(f'{shodan_query_data_row["Vendor"]}.csv')
        new_column = pd.DataFrame({'Vendor': [shodan_query_data_row["Vendor"] for i in range(df.shape[0])], 'Query': [shodan_query_data_row["Query"] for i in range(df.shape[0])]})
        new_column = new_column.merge(df, left_index=True, right_index=True)
        os.system("mkdir shodan_output_files")
        new_column.rename(columns={'ip_str': 'IP', 'port': 'Port', 'transport': 'Protocol'}, inplace=True)
        new_column.to_csv(f'{SHODAN_OUTPUT_FILES_LOCATION}/{shodan_query_data_row["Vendor"]}.csv', index=False)
        shodan_output_file_names.append(f'{SHODAN_OUTPUT_FILES_LOCATION}/{shodan_query_data_row["Vendor"]}.csv')

    return shodan_output_file_names


# Function to process each line of CSV data
def process_csv_row(row):
    ip_str_data = row[2]
    port_str_data = row[3]
    protocol_data = row[4]
    print("Processing {}".format(row))

    if "tcp" in protocol_data:
        http_status_code = None
        https_status_code = None

        # Check HTTP
        try:
            http_status_code = requests.get(f"http://{ip_str_data}:{port_str_data}", verify=False,
                                            timeout=5).status_code
        except RequestException:
            http_status_code = 'Unavailable'

        # Check HTTPS
        try:
            https_status_code = requests.get(f"https://{ip_str_data}:{port_str_data}", verify=False,
                                             timeout=5).status_code
        except RequestException:
            https_status_code = 'Unavailable'

        # Choose the valid status code if available
        status_code_data = http_status_code if http_status_code != 'Unavailable' else https_status_code
        status_code_data = status_code_data if status_code_data != 'Unavailable' else 'Unavailable'

        return [ip_str_data, port_str_data, protocol_data, str(status_code_data)]

    elif "udp" in protocol_data:
        nmap = nmap3.NmapScanTechniques()
        result = nmap.nmap_udp_scan(ip_str_data, args=f"-Pn -p {port_str_data}")
        result_state = result[ip_str_data]['ports'][0]['state']

        return [ip_str_data, port_str_data, protocol_data, str(result_state)]

    return None


# Remove duplicates based on IP, Port, and Protocol
def remove_duplicates(csv_reader):
    unique_rows = []
    seen = set()
    for row in csv_reader:
        ip_port_protocol = (row[2], row[3], row[4])
        if ip_port_protocol not in seen:
            seen.add(ip_port_protocol)
            unique_rows.append(row)
    return unique_rows


def acd_adapted_add_nmap_status(shodan_input_file_names):
    for input_info in shodan_input_file_names:
        INPUT_CSV_FILE = input_info
        OUTPUT_CSV_FILE = input_info

        # Read the CSV file and process the data
        with open(INPUT_CSV_FILE, 'r') as csv_file:
            csv_reader = csv.reader(csv_file)

            # Remove duplicate rows
            unique_rows = remove_duplicates(csv_reader)

            # Create the output header line
            output_header = ["Vendor", "Query", "IP", "Port", "Protocol", "Status"]

            # Process each row and write to the output CSV file
            with open(OUTPUT_CSV_FILE, 'w', newline='') as output_csv_file:
                csv_writer = csv.writer(output_csv_file)
                csv_writer.writerow(output_header)

                for row in unique_rows:
                    vendor_name, query_name = row[0], row[1]  # Read vendor and query names from each row
                    processed_row = process_csv_row(row)
                    if processed_row:
                        csv_writer.writerow([vendor_name, query_name] + processed_row)


def acd_adapted_main():
    splitted_list_data = acd_adapted_read_shodan_query_file()
    shodan_output_file_names = acd_adapted_query_shodan(splitted_list_data)
    acd_adapted_add_nmap_status(shodan_output_file_names)
    return 0


def snmp_check():
    np = nmap.PortScanner()
    ip_address= get_ipaddress()
    result=np.scan(ip_address,'161-162','-Pn --script=snmp-info')
    print(result)
    return 0

def siemens_SSeven():
    np = nmap.PortScanner()
    ip_address= get_ipaddress()
    result=np.scan(ip_address,'102','-Pn --script=s7-info')
    print(result)
    return 0

def atg_info():
    np = nmap.PortScanner()
    ip_address= get_ipaddress()
    result=np.scan(ip_address,'10001','-Pn --script=./scripts/atg-info.nse')
    print(result)
    return 0

def omrom_scan():
    np = nmap.PortScanner()
    ip_address= get_ipaddress()
    result=np.scan(ip_address,'9600','-Pn --script=omrom-info')
    print(result)
    return 0

def modbus_scan():
    np = nmap.PortScanner()
    ip_address= get_ipaddress()
    result=np.scan(ip_address,'502','-Pn -sT --script=modbus-discover')
    print(result)
    return 0

def main():
    banner()
    selectionScan = [
        inquirer.List('ScanType',
                message="What Scan Type do you need?",
                choices=['ACD Adapted',
                         'Shodan',
                         'List ICS Protocol and Port', 
                         'Netdiscover',
                         'Check Port Detection', 
                         'Snmp-check', 
                         'Siemens S7 ',
                         'ATG INFO',
                         'OMROM SCAN',
                         'Modbus', 
                         'PCAP',
                         'Quit'],
            ),
            ]
    answers = inquirer.prompt(selectionScan)
    print(answers)

    if (answers['ScanType'] == "ACD Adapted"):
        acd_adapted_main()
        main()

    if(answers['ScanType'] == "Shodan"):
        shodan_fnc()
        main()
    
    if(answers['ScanType'] == "List ICS Protocol and Port"):
        list_ICSProtoPort()
        main()

    if(answers['ScanType'] == "Check Port Detection"):
        CheckPort()
        main()

    if(answers['ScanType'] == "Netdiscover"):
        print("Please Enter IP/Subnet\t")
        netDiscover()
        main()

    if(answers['ScanType'] == "Snmp-check"):
        snmp_check()
        main()

    if(answers['ScanType'] == "Siemens S7 "):
        siemens_SSeven()
        main()

    if(answers['ScanType'] == "ATG INFO"):
        atg_info()
        main()

    if(answers['ScanType'] == "OMROM SCAN"):
        omrom_scan()
        main()

    if(answers['ScanType'] == "Modbus"):
        modbus_scan()
        main()

    if(answers['ScanType'] == "PCAP"):
        sniff()
        main()

    if(answers['ScanType'] == "Quit"):
        print('Goodbye!')
        exit()
if __name__ == "__main__":
    
    main()