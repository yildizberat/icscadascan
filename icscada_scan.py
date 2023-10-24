import nmap
import sys
import inquirer
import scapy.all as scapy
import pandas as pd
import shodan

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

def main():
    selectionScan = [
        inquirer.List('ScanType',
                message="What Scan Type do you need?",
                choices=['Shodan','List ICS Protocol and Port', 'Netdiscover','Check Port Detection', 'Snmp-check', 'Siemens S7 ','ATG INFO','PLC SCAN','Modicon SCAN','Modbus', 'PCAP','Quit'],
            ),
            ]
    answers = inquirer.prompt(selectionScan)
    print(answers)

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
        print("in if")
        main()

    if(answers['ScanType'] == "Siemens S7 "):
        print("in if")
        main()

    if(answers['ScanType'] == "ATG INFO"):
        print("in if")
        main()

    if(answers['ScanType'] == "PCL SCAN"):
        print("in if")
        main()

    if(answers['ScanType'] == "Modicon SCAN"):
        print("in if")
        main()

    if(answers['ScanType'] == "Modbus"):
        print("in if")
        main()

    if(answers['ScanType'] == "PCAP"):
        print("in if")
        main()

    if(answers['ScanType'] == "Quit"):
        exit()
if __name__ == "__main__":
    main()
