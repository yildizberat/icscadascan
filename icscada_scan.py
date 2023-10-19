import nmap
import sys
import inquirer

selectionScan = [
  inquirer.List('ScanType',
                message="What Scan Type do you need?",
                choices=['Shodan', 'Netdiscover','Check Port Detection', 'Snmp-check', 'Siemens S7 ','ATG INFO','PLC SCAN','Modicon SCAN','Modbus', 'PCAP','Quit'],
            ),
]
answers = inquirer.prompt(selectionScan)
print(answers)

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


if(answers['ScanType'] == "Shodan"):
    print("in if")

if(answers['ScanType'] == "Check Port Detection"):
    CheckPort()

if(answers['ScanType'] == "Netdiscover"):
    print("in if")

if(answers['ScanType'] == "Snmp-check"):
    print("in if")

if(answers['ScanType'] == "Siemens S7 "):
    print("in if")

if(answers['ScanType'] == "ATG INFO"):
    print("in if")

if(answers['ScanType'] == "PCL SCAN"):
    print("in if")

if(answers['ScanType'] == "Modicon SCAN"):
    print("in if")

if(answers['ScanType'] == "Modbus"):
    print("in if")

if(answers['ScanType'] == "PCAP"):
    print("in if")

if(answers['ScanType'] == "Quit"):
    exit()




'''


scanInfo=nm.scan(ipaddress, '443')
nm.command_line()
print(scanInfo)
'''
