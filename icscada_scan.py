import nmap
import sys
import inquirer

selectionScan = [
  inquirer.List('ScanType',
                message="What Scan Type do you need?",
                choices=['Shodan', 'Netdiscover','Open Port Detection', 'Snmp-check', 'Siemens S7 ','ATG INFO','PLC SCAN','Modicon SCAN','Modbus', 'PCAP','Quit'],
            ),
]
answers = inquirer.prompt(selectionScan)
print(answers)

if(answers['ScanType'] == "Shodan"):
    print("in if")

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

def get_ipaddress():
    sys.stdout.write("Enter IP Address For Scan:")
    sys.stdout.flush()
    ip=sys.stdin.readline()
    print("the IP Address you Entered:"+ip)
    return ip

def OpenPortDetection(ip):
    return 0
'''
ipaddress = get_ipaddress()
nm = nmap.PortScanner()
scanInfo=nm.scan(ipaddress, '443')
nm.command_line()
print(scanInfo)
selection = inquirer.prompt(selectionScan)
print(selection["ScanType"])  
'''
