from colorama import init, Fore, Back, Style
import requests
import json
import argparse
import socket
import time
import urllib3
import subprocess
import os
import sys
import nmap

init(autoreset=True)

print(Back.BLACK + Fore.GREEN + r'''
	            ,----------------,           ,---------,
        ,-----------------------,          ,"        ,"|
      ,"                      ,"|        ,"        ,"  |
     +-----------------------+  |      ,"        ,"    |
     |  .-----------------.  |  |     +---------+      |
     |  |                 |  |  |     | -==----'|      |
     |  |    Automation   |  |  |     |         |      |
     |  |         Tool    |  |  |/----|`---=    |      |
     |  |                 |  |  |   ,/|==== ooo |      ;
     |  |                 |  |  |  // |(((( [14]|    ,"
     |  `-----------------'  |," .;'| |((((     |  ,"
     +-----------------------+  ;;  | |         |,"
        /_)______________(_/  //'   | +---------+
   ___________________________/___  `,
  /  oooooooooooooooo  .o.  oooo /,   \,"-----------
 / ==ooooooooooooooo==.o.  ooo= //   ,`\--{)B     ,"
/_==__==========__==_ooo__ooo=_/'   /___________,"
`-----------------------------''')


def args_parser():
    # parse required argument/s needed for program
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--ip', type=str, required=True, help='IP address (e.g., 8.8.8.8)')
    args = parser.parse_args()
    return args

def ip_to_domain(ip_address):
    try:
        domain_name = socket.gethostbyaddr(ip_address)[0]
        return domain_name
    except socket.herror:
        return None

active_subdomains = []
nameservers = []

class Abuse_certificate_transparency:
    def __init__(self):
        args = args_parser()
        self.ip = args.ip
        self.domain = ip_to_domain(self.ip)
        if not self.domain:
            print(f'Invalid IP address or no domain found for IP: {self.ip}')
            sys.exit(1)

    def parse_url(self):
        # parse host from scheme, to use for certificate transparency abuse
        try:
            host = urllib3.util.url.parse_url(f'http://{self.domain}').host
        except Exception as e:
            print(f'Invalid IP, try again...')
            sys.exit(1)
        return host

    def request_json(self):
        # request json data to get list of registered subdomains with cert trans records
        subdomains = []
        try:
            r = requests.get(f'https://crt.sh/?q=%.{self.parse_url()}&output=json')
            if r.status_code != 200:
                print('{!} host status-code: %s\n ~ unable to access records using this abuse certificate transparency method' % (r.status_code))
            else:
                try:
                    json_data = json.loads(r.text)
                    for sub in json_data:
                        if sub not in subdomains:
                            subdomains.append(sub['name_value'])
                except Exception as e:
                    print(f'json_data:Error {e}')
                    pass
        except Exception as e:
            print(f'request_json//Error: {e}')
            pass
        return set(subdomains)
          

    def active_subs(self):
        # check registered subdomains to see if active or not
        global active_subdomains

        for sub in self.request_json():
            try:
                sub = socket.gethostbyname_ex(sub)
                if sub in active_subdomains:
                    pass
                else:
                    active_subdomains.append(sub)
            except:
                continue
        number_all = len(self.request_json())
        number_active = len(active_subdomains)

        Style.RESET_ALL

        try:
            print('\n', Fore.GREEN + '''\n\n{!} There are %s %s %s''' %
                (Fore.RED + Back.BLACK + str(number_all), Fore.RED + Back.BLACK + 'REGISTERED', Fore.GREEN + 'subdomains for this domain.'))
            

            index = Fore.GREEN + Back.BLACK + str('INDEX:green')
            sub_red = Fore.RED + Back.BLACK + str('SUBDOMAIN:red')
            line = Fore.CYAN + Back.BLACK + str('*****************************')
            print('\n%s\n%s %s\n%s\n' % (line, index, sub_red, line))


            for index, sub in enumerate(self.request_json()):
                print(Fore.GREEN + str(index + 1), Fore.RED + str(sub))

            print('\n', Fore.GREEN + '''\n\n{!} There are %s %s %s''' %
                (Fore.RED + Back.BLACK + str(number_active), Fore.RED + Back.BLACK + 'ACTIVE', Fore.GREEN + 'subdomains for this domain.'))
         

            index = Fore.GREEN + Back.BLACK + str('INDEX:green')
            dns_white = Fore.WHITE + Back.BLACK + str('DNS SERVER:white')
            sub_red = Fore.RED + Back.BLACK + str('SUBDOMAIN:red')
            ip_yell = Fore.BLUE + Back.BLACK + str('IP_ADDR:blue')
            line = Fore.CYAN + Back.BLACK + str('************************************************************')
            print('\n%s\n%s %s %s %s\n%s\n' % (line, index, dns_white, sub_red, ip_yell, line))
    
            for index, sub in enumerate(active_subdomains):
                print(Fore.GREEN + str(index + 1), Fore.WHITE + Back.BLACK + str(sub[0]), Fore.RED + Back.BLACK + str(sub[1]), Fore.BLUE + Back.BLACK + str(sub[2]))

        except Exception as e:
            print(f'active_subdomains//Error: {e}')
            pass

        return active_subdomains

class Dns_zone_transfer:
    def __init__(self, ip):
        self.domain = abuse.parse_url()
        self.ip = ip

    def nslookup(self):
        global nameservers
        # nslookup to find nameservers of target domain
        dns_white = Fore.RED + Back.BLACK + str('Dns records')
        sec_bit = Fore.GREEN + Back.BLACK + str('for this domain.\n')
        print(Fore.GREEN + Back.BLACK + str('\n\n\n{!} %s %s' % (dns_white, sec_bit)))
        line = Fore.CYAN + Back.BLACK + str('************************************************************')
        records = Fore.GREEN + Back.BLACK + str('DNS RECORDS:green')
        print('%s\n%s\n%s\n' % (line, records, line))
        try:
            result = subprocess.run(['nslookup', '-type=ns', self.domain], capture_output=True, text=True)
            nslookup_output = result.stdout
            for line in nslookup_output.splitlines():
                if 'nameserver' in line:
                    ns = line.split()[-1]
                    nameservers.append(ns)
                    print(Fore.GREEN + f'Nameserver: {ns}')
        except Exception as e:
            print(f'nslookup//Error: {e}')

    

    def nmap_scan(self):
        nm = nmap.PortScanner()
        nm.scan(hosts=self.ip, arguments='-sV -Pn -T4')

        for host in nm.all_hosts():
            print(f"Host : {host} ({nm[host].hostname()})")
            print(f"State : {nm[host].state()}")

            for proto in nm[host].all_protocols():
                print("----------")
                print(f"Protocol : {proto}")

                lport = nm[host][proto].keys()
                for port in lport:
                    print(f"port : {port}\tstate : {nm[host][proto][port]['state']}\tName : {nm[host][proto][port]['name']}")


if __name__ == '__main__':
    # Check requirements are met, eg. install python modules
    
    abuse = Abuse_certificate_transparency()
    abuse.active_subs()

    dns = Dns_zone_transfer(abuse.ip)
    dns.nslookup()
    dns.nmap_scan()

    