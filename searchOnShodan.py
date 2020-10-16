import requests, urllib3, shodan, sys, xlsxwriter
from time import strftime, gmtime, sleep 
from colorama import init, Fore, Back, Style
init()

def print_action(skk): print(Fore.CYAN + "[*] {}".format(skk) + Style.RESET_ALL) 
def print_red(skk): print(Fore.RED + "[!] {}".format(skk) + Style.RESET_ALL)
def print_green(skk): print(Fore.GREEN + "[*] {}".format(skk) + Style.RESET_ALL)

# searchOnShodan retourne les informations et les vulnérabilités d'un nom de domaine
# On trouve l'adresse IP associée, on questionne shodan et on parse les résultats.

#Pour l'utiliser : ajouter les noms de domaines à étudier dans domaines.txt + vérifier que la clef API shodan est toujours d'actualité 
#(rappel : connexion à shodan puis mon compte => clef api)

#Sortie: fichier output.xlsx format excel

SHODAN_API_KEY= "<clef_shodan_a_renseigner>" #Go on shodan => Mon compte => API KEY
host = []
resolved = []
hostIP = []
targets = []

excel = xlsxwriter.Workbook('output.xlsx') 
worksheet = excel.add_worksheet("Noms de domaines") 

f = open("domaines.txt", "r")

startTime = strftime("%Y-%m-%d %H:%M:%S", gmtime())
print("Start : " + startTime)

for x in f:
        targets.append(x.rstrip())

row=0
col=0

worksheet.write(row,col,"Domaines :")
col += 1
worksheet.write(row,col,"Ip :")
col += 1
worksheet.write(row,col,"Organisation :")
col += 1
worksheet.write(row,col,"Pays :")
col += 1
worksheet.write(row,col,"Ville :")
col += 1
worksheet.write(row,col,"OS :")
col += 1
worksheet.write(row,col,"ASN :")
col += 1
worksheet.write(row,col,"Domaines trouvés :")
col += 1
worksheet.write(row,col,"Ports :")
col += 1
worksheet.write(row,col,"vulnérabilités :")

col=0

for target in targets:
        api = shodan.Shodan(SHODAN_API_KEY)
        dnsResolve = 'https://api.shodan.io/dns/resolve?hostnames=' +  target + '&key=' + SHODAN_API_KEY
        
        try:  
                # First we need to resolve our targets domain to an IP    
                resolved = requests.get(dnsResolve)    
                hostIP = resolved.json()[str(target)]
                # Then we need to do a Shodan search on that IP  
                host = api.host(hostIP)
        except:
                #print_red("Aucun résultat trouvé pour "+target)
                pass

        print_action("Recherche de "+target+" sur shodan")  

        if host:
                doms = ''
                cve_details = ''


                print("IP: %s" % host['ip_str'])  
                print("Organization: %s" % host.get('org', 'n/a')) 
                print("Pays: %s" % host.get('country_name', 'n/a')) 
                print("Ville: %s" % host.get('city', 'n/a')) 
                print("Operating System: %s" % host.get('os', 'n/a'))
                print("ASN: %s" % host.get('asn', 'n/a'))
                for dom in host.get('domains', 'n/a'):
                        doms = doms + dom + ";"
                        print("Domain: %s" % dom) 

                col = 0
                row += 1

                ## Add domain on excel output
                worksheet.write(row,col,target)
                col +=1
                worksheet.write(row,col,host['ip_str']) 

                col +=1
                if type(host.get('org', 'n/a')) == type(None):
                        worksheet.write_string(row,col,"None")
                else:
                        worksheet.write_string(row,col,host.get('org', 'n/a'))

                col +=1
                if type(host.get('country_name', 'n/a')) == type(None):
                        worksheet.write_string(row,col,"None")
                else:
                        worksheet.write_string(row,col,host.get('country_name', 'n/a'))
                
                col +=1
                if type(host.get('city', 'n/a')) == type(None):
                        worksheet.write_string(row,col,"None")
                else:
                        worksheet.write_string(row,col,host.get('city', 'n/a'))

                col +=1
                if type(host.get('os', 'n/a')) == type(None):
                        worksheet.write_string(row,col,"None")
                else:
                        worksheet.write_string(row,col,host.get('os', 'n/a'))

                col +=1
                if type(host.get('asn', 'n/a')) == type(None):
                        worksheet.write_string(row,col,"None")
                else:
                        worksheet.write_string(row,col,host.get('asn', 'n/a'))

                col +=1

                if doms == '':
                        worksheet.write_string(row,col,"None")
                else:
                        worksheet.write_string(row,col,doms)

                col +=1
                # Print all banners
                print_action("Affichage de toutes les bannières:") 
                port_banner = ''
                for item in host['data']:        
                        print("Port: %s" % item['port'])       
                        print("Banner: %s" % item['data'])
                        port_banner = port_banner+str(item['port'])+" \n"
                worksheet.write_string(row,col,port_banner)
                col +=1

                
                # Print vuln information
                try:
                          if host['vulns']:
                                  if len(host['vulns']) > 0:              
                                          print_action("Affichage de toutes les vulnérabilités trouvées:")
                                  else:
                                          print_red("Aucune vulnérabilité trouvé pour "+target)
                                          pass
                                  for number in range(len(host['data'])):
                                          try:
                                                  if host['data'][number]["vulns"]:
                                                          for CVE in host['data'][number]["vulns"]: 
                                                                  print_green('vulnérabilité : {0} - CVSS : {1}'.format(CVE, host['data'][number]["vulns"][CVE]['cvss']))
                                                                  print(host['data'][number]["vulns"][CVE]['summary'])
                                                                  cve_details = cve_details + CVE +"- CVSS: "+str(host['data'][number]["vulns"][CVE]['cvss'])+" \n"
                                                          worksheet.write_string(row,col,cve_details)
                                          except:
                                                  pass
                except:
                          print_red("Aucune vulnérabilité trouvé pour "+target) 
                          pass
        else:
          print_red("Problème avec : "+target+"- On relance la requête.")
          targets.append(target)
excel.close()
