from shodan import Shodan
from shodan.cli.helpers import get_api_key
import csv
data = ["IP","CVE","PORT","CVSS"]
api = Shodan(get_api_key())
with open('Shodan.csv','w') as file:
    writer = csv.writer(file)
    writer.writerow(data)
limits = 5
i = 0
results = api.search('org:telenor has_vuln:true country:dk', limit=limits)
print('Results found: {}'.format(results['total']))
for result in results['matches']:
    i = i+1
    print(result['vulns'])
    print('IP {}'.format(result['ip_str']))
    print(result['port'])
    print('PORT {}'.format(result['port']))
    for item in result['vulns']:
        CVE = item.replace('!','')
        print('Vulns: %s' % item)
        print('CVSS: {}'.format(result['vulns'][item]['cvss']))
        data = [result['ip_str'], item,result['port'], result['vulns'][item]['cvss']]
        with open('Shodan.csv', 'a') as file:
            writer = csv.writer(file)
            writer.writerow(data)