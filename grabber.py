import requests
import re

pattern_hashes = "^[a-f0-9]{64}$"
pattern_url = "https?:\/\/.*"
pattern_ip = "(?:(?:\d|[01]?\d\d|2[0-4]\d|25[0-5])\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d|\d)(?:\/\d{1,2})?"
pattern_domain = "^[a-zA-Z0-9][a-zA-Z0-9-_]{0,61}[a-zA-Z0-9]{0,1}\.([a-zA-Z]{1,6}|[a-zA-Z0-9-]{1,30}\.[a-zA-Z]{2,3})$"

headers = {
  'Accept': 'application/json'
}

r = requests.get('https://labs.inquest.net/api/iocdb/list', headers = headers)
j = r.json()

def ioc_grabber(fileHandle, pattern, data, notUseRegular=False):
  if notUseRegular:    
    writerHandle(fileHandle, data)
    return

  sections = re.findall(pattern, data, re.DOTALL)
  if any(isinstance(e, str) and len(e) > 0 for e in sections):
    writerHandle(fileHandle, "\n".join(sections))

def writerHandle(fileHandle, data):
  fileHandle.write(data)
  fileHandle.write('\n')


with open("links.txt", "a") as links:
  with open("hashes.txt", "a") as ioc_hash:
    with open("urls.txt", "a") as ioc_url:
      with open("ip.txt", "a") as ioc_ip:
        with open("domains.txt", "a") as ioc_domain:

          for each in (j['data']):
            ioc_grabber(links, None, each['reference_link'], True)
            ioc_grabber(ioc_hash, pattern_hashes, each['artifact'])
            ioc_grabber(ioc_url, pattern_url, each['artifact'])
            ioc_grabber(ioc_ip, pattern_ip, each['artifact'])
            ioc_grabber(ioc_domain, pattern_domain, each['artifact'])
          
          ioc_domain.close()
        ioc_ip.close()
      ioc_url.close()
    ioc_hash.close()
  links.close()
