import requests
from requests import Response
import concurrent

def get_location(ip):
   Response = requests.get("https://ipinfo.io/"+ip+"/json")
   if Response.status_code ==  200 :
      print(Response.json())




if __name__ == '__main__' :
   print(get_location('109.199.110.135'))
    



