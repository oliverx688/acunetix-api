# acunetix-api
Leverage https://github.com/jenkinsci/acunetix-plugin/blob/master/src/main/java/com/acunetix/Engine.java

The api provided in it is rewritten from

Globally depends on the obtained api-key
````
headers = {"X-Auth":apikey,"content-type": "application/json"}
````
1. Add tasks
````
post /api/v1/targets

data = {"address":url,"description":url,"criticality":"10"}
````
2. Scanning tasks
````
post /api/v1/scans

data = {"target_id":target_id,"profile_id":"11111111-1111-1111-1111-111111111111","schedule": {"disable": False,"start_date":None,"time_sensitive": False}}
````
target_id is the result returned by the first step of adding the task


3. Get task summary
````
get /api/v1/scans
````
4. Get task details
````
get /api/v1/scans/+scan_id
````
5. Delete Scan
````
DELETE /api/v1/scans/+scan_id
````
Reference for details

http://0cx.cc/about_awvs11_api.jspx