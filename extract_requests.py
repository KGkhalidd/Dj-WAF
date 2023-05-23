import os
import django
# Set environment variable > Django settings
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'waf.settings')
django.setup()

import json 
# Read the file containing the requests
file_path = "F:\projects\djWAF\src\waf.txt"
with open(file_path, "r") as file:
    requests_data = file.readlines()

# Initialize variables to store extracted data
paths = []
endpoints = []
methods = []
body_data = []

# Process each request
for request_str in requests_data:
    # Parse the request string as JSON
    request = json.loads(request_str)

    # Extract the desired information
    path = request.get("path")
    method = request.get("method")
    body_params = request.get("body_params")

    # Generate the endpoint by combining method and path
    endpoint = f"{method} {path}"

    # Store the extracted data
    paths.append(path)
    endpoints.append(endpoint)
    methods.append(method)
    body_data.append(body_params)

# Generate the HTML output
html_output = "<html><head><title>Request Data</title></head><body><table>"
html_output += "<tr><th>Path</th><th>Endpoint</th><th>Method</th><th>Body Data</th></tr>"

for i in range(len(paths)):
    html_output += "<tr>"
    html_output += f"<td>{paths[i]}</td>"
    html_output += f"<td>{endpoints[i]}</td>"
    html_output += f"<td>{methods[i]}</td>"
    html_output += f"<td>{json.dumps(body_data[i])}</td>"
    html_output += "</tr>"

html_output += "</table></body></html>"

# Save the HTML output to a file
output_file_path = "haha.html"
with open(output_file_path, "w") as output_file:
    output_file.write(html_output)

request_length = len(paths)
print(request_length)