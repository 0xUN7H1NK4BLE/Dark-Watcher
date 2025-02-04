import subprocess
from openai import OpenAI
import json
import re
import socket
from pyvis.network import Network
import os
import requests
import validators
from datetime import datetime
import plotly.graph_objects as go
import time
from flask import Flask, render_template, request, redirect, url_for, flash

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'

client = OpenAI(
    base_url = 'http://localhost:11434/v1',
    api_key='ollama', # required, but unused
)

@app.template_filter('timestamp_to_date')
def timestamp_to_date(value):
    try:
        timestamp = int(float(value)) / 1000  # Convert ms to seconds
        return datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
    except ValueError:
        return "Invalid timestamp"
    
# Function to get subdomains using sublist3r
def get_subdomains(domain):
    try:
        subprocess.run(["mkdir", "-p", f"data/{domain}"])
        subprocess.run(["subfinder", "-silent", "-r", "8.8.8.8,1.1.1.1", "-d", domain, "-o", f"data/{domain}/subfinder_{domain}.txt"])
        # subprocess.run(["findomain", "-t", domain, "-u", f"data/{domain}/findomain_{domain}.txt"])
        # subprocess.run(["amass", "enum", "-passive", "-d", domain, "-o", f"data/{domain}/amassp_{domain}.txt"])
        input_files = f"data/{domain}/*"
        output_file = f"data/{domain}/subdomains_{domain}.txt"
        
        # Run the cat and sort commands
        cat_command = f"cat {input_files}"
        sort_command = "sort -u"
        
        # Use subprocess to run the command and redirect output to a file
        with open(output_file, "w") as outfile:
            subprocess.run(f"{cat_command} | {sort_command}", shell=True, stdout=outfile)

            subprocess.run(["cat", f"data/{domain}/*","|","sort","-u",">", f"data/{domain}/subdomains_{domain}.txt"])
        scan_ports(domain)
    except Exception as e:
        return str(e)

def data_parser(main_domain, data_httpx_file):
    print(f"Processing data from {data_httpx_file}...")
    parsed_data = {}
    try:
        with open(data_httpx_file, 'r') as file:
            for line in file:
                if line.strip():
                    entry = json.loads(line)
                    domain = entry.get('input', 'Unknown domain')
                    technologies = entry.get('tech', [])
                    parsed_data[domain] = technologies if technologies else ['No technologies detected']
    except FileNotFoundError:
        print(f"File not found: {data_httpx_file}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    
    output_dir = f"data/{main_domain}"
    os.makedirs(output_dir, exist_ok=True)
    
    # Convert the dictionary to a JSON string before writing to the file
    with open(f"{output_dir}/buildwith_{main_domain}.txt", "w") as outfile:
        outfile.write(json.dumps(parsed_data, indent=4))
        
    return parsed_data


def buildwith(main_domain, domain_file):
    data = {}  # Dictionary to store domain -> info mappings
    try:
        with open(domain_file, 'r') as file:
            for line_number, line in enumerate(file, start=1):
                domain = line.strip()
                print(f"Processing domain ({line_number}): {domain}...")
                if domain:  # Skip empty lines
                    try:
                        # Ensure the directory exists before running httpx
                        output_dir = os.path.join("data", main_domain)
                        os.makedirs(output_dir, exist_ok=True)

                        # Define the output file path
                        output_file = os.path.join(output_dir, f"httpx_{main_domain}.json")

                        # Construct the command with echo and pipe
                        command = f"echo {domain} | httpx -silent -json | tee -a {output_file}"
                        
                        # Use subprocess to run the command
                        subprocess.run(command, shell=True, check=True)

                        # Read the output JSON file and load its content
                        with open(output_file, 'r') as json_file:
                            info = json.load(json_file)
                            data[domain] = info  # Store the result in the dictionary

                    except subprocess.CalledProcessError as e:
                        print(f"Error running httpx for {domain}: {e}")
                        data[domain] = {"error": "httpx execution failed"}
                    except json.JSONDecodeError:
                        print(f"Error decoding JSON for {domain}.")
                        data[domain] = {"error": "Failed to parse JSON"}
                    except Exception as e:
                        print(f"Error processing {domain}: {e}")
                        data[domain] = {"error": str(e)}  # Log error for the domain

    except FileNotFoundError:
        print(f"File not found: {domain_file}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    
    
    

    return data_parser(main_domain,f"data/{main_domain}/httpx_{main_domain}.json")



def scan_ports(domain):
    try:
        # naabu -list hosts.txt
        subprocess.run(["naabu", "-list", f"data/{domain}/subdomains_{domain}.txt", "-silent", "-o", f"data/{domain}/naabu_{domain}.txt"])
    except Exception as e:
        return str(e)
    
static_dir = os.path.join(os.getcwd(), 'static')
if not os.path.exists(static_dir):
    os.makedirs(static_dir)


def resolve_subdomains_from_file(domain,file_path):
    print(f"Resolving subdomains from {file_path}...")
    resolved_subdomains = {}
    
    try:
        with open(file_path, 'r') as file:
            # Read each line (subdomain) from the file
            for line in file:
                subdomain = line.strip()  # Remove any extra whitespace or newline
                
                if subdomain:
                    try:
                        # Resolve the subdomain to its IP address
                        ip_address = socket.gethostbyname(subdomain)
                        resolved_subdomains[subdomain] = ip_address 
                        with open(f"data/{domain}/resolved_subdomains_{domain}.txt", "a") as outfile:
                            outfile.write(f"{subdomain}:{ip_address}\n")
                    except socket.gaierror as e:
                        # If the subdomain cannot be resolved, store the error message
                        resolved_subdomains[subdomain] = f"Error resolving: {e}"
    
    except FileNotFoundError:
        print(f"Error: The file {file_path} does not exist.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    
    return resolved_subdomains


# Function to create an interactive pie chart for subdomains
def create_subdomain_pie_chart(domain, static_dir="static"):
    input_file = f"data/{domain}/resolved_subdomains_{domain}.txt"
    
    if not os.path.exists(input_file):
        raise FileNotFoundError(f"Resolved subdomain file not found: {input_file}")
    
    # Read the resolved subdomains
    subdomain_ip_map = {}
    with open(input_file, 'r') as file:
        for line in file:
            if ":" in line:
                subdomain, ip = line.strip().split(":")
                subdomain_ip_map[subdomain] = ip
    
    # Create a Pyvis network
    net = Network(
        height="800px",  # Increased size
        width="100%",    # Full width
        bgcolor="#FFFFFF",  # White background
        font_color="black",
        notebook=False,
        directed=False,
    )
    
    # Add nodes and edges with clearer colors
    for subdomain, ip in subdomain_ip_map.items():
        # Add subdomain nodes with a distinct color
        net.add_node(subdomain, label=subdomain, color="#4A90E2", title=f"Subdomain: {subdomain}")  # Light blue
        # Add IP nodes with another color
        net.add_node(ip, label=ip, color="#D94F4F", title=f"IP: {ip}")  # Red
        # Connect subdomain to IP with a gray edge
        net.add_edge(subdomain, ip, color="gray")
    
    # JSON configuration for the network options
    options = {
        "nodes": {
            "borderWidth": 2,
            "borderWidthSelected": 3,
            "font": {
                "size": 16
            }
        },
        "edges": {
            "color": {
                "inherit": True
            },
            "smooth": {
                "type": "continuous"
            }
        },
        "physics": {
            "forceAtlas2Based": {
                "gravitationalConstant": -50,
                "centralGravity": 0.01,
                "springLength": 150,  # Increased spring length
                "springConstant": 0.08,
                "damping": 0.4
            },
            "minVelocity": 0.75,
            "solver": "forceAtlas2Based"
        }
    }

    # Convert the dictionary to a JSON string and set options
    net.set_options(json.dumps(options))

    # Ensure the static directory exists
    if not os.path.exists(static_dir):
        os.makedirs(static_dir)

    # Save the interactive HTML file
    output_file = os.path.join(static_dir, f"subdomain_pie_{domain}.html")
    net.save_graph(output_file)
    
    return output_file  # Return the full path to the saved file

# Function to create an interactive pie chart for open ports
def create_ports_pie_chart(ports, domain):
    labels = list(ports.keys())
    values = list(ports.values())
    
    fig = go.Figure(data=[go.Pie(labels=labels, values=values, hole=0.3)])
    fig.update_layout(title=f"Open Ports for {domain}")
    
    # Save Plotly chart to the static folder
    ports_chart_path = os.path.join(static_dir, f'ports_pie_{domain}.html')
    fig.write_html(ports_chart_path)
    return f"ports_pie_{domain}.html"  # Return the relative path

# Function to parse subdomains file and count occurrences
def parse_subdomains_file(domain):
    subdomains = {}
    subdomain_file_path = f"data/{domain}/subdomains_{domain}.txt"
    
    if os.path.exists(subdomain_file_path):
        with open(subdomain_file_path, 'r') as file:
            for line in file:
                subdomain = line.strip()
                if subdomain in subdomains:
                    subdomains[subdomain] += 1
                else:
                    subdomains[subdomain] = 1
    return subdomains

# Function to parse open ports file and count occurrences
def parse_ports_file(domain):
    ports = {}
    ports_file_path = f"data/{domain}/naabu_{domain}.txt"
    
    if os.path.exists(ports_file_path):
        with open(ports_file_path, 'r') as file:
            for line in file:
                _, port = line.strip().split(":")
                if port in ports:
                    ports[port] += 1
                else:
                    ports[port] = 1
    return ports
def format_response(data):
    formatted_response = ""
    domain = data['domain']
    compromised = data['compromised']
    subdomains = data['subdomains']

    for subdomain_info in subdomains:
        subdomain = subdomain_info['subdomain']
        breach_count = subdomain_info['count']
        index_time_min = datetime.utcfromtimestamp(
            int(float(subdomain_info['index_time']['min']) / 1000)
        ).strftime('%Y-%m-%d')
        index_time_max = datetime.utcfromtimestamp(
            int(float(subdomain_info['index_time']['max']) / 1000)
        ).strftime('%Y-%m-%d')

        countries = subdomain_info['countries']
        country_list = ', '.join([country['code'] for country in countries])

        formatted_response += f"{subdomain}: {breach_count} breaches\n"
        formatted_response += f"From {index_time_min} to {index_time_max}\n"
        formatted_response += f"Countries with the most breaches:\n{country_list}\n\n"
        with open(f"data/{domain}/hackedlist_{domain}.txt", "w") as outfile:
            outfile.write(formatted_response)

    return formatted_response.strip()


def hackedlist(domain):
    url = "https://hackedlist.io/api/domain"
    params = {"domain": f"{domain}"}
    headers = {
        "accept": "*/*",
        "accept-language": "en-US,en;q=0.8",
        "priority": "u=1, i",
        "referer": "https://hackedlist.io/",
        "sec-ch-ua": '"Brave";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Linux"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "sec-gpc": "1",
        "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    }

    response = requests.get(url, headers=headers, params=params)

    if response.status_code == 200:
        data = response.json()
        
    else:
        flash((f"Error: {response.status_code}, {response.text}"), "danger")
        # with open(output_file, "w").json.dump(data, file, indent=4)
    output_path = f"data/{domain}/hackedlist_{domain}.json"
    with open(output_path, "w") as file:
        json.dump(data, file, indent=4)

    return format_response(data)

def is_domain_scanned(domain):
    scan_file = f"data/scanned_domains"
    if os.path.exists(scan_file):
        with open(scan_file, 'r') as file:
            for line in file:
                if domain in line:
                    return True


def create_file_for_openai(domain):
    """
    Reads the necessary files for the given domain and creates a summary file
    for OpenAI analysis.
    """
    try:
        # Read input files
        files = {
            "naabu": f"data/{domain}/naabu_{domain}.txt",
            "hackedlist": f"data/{domain}/hackedlist_{domain}.txt",
            "buildwith": f"data/{domain}/buildwith_{domain}.txt",
            "resolved": f"data/{domain}/resolved_subdomains_{domain}.txt",
        }

        content_data = {}
        for key, path in files.items():
            if os.path.exists(path):
                with open(path, "r") as file:
                    content_data[key] = file.read()
            else:
                content_data[key] = f"No breach found for {domain}"

        # Define the content to write
        content = f"""
These are the open ports of different subdomains of {domain}:
{content_data['naabu']}

The technologies used by these subdomains are:
{content_data['buildwith']}

These domains resolve to these IP addresses:
{content_data['resolved']}

This is the result of past hack data of the domain:
{content_data['hackedlist']}

this is the result of secutity headers used or not used by the domain:
{check_security_headers(domain)}

"""

        # Write to a new file
        output_file = f"data/{domain}/summary_{domain}.txt"
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, "w") as file:
            file.write(content)

        return output_file

    except Exception as e:
        print(f"Error while creating summary file: {e}")
        return None

def check_security_headers(domain):
    try:
        # Ensure the URL has a scheme (http or https)
        if not domain.startswith("http://") and not domain.startswith("https://"):
            domains = "https://" + domain
        
        # Send an HTTP GET request to the domain
        response = requests.get(domains, timeout=10)
        headers = response.headers

        # Define security headers to check for, with their importance weight
        security_headers = {
            "Strict-Transport-Security": 3,  # HSTS (High importance)
            "Content-Security-Policy": 3,   # CSP (High importance)
            "X-Content-Type-Options": 2,   # MIME type sniffing (Moderate importance)
            "X-Frame-Options": 2,          # Clickjacking protection (Moderate importance)
            "X-XSS-Protection": 1,         # XSS protection (Low importance, deprecated)
            "Referrer-Policy": 2,          # Referrer information control (Moderate importance)
            "Permissions-Policy": 2        # Feature policy (Moderate importance)
        }

        # Analyze the headers and prepare the results
        results = {}
        total_weight = sum(security_headers.values())
        obtained_weight = 0

        for header, weight in security_headers.items():
            if header in headers:
                results[header] = headers[header]
                obtained_weight += weight
            else:
                results[header] = "Missing"

        # Calculate weighted rating percentage
        rating_percentage = (obtained_weight / total_weight) * 100

        # Assign a grade based on the weighted percentage
        if rating_percentage >= 95:
            grade = "A+"
        elif rating_percentage >= 85:
            grade = "A"
        elif rating_percentage >= 75:
            grade = "B+"
        elif rating_percentage >= 65:
            grade = "B"
        elif rating_percentage >= 50:
            grade = "C"
        else:
            grade = "F"

        output = {
            "domain": domain,
            "headers": results,
            "rating": f"{rating_percentage:.2f}%",
            "grade": grade
        }
        with open(f"data/{domain}/security_headers_{domain}.json", "w") as file:
            json.dump(output, file, indent=4)
        # Return results as a JSON object
        return output
    except requests.exceptions.RequestException as e:
        return json.dumps({"error": f"Could not connect to {domain}. Error: {str(e)}"}, indent=4)


def ai_response(domain):
    """
    Sends domain analysis data to the OpenAI API and processes the response, retrying until valid JSON is received.
    """
    try:
        # Step 1: Prepare data for analysis
        summary_file_path = create_file_for_openai(domain)
        if not summary_file_path or not os.path.exists(summary_file_path):
            raise FileNotFoundError(f"Summary file not found: {summary_file_path}")

        with open(summary_file_path, "r") as file:
            data_for_openai = file.read()

        # Step 2: Define the prompt
        prompt = (
            f"Analyze the domain '{domain}' based on the following data:\n"
            f"{data_for_openai}.\n"
            "Provide a detailed cybersecurity analysis and respond strictly in JSON format with the following structure:\n\n"
            "{\n"
            "  \"vulnerability_index\": <score between 0 and 10>,\n"
            "  \"reasons\": [\n"
            "    \"reason 1: detailed explanation of the vulnerability or issue, including data from the domain analysis\",\n"
            "    \"reason 2: another specific vulnerability or issue with supporting data or trends\",\n"
            "    \"reason 3: a further reason or vulnerability identified, with supporting analysis from the domain data\",\n"
            "    \"reason 4: (optional) additional vulnerability if applicable, with insights based on the domain information\"\n"
            "  ],\n"
            "  \"recommendations\": [\n"
            "    \"recommendation 1: actionable solution or mitigation strategy for addressing the first vulnerability\",\n"
            "    \"recommendation 2: actionable solution or mitigation strategy for addressing the second vulnerability\",\n"
            "    \"recommendation 3: further suggestion for remediation, prevention, or security improvement\",\n"
            "    \"recommendation 4: (optional) any additional recommendation for future-proofing security\"\n"
            "  ]\n"
            "}\n\n"
            "Ensure that the response contains **only** the JSON object and no additional explanations, markdown, or commentary."
        )

        # Step 3: Initialize retry logic
        retries = 5  # Define a max number of retries
        for attempt in range(retries):
            # Make the API call
            response = client.chat.completions.create(
                model="gemma2:2b",
                messages=[
                    {"role": "system", "content": "You are an expert in cybersecurity vulnerability analysis."},
                    {"role": "user", "content": prompt},
                ]
            )

            # Extract raw content from the response
            response_content = response.choices[0].message.content.strip()
            print(f"Raw response content: {response_content}")

            # Step 4: Extract and validate JSON
            try:
                json_match = re.search(r"\{.*?\}", response_content, re.DOTALL)
                if not json_match:
                    raise ValueError("No valid JSON object found in the response.")
                
                cleaned_json = json_match.group()
                result_json = json.loads(cleaned_json)
                
                # If JSON is valid, break the loop and return the result
                break
            except (json.JSONDecodeError, ValueError) as e:
                print(f"Invalid JSON response on attempt {attempt + 1}: {e}")
                if attempt == retries - 1:
                    flash(f"Error: Failed to receive valid JSON after {retries} attempts.", "danger")
                    return redirect(url_for("index"))
                time.sleep(2)  # Wait a bit before retrying

        # Step 5: Save the result if valid JSON was found
        output_file_path = f"data/{domain}/AI_result_{domain}.json"
        os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
        with open(output_file_path, "w") as outfile:
            json.dump(result_json, outfile, indent=4)

        print(f"Extracted JSON saved to {output_file_path}")
        return result_json

    except Exception as e:
        print(f"Error during AI analysis: {e}")
        flash(f"Error: {str(e)}", "danger")
        return redirect(url_for("index"))
        
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        domain = request.form.get("domain")  # Retrieve form data
        if not domain:  # Check if the domain is empty
            flash("Please enter a domain name", "danger")  # Display error message
            return render_template("index.html")
        if not validators.domain(domain):  
            flash("Please enter a valid domain name", "danger")
            return render_template("index.html")
        
  
        Scanned=is_domain_scanned(domain)
        if Scanned:
            flash("Domain already scanned", "info")
            try:
                subdomains_file = f"subdomain_pie_{domain}.html"
                ports_file = f"ports_pie_{domain}.html"
                result_json = open(f"data/{domain}/AI_result_{domain}.json").read()
                result_json = json.loads(result_json)
                hackedlist1 = open(f"data/{domain}/hackedlist_{domain}.json").read()
                hackedlist1=json.loads(hackedlist1)
                domain_data = open(f"data/{domain}/buildwith_{domain}.txt").read()
                domain_data = json.loads(domain_data)

            except FileNotFoundError:
                flash("Required files for the domain analysis are missing.", "danger")
                return redirect(url_for("index"))
            
            return render_template("results.html", domain=domain, subdomain_chart=subdomains_file, ports_chart=ports_file, hackedlist=hackedlist1,data=check_security_headers(domain),domain_data=domain_data ,result=result_json)
            
            
        flash(f"Scanning the {domain} . Please wait...", "info")
        get_subdomains(domain)
        resolve_subdomains_from_file(domain,f"data/{domain}/subdomains_{domain}.txt")
        parse_subdomains_file(domain)

        # # # Create the charts
        create_subdomain_pie_chart(domain)
        subdomain_chart_path=f"subdomain_pie_{domain}.html"
        ports = parse_ports_file(domain)
        ports_chart_path = create_ports_pie_chart(ports, domain)
        hackedlist(domain)
        hacked_data = open(f"data/{domain}/hackedlist_{domain}.json").read()
        hacked_data = json.loads(hacked_data)
        domain_data=buildwith(domain,f"data/{domain}/subdomains_{domain}.txt")
        ai_response(domain)
        result_json = open(f"data/{domain}/AI_result_{domain}.json").read()
        result_json = json.loads(result_json)
        open("data/scanned_domains", "a").write(f"{domain}\n")
        return render_template(
            "results.html",
            domain=domain,
            subdomain_chart=subdomain_chart_path,
            ports_chart=ports_chart_path,
            data=check_security_headers(domain),
            hackedlist=hacked_data,
            domain_data=domain_data,
            result=result_json
        )
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000) 