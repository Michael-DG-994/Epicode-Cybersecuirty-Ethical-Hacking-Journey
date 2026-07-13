
### TracerTNG a simple OSINT recon tool by Michael-DG ###

## TracerTNG is named after "Tracer Tong" from the Deus Ex videogame franchise ##
## After a LOT (not) of thinking I BSed it into meaning "Tracer Tool & Network Gatherer" ##

## this is completely amatorial work used for education purposes only and in this state presents major flaws ##

## This tool was also built specifically for Kali and utilizes its pre-installed tools to function properly ##

## Written in english cause I unironically have an easier time explaining steps in En than I do IT

import argparse #used for cli arguments parsing
import subprocess #runs external commands for tools
import sys
import textwrap
import os #access env
import json #for talking with web APIs
import socket #low level network resolving
import datetime #timestamps for the reports
import shutil #checks if a binary is present o Path
import re #Parse the output
import time #to avoid hammering the Gemini API
from pathlib import Path #handling file paths

#Third Party imports
try:
    import requests #HTTP requests
    HAS_REQUESTS=True
except ImportError:
    HAS_REQUESTS=False

try:
    import dns.resolver #DNS queries since nslookup is annoying to parse
    HAS_DNSPYTHON=True
except ImportError:
    HAS_DNSPYTHON=False

try:
    import shodan as shodan_lib #shodan client
    HAS_SHODAN=True
except ImportError:
    HAS_SHODAN=False

try:
    from google import genai 
    HAS_GEMINI=True
except:
    HAS_GEMINI=False

try:
    from bs4 import BeautifulSoup #html parse to get dnsdumper results
    HAS_BF4=True
except ImportError:
    HAS_BF4=False

try:
    from googlesearch import search as google_search #google dork queries
    HAS_GSEARCH=True
except ImportError:
    HAS_GSEARCH=False
    
#Output formatting
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    C_TITLE=Fore.CYAN+Style.BRIGHT #headers
    C_OK=Fore.GREEN  #success
    C_WARN=Fore.YELLOW #warning or missing requirements
    C_ERR=Fore.RED #errors
    C_INFO=Fore.BLUE+Style.BRIGHT #info
    C_RESET=Style.RESET_ALL #reset terminal to deafault
    C_BOLD=Style.BRIGHT #bold text
    C_DIM=Style.DIM #less important lines
except ImportError: #if colorama is missing the script still works but all strings will look the same and colorless
    C_TITLE=C_OK=C_WARN=C_ERR=C_INFO=C_RESET=C_BOLD=C_DIM=""

#define functions for print
def warn(msg):print(f" {C_WARN}[!]{C_RESET} {msg}")
def ok(msg):print(f" {C_OK}[✓]{C_RESET} {msg}")
def err(msg):print(f" {C_ERR}[X]{C_RESET} {msg}")
def info(msg):print(f" {C_INFO}[*]{C_RESET} {msg}")
def dim(msg):print(f" {C_DIM}  {msg}{C_RESET}") 

#BANNER
def banner():
    print(f"""
{C_TITLE}╔══════════════════════════════════════════════════════╗
║     TracerTNG  - MIKE DG  -  Kali Linux Edition      ║
║              Educational OSINT script                ║
╚══════════════════════════════════════════════════════╝{C_RESET}
""")

#Section header
def section(title:str)->None:
    bar="="*60
    print(f"\n{C_TITLE}{bar}")
    print(f">>> {C_TITLE}")
    print(f"{bar}{C_RESET}")

#Y/N prompts
def ask_y_n(question:str)->bool: #returns boolean True or False associated with the question
    answer=input(f"\n {C_WARN}[?]{C_RESET} {question} {C_BOLD}[y/n]{C_RESET}").strip().lower() #ignore spaces and normalize string in lowercase
    return answer in ("y", "yes") #only "y" or "yes" will count as true everything else is false (including empty input)

#tool checker
def tool_available(name:str)->bool:
    return shutil.which(name) is not None #shutil finds binary name in path, if it finds it it'll return it otherwise it returns None, every subprocess uses this before a call to give an error if absent

#load env
def load_dotenv(env_path:str=".env")->None: #loading the key and value from the .env into enviroment
    path=Path(env_path)
    if not path.exists():
        return
    with open(path,"r") as f:
        for raw_line in f:
            line=raw_line.strip() #remove extra space
            if not line: #skip blank lines
                continue
            if line.startswith("#"): #ignore comments
                continue
            if "=" not in line: #ignore lines with no assegnation
                continue
            key, _, value=line.partition("=")#key and value are divided by the "="
            key=key.strip() #remove spaces
            value=value.strip().strip('"').strip("'")#remove spaces or quotations
            if key and key not in os.environ:
                os.environ[key]=value

load_dotenv() #invoke the function right off

#GET API KEY
def get_api_key(env_var:str, service_name:str)->str: #get key from enviroment, get the name of the service and obtain key or "" if absent
    key=os.environ.get(env_var,"").strip()
    if not key:
        warn(f"{service_name} API key not found in enviroment.\n")
    return key
    
#SUBPROCESS RUNNER
def run_cmd(cmd:list, timeout:int=90)->str: #timeout=90 is the time in seconds before we kill the process, cmd is the command to run, it returns a string of results or an error if the command fails
    try:
        result=subprocess.run(
            cmd,
            capture_output=True, #don't print on terminal
            text=True, #return a str not bytes
            timeout=timeout
        )
        combined=(result.stdout  or "")+(result.stderr or "") #combine stdout abd stderr depending on what the tools use to write results
        return combined.strip()
    except subprocess.TimeoutExpired: #subprocess is timedout
        return f"[TIMED OUT: exceeded {timeout}s]"
    except FileNotFoundError: #couldn't find subprocess requirements
        return f"[NOT FOUND: {cmd[0]}]"
    except Exception as e:
        return f"[GENERAL ERROR: {e}]"

#DNS RECON with dnspython or if missing nslookup for various address resolving related info

DNS_RECORD_TYPES=["A","AAAA","MX","NS","TXT","CNAME","SOA"]

def dns_recon(target:str)->dict: #function receives the target's domain as a string and outputs a dictionary of record type : values
    section(f"DNS RECON - {target}") #section header call
    results={}

    if HAS_DNSPYTHON: #check if dnspython requirement is fullfilled
        info("dnspython - DNS queries ...")
        resolver=dns.resolver.Resolver() 
        for rtype in DNS_RECORD_TYPES:
            try:
                answers=resolver.resolve(target,rtype) 
                records=[str(r) for r in answers] #convert DNS answer object to a string
                results[rtype]=records
                ok(f"{rtype:<6}>>>"+", ".join(records))#print each record in own line
            except dns.resolver.NoAnswer: #if we get no answer we pass
                pass
            except dns.resolver.NXDOMAIN: #domain doesn't exist
                err(f"NXDOMAIN: {target} does not exist in DNS")
                break
            except dns.resolver.NoNameservers: #no dns nameserver respoded for the query
                warn(f"No nameservers responded for {rtype} query")
            except dns.resolver.Timeout:
                warn(f"DNS timeout on {rtype} query")
    else:
        warn("dnspython not found - fallback to nslookup") #a fallback for dnspython
        for rtype in DNS_RECORD_TYPES:
            out=run_cmd(["nslookup",f"-type={rtype}",target], timeout=15)
            if out and "NXDOMAIN" not in out and "SERVFAIL" not in out:
                results[f"{rtype}_raw"]=out
                lines=[line for line in out.splitlines() if line.strip()][:5] #print the first 5 non empty lines to not fill the terminal
                ok(f"{rtype} records:")
                for line in lines:
                    dim(line)
    
    try: 
        ip=socket.gethostbyname(target) #name -> IP
        results["resolved_ip"]=ip
        ok(f"Resolved IP: {ip}")
        try:
            hostname, _, _= socket.gethostbyaddr(ip) #i do the reverse IP->name
            results["reverse_dns"]=hostname
            ok(f"Reverse DNS: {hostname}")
        except socket.herror: #no PTR record present
            results["reverse_dns"]=None
    except socket.gaierror as e: #can't get address info
        err(f"Could not resolve ip for {target}: {e}")
    return results 

#WHOIS x domain registration

def whois_lookup(target:str)->dict: #gets domain as string returns raw text output and full whois output
    section(f"WHOIS - {target}")
    results={}
    if not tool_available("whois"): #tool availability check
        err("whois missing - install required")
        return results
    info(f"Running: whois {target}")
    out=run_cmd(["whois",target],timeout=30)

    if not out: #no result
        warn("whois returned no output")
        return results 
    results["raw"]=out
    lines=out.splitlines() #split multiline string into list of lines
    printed=0 #per ora metto a 0 per counter
    for line in lines:
        if line.strip() and not line.startswith("%") and not line.startswith("#"): #ignore comments and disclaimers
            ok(line)
            printed+=1 #line counter increase
            if printed>=80:
                info(f"... {len(lines) - printed}")
                break
        return results

#subdomain enumeration with sublist3r (search engine/dns/certificates query) and subfinder (passive sources/transparency/APIs query)

#sublist3r
def subdomain_enumeration(target:str)->list: #from target domain as string returns sorted list of subdomain strings
    section(f"SUBDOMAIN ENUMERATION - {target}")
    found=set() #remove duplicates with python set
    if tool_available("sublist3r"):
        info("Running Sublist3r...")
        tmp_out="/tmp/sublist3r_out.txt"
        out=run_cmd(
            ["sublist3r","-d",target,"-t","40","-o",tmp_out], #-d target domain #-t number of threads #-o outputs file to /tmp called sublist3r_out.txt
            timeout=180 #max 3 minutes
            ) 
    
        tmp_path=Path(tmp_out)#read the output
        if tmp_path.exists():
            lines=tmp_path.read_text().splitlines() #read the text in the output, turn the mutliline string into list of lines
            for line in lines:
                line=line.strip() #x spaces
                if line and target in line:
                    found.add(line)#add to already found
                    ok(f"[sublist3r] {line}")
            tmp_path.unlink(missing_ok=True) #clean temporary file
        elif out:
            for line in out.splitlines():
                line=line.strip()
                if line and target in line and " " not in line:
                    found.add(line)
                    ok(f"[sublist3r] {line}")
        else:
            warn("Sublist3r not found - install required")
#subfinder
    if tool_available("subfinder"):
        info("Running Subfinder...")
        out=run_cmd(
            ["subfinder","-d",target,"-silent"],
            timeout=120 #2min max
        )
        if out:
            for line in out.splitlines():
                line=line.strip() #normalize/format lines in list of lines
                if line and target in line:
                    if line not in found: #only prints if not already in set
                        ok(f"[subfinder] {line}")
                    found.add(line)
    else:
        warn("Subfinder not found - install required")
    total=len(found)
    info(f"Total unique subdomains found: {total}")
    return sorted(found) #sorted list

#Certificate transparency with crt.sh

def crtsh_lookup(target:str)->list: #return list of unique subdomains and names found in certificate logs
    section(f"CERTIFICATE TRANSPARENCY - crt.sh running - {target}")
    results=[]
    if not HAS_REQUESTS:
        warn("Request library not installed")
        return results
    url=f"https://crt.sh/?q=%.{target}&output=json" #output JSON,  %.target matches any subdomain
    info(f"Querying: {url}")
    try:
        response=requests.get(url,timeout=(10,30)) #request has a timeout for connection and a timeout for response
        response.raise_for_status() #exception if there's a server/client-side status error
        data=response.json() #parse the json into a python list of dictionaries
        seen=set() #ignore duplicates like before
        for entry in data: 
            for name in entry.get("name_value","").splitlines(): #each entry has a name value x.target.y or *.target.y or multiple names separated  by newline
                name=name.strip().lower()#remove spaces and normalize in lowercase
                if name and name not in seen and not name.startswith("*"): #if present and not already seen or wildcard
                    seen.add(name)
                    results.append(name)
                    ok(f"[crt.sh] {name}")
        info(f"Found {len(results)} unique names in certificate logs")
    except requests.exceptions.Timeout:
        warn("crt.sh request timed out")
    except requests.exceptions.ConnectionError: #couldn't connect
        warn("Could not connect to crt.sh - check connection")
    except (json.JSONDecodeError, ValueError): #couldn't decode json
        warn("crt.sh returned unexpected data")
    except Exception as e: #generic error
        err(f"crt.sh ERROR: {e}")
    return results

#DNSDumpster yet another source for more cross-research

def dnsdumpster_lookup(target:str)->list: #returns list of hostnames and IPS found
    section(f"DNSDUMPSTER - {target}")
    results=[]
    if not HAS_REQUESTS:
        warn("Request library not installed")
        return results
    if not HAS_BF4:
        warn("BeautifulSoup not installed\nSkipping DNSDumpster")
        return results
    base_url="https://dnsdumpster.com" #CSRF token necessary so we need to grab it from homepage
    session=requests.Session() #session keeps cookies from requests
    try:
        info("Fetching CSRF token from DNSDumpster...")
        homepage=session.get(base_url,timeout=15)
        homepage.raise_for_status() #to avoid crash on client/server side status errors
        soup=BeautifulSoup(homepage.text,"html.parser")
        csfr_token=soup.find("input",{"name":"csrfmiddlewaretoken"}) #find the CSRF input field
        if not csfr_token:
            warn("Could not retrieve CSFR token")
            return results
        token_value = csfr_token.get("value","")
        info(f"Got CSFR token: {token_value[:16]}...") #shows first 16 chars of token
        post_data={
            "csrfmiddlewaretoken":token_value,
            "targetip":target,
            "user":"free",
        }
        headers = {"Referer":base_url} #required by DNSDumpster
        info(f"Submitting search for: {target}")
        response=session.post(base_url,data=post_data, headers=headers, timeout=30)
        response.raise_for_status()
        result_soup=BeautifulSoup(response.text,"html.parser") #parse in html
        for td in result_soup.find_all("td"): 
            text=td.get_text(strip=True)
            if target in text or re.match(r"\d+\.\d+\.\d+\.\d+"): #if it contains a domain name or looks like an ip address
                clean=text.split("\n")[0].strip()
                if clean and clean not in results:
                    results.append(clean)
                    ok(f"[dnsdumpster] {clean}")
        info(f"Found {len(results)} entries from DNSDumpster")
    except requests.exceptions.Timeout:
        warn("DNSDumpster Timed out")
    except requests.exceptions.ConnectionError:
        warn("Could not connect to DNSDumpster")
    except Exception as e:
        err(f"DNSDumpster error: {e}")
    return results

#theHarvester specifically for emails

def run_Harvester(target:str)->str:
    section(f"theHARVESTER - {target}")
    harvester_bin=None
    for idk in ["theHarvester","theharvester"]:
        if tool_available(idk):
            harvester_bin=idk
            break
    if not harvester_bin:
        err("theHarvester not found - install required")
        return ""
    
    sources=(
        "duckduckgo,yahoo,"
        "crtsh, dnsdumpster,"
        "hackertarget,rapiddns"
    ) #sources that don't require API keys

    cmd=[harvester_bin, "-d", target, "-b", sources, "-l", "200"] #-d target domain, -b data sources, -l limit results to 200
    info (f"Running: {" ".join(cmd)}")
    out=run_cmd(cmd, timeout=240) #timeout after 4 minutes

    if out:
        lines=out.splitlines()
        for line in lines[:100]: #i'll print only 100 lines it's too long otherwise
            if line.strip():
                ok(line)
        if len(lines)>100:
            info(f"Max lines reached, more saved on log")
    return out

#RECON-NG overkill but it's best to have as many sources in one place as possible, this one is already very complete on its own but you never know what you might miss, at worst the AI receives further confirmation of results later

def run_recon_ng(target:str)->str:
    section(f"RECON-NG - {target}")
    if not tool_available("recon-ng"):
        err("recon-ng not found - install required")
        return ""
    workspace=f"recon_{target.replace('.','_')}" #xxx.com becomes recon_xxx_com 
    #now i have to write down all the recon-ng commands
    commands="\n".join([
        f"workspaces create {workspace}", #create workspace
        f"db insert domains name={target}", #set target domain
        "modules load recon/domains-hosts/hackertarget", #load hackertarget
        "run",
        "modules load recon/domains-hosts/certificate_transparency", #load cert transparency
        "run",
        "modules load recon/domains-hosts/google_site_web", #load google search for indexed subdomains
        "run",
        "show hosts", #dump the finds
        "exit",
    ])
    info("Running recon-ng modules...")

    try:
        results=subprocess.run(
            ["recon-ng"], #run reconn-ng
            input=commands, #input commands we wrote before
            capture_output=True, #instead of output on screen we store it in results
            text=True, #instead of an output in bytes we turn em into str
            timeout=180 #timeout after 3mins
        )
        out=(results.stdout or "")+(results.stderr or "") #the output from recon-ng + error output and some fallbacks for vacant outputs
        if out:
            lines=out.splitlines() #output from multiline string to list of lines
            for line in lines[:80]: #set a hard limit at 80
                if line.strip() and not line.startswith("[*] No"): #removes vacant lines like the "no hosts found" or "no results for this module"
                    ok(line)
        return out.strip()
    except subprocess.TimeoutExpired: #timeout warning
        warn("recon-ng Timed out")
        return "[TIMEOUT]"
    except Exception as e: #general errors
        err(f"recon-ng ERROR: {e}")
        return f"[ERROR: {e}]"
    
#GOOGLE DORKS #careful with this as you can EASILY Get rate limited by google

DEFAULT_DORKS=[
    'site:{t} intitle:"index of" ".git"', #find exposed git repos
    'site:{t} intitle:"index of" "backup"', #find backup directories
    'site:{t} ext:env (|) ext:log (|) ext:sql', #eng/log/config files
    'site:{t} inurl:admin (|) inurl:login (|) inurl:dashboard', #admin panels
    'site:{t} intitle:"phpinfo()"', #php info pages
    'site:{t} "password" filetye:txt', #password stored in text files
    'site:{t} inurl:.git/config', #git config files
    'site:{t} inurl:wp-admin (|) inurl:wp-content', #WordPress
    'site:{t} inurl:".env"', #.env files
    '"@{t}" filetype:xls (|) filetype:csv', #leaked mails
]

def google_dorks(target:str, custom_dorks:list=None)->dict: #custom dorks are optional ones besides the default, if none are used it just uses DEFAULT_DORKS, returns dictionary of dork query : result list
    section(f"GOOGLE DORKS - {target}")
    results={}#empty dict for results
    dork_list=custom_dorks if custom_dorks else DEFAULT_DORKS
    for template in dork_list:
        query=template.replace("{t}",target) #i replace the placeholder {t} for the actual target
        if HAS_GSEARCH:
            info(f"Dorking: {query}")
            hits=[] #empty list for now of all the queries that came up succesfull
            try:
                for url in google_search(query,num_results=5): #set max results at 5
                    ok(f" >>> {url}") #show hits
                    hits.append(url)#every query that has results on google_search, up to 5 results, gets added to the list of hits
                time.sleep(2) #to not get rate limited by google (hopefully)
            except Exception as e:
                warn(f"Google search ERROR: {e}")
            results[query]=hits 
        else:
            print(f"search {query}")
            results[query]={"(manual search - install googlesearch-python required)"}
    if not HAS_GSEARCH:
        warn(
            "googlesearch-python not installed\n"
            " Copy the queries and run them in your google browser"
        )
    return results
    
#SHODAN API - i can't legally do what shodan does, what i can legally do is get results from shodan itself, this gets me open ports, service info and detailed results i just had to include it
#also they're based SYSTEM SHOCK fans

def shodan_lookup(target:str)->dict: #i'll return structured shodan info
    section(f"SHODAN - {target}")
    results={}
    api_key=get_api_key("SHODAN_API_KEY","Shodan")
    if not api_key:
        return results #the warning about missing api keys is already in the function
    if not HAS_SHODAN:
        err("shodan library missing - install required")
        return results
    try:
        api=shodan_lib.Shodan(api_key) #initialise shodan api 
        try:
            ip=socket.gethostbyname(target) #name->ip
            info(f"Resolved {target}>>>{ip}")
        except socket.gaierror: #can't get address info
            ip=target #instead of using the IP we just get the results for the target's name itself
        info(f"Querying SHodan data for {ip}")
        host=api.host(ip)
        results.update({
            "ip":host.get("ip_str"), #target ip address
            "org":host.get("org"), #irgabuzatuib that owns ip hosting
            "os":host.get("os"), #operating system
            "country":host.get("country_name"), #country for geolocation
            "city":host.get("city"), #city for server location
            "isp":host.get("isp"), #internet service provider
            "last_update":host.get("last_update"), #when shodan last scanned target
            "hostnames":host.get("hostnames",[]), #list of hostnames that resolve ip
            "tags":host.get("tags",[]), #list of tags assigned by shodan like "vpn" "honeypot" "tor"
            "vulns":list(host.get("vulns",{}).keys()) #vulns is a dictionary of CVE-ID : details so we just store IDs
        })
        ok(f"IP: {results["ip"]}")
        ok(f"ORG: {results["org"]}")
        ok(f"OS: {results["os"]}")
        ok(f"LOCATION: {results["country"]}, {results["city"]}")
        ok(f"ISP: {results["isp"]}")
        ok(f"HOSTNAMES: {", ".join(results["hostnames"])}")
        if results["vulns"]: #CVEs are important in OSINT so we're gonna highlight them
            warn(f"CVES found: {", ".join(results["vulns"])}")
        ports=[]#now we're gonna create a list for the ports found open
        for service in host.get("data",[]): #shodan stores the info in data
            port_info={
                "port": service.get("port"),#port number
                "proto": service.get("proto"), #transport protocol
                "product": service.get("product", ""), #software running on that port, "" if empty
                "version": service.get("version", ""), #version of that software, "" if empty
                "banner": service.get("data","")[:200].replace("\n","") #full banner but limited to 200chars, these are the first bytes sent back to Shodan on connection w the server
            }
            ports.append(port_info)
            ok(
                f"Port {port_info["port"]}/{port_info["proto"]}" #print the port and transport protocol
                f" {port_info["product"]} {port_info["version"]}" #if it's found, print software and version
            )
            if port_info["banner"]:
                dim(f"Banner: {port_info["banner"][:80]}") #print banner limited to 80 chars with dim characters
        results["ports"]=ports
        #related hosts on domain
        info(f"Seaching Shodan for other hosts under {target}...")
        search=api.search(f"hostname:{target}")
        related_ips=[m.get("ip_str") for m in search.get("matches",[]) if m.get("ip_str") != ip] #gets the list of result dictionaries or defaults to an empty list of none are found
        if related_ips:
            ok(f"Related IPs: {", ".join(related_ips[:10])}") #maximum of 10 items
        results["related_ips"]=related_ips
    except shodan_lib.APIError as e:
        err(f"Shodan API ERROR: {e}")
    except Exception as e:
        err(f"Shodan Unexpected ERROR: {e}")
    return results

#LOG FILE

def save_log(target:str, all_data:dict)->tuple: #get target domain, get the dictionary of all results from main() and reutn a tuple of paths of saved files
    if not ask_y_n("Save all results to a log file?"):
        info("Skipping log file save")
        return None, None
    ts=datetime.datetime.now().strftime("%Y%m%d_%H%M%S") #timestamp as string
    safe_target=re.sub(r"[^a-zA-Z0-9_-],","_",target) #tells to replace any character NOT in that pattern with an underscore -> example.org -> example_org
    output_dir=Path.cwd()/"TracerTNG_results" #current working direcotry
    output_dir.mkdir(parents=True,exist_ok=True) #creates it + any parent if needed
    info(f"Saving results to: {output_dir}/")

    json_path=output_dir/f"TracerTNG_{safe_target}_{ts}.json" #JSON file creation
    with open(json_path,"w",encoding="utf-8") as f: #with manages closing the file when block finishes, "w" tells python to write a new file, encode the text in utf-8
        json.dump(all_data,f,indent=2,default=str) #serializing python dicts to JSON text, convert non adaptable objects in string if necessary
    ok(f"JSON data saved >>> {json_path}")

    log_path=output_dir/f"TracerTNG_{safe_target}_{ts}.log" #readable log creation
    with open(log_path,"w",encoding="utf-8") as f:
        f.write("="*70+"\n")
        f.write(f"TracerTNG OSINT REPORT - {target}\n")
        f.write(f" Time: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}")
        f.write("="*70+"\n\n")
        for module_name,module_data in all_data.items(): #fpr every module result
            if module_name in ("target","timestamp"):
                continue #skip metadata
            f.write(f"\n{"-"*70}\n")
            f.write(f" MODULE: {module_name.upper()}\n")
            f.write(f"\n{"-"*70}\n\n")
            
            if isinstance(module_data,str): #if the data is a string i just write directly
                f.write(module_data+"\n")
            elif isinstance(module_data,list): #if the data is a list i write one x line
                for item in module_data:
                    f.write(f"{item}\n")
            elif isinstance(module_data,dict): #if the data is a dict i write key: value
                for key,value in module_data.items():
                    f.write(f" {key}: {value}\n")
            else: #generic convert to string
                f.write(str(module_data)+"\n")
    ok(f"Log file SAVED >>> {log_path}")
    return log_path, json_path

#GEMINI PROMPTING

GEMINI_PROMPT_TEMPLATE="""\
You are a cybersecurity analyst writing a professional OSINT recon report.
You have been given the raw recon data collected through OSINT for the target:
 
TARGET DOMAIN : 
SCAN DATE     : 
 
Your task is:
- Analyse ALL the data provided.
- Identify the most significant security-relevant findings.
- Write a structured report.
- Be precise and factual — do NOT speculate beyond what the data shows.
- Assign an overall risk level: Low / Medium / High / Critical.
 
--- BEGIN RAW RECON DATA ---

--- END RAW RECON DATA ---
 
Write your report using the following sections:
 
## 1. Executive Summary
(3-5 sentences. Overall risk level. Most critical findings highlighted.)
 
## 2. Infrastructure Overview
(IP addresses, hosting provider, ASN, geolocation, CDN/WAF detected)
 
## 3. DNS & Domain Intelligence
(Notable DNS records, mail infrastructure, domain age, registrar)
 
## 4. Exposed Subdomains
(List significant subdomains; flag dev/staging/admin/api as higher risk)
 
## 5. Certificate Transparency Findings
(Notable names from cert logs, wildcard certs, recently issued certs)
 
## 6. Email & Personnel Intelligence
(Emails found, patterns, employee names, social exposure)
 
## 7. Internet-Facing Services (Shodan)
(Open ports, service versions, CVEs, misconfigurations)
 
## 8. Sensitive Content (Google Dorks)
(Exposed files, admin panels, leaked data, configuration files)
 
## 9. Attack Surface Summary
(What an attacker would prioritise. Top 3-5 attack vectors.)
 
## 10. Recommendations
(Prioritised, actionable, specific to the findings above)
 
Be thorough but concise. Flag **critical findings** in bold.
"""

def gemini_report(target:str, all_data:dict)->str: #gets target, gets data, returns string
    section("---GEMINI AI REPORT GENERATION---")
    if not ask_y_n("Generate an AI security report with the data acquired (powered by Google Gemini)"):
        info("AI Report DECLINED")
        return ""
    api_key=get_api_key("GEMINI_API_KEY","Gemini")
    if not api_key:
        return "" #error already in function
    if not HAS_GEMINI:
        err("Google GENAI library not found - install required")
        return ""
    try:
        data_str=json.dumps(all_data,indent=2,default=str) #serializing python dicts to JSON text, convert non adaptable objects in string if necessary (like prior)
        prompt=GEMINI_PROMPT_TEMPLATE.format(
            target=target,
            date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
            data=data_str,
        )
        client=genai.Client(api_key=api_key) #initialize gemini
        response=client.models.generate_content(
            model="gemini-2.0-flash",
            contents=prompt,
            config=genai.types.GenerateContentConfig(
                temperature=0.1, #maximum accuracy, ai doesn't have "creativity" or avoids speculation
                max_output_tokens=4096,
            )
        )
       
        info("Sending data to Gemini 1.5 Flash (temp= 0.1)...")
        report_text=response.text #etract text from response
        print(f"\n{C_OK}{report_text}{C_RESET}\n")
        if ask_y_n("Save Gemini Report to file?"):
            ts=datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_target=re.sub(r"[^a-zA-Z0-9_-],","_",target)
            output_dir=Path.cwd()/f"TracerTNG_{safe_target}_{ts}.md"
            output_dir.mkdir(parents=True,exist_ok=True)
            report_path=output_dir/f"TracerTNG_{safe_target}_{ts}"
            with open(report_path,"w",encoding="utf-8") as f:
                f.write(f"TracerTNG AI OSINT Report - {target})")
                f.write(f"*Generated by Google Gemini 1.5 Flash - {datetime.datetime.now()}*\n\n")
                f.write(report_text)
            ok(f"AI Report SAVED>>> {report_path}")
        return report_text
    except Exception as e: #if anything goes wrong
        err(f"Gemini ERROR: {e}")
        return ""
    
#arg parse for parsing CLI commands
def parse_arg():
    parser=argparse.ArgumentParser(
        prog="TracerTNG.py",
        description=(
            f"{C_TITLE}TracerTNG - simple OSINT recon tool by Michael-DG{C_RESET}\n"
            f"This is completely amatorial work used for educational purposes only and presents major flaws.\n"
            f"TracerTNG is named after 'Tracer Tong' from the Deus Ex videogame franchise, but stands for Tracer Tool & Network Gatherer.\n"
            f"This tool was built {C_BOLD}SPECIFICALLY{C_RESET} for Kali Linux as it requires tools that come preinstalled with it."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
        {C_BOLD}EXAMPLES:{C_RESET}
        # Full scan with default dorks
        python3 recon_tool.py -t example.com
        
        # Full scan with custom Google dork templates
        python3 recon_tool.py -t example.com --dorks 'site:{{t}} ext:env' 'site:{{t}} inurl:admin'
        
        # Skip Google dorks and recon-ng (faster)
        python3 recon_tool.py -t example.com --skip-dorks --skip-recon-ng
        
        {C_BOLD}API KEY SETUP (required for Shodan + Gemini):{C_RESET}
        cp .env.example .env
        nano .env
        # → fill in SHODAN_API_KEY and GEMINI_API_KEY
        # → save, then run the script
        
        {C_BOLD}NEVER put API keys in the command line or in the script code.{C_RESET}
        """
    )
    parser.add_argument(
        "-t", "--target",
        required=True,
        metavar="DOMAIN",
        help="Target Domain to scan"
    )
    parser.add_argument(
        "--dorks", #custom google dorks
        nargs="*",
        metavar="TEMPLATE",
        default=None,
        help=(
            "Custom GOOGLE DORK templates. If omitted default dorks are used."
        )
    )
    skip_group=parser.add_argument_group("skip flags (to speed up the scan)") #i gave the option to skip certain scans through flags rather than prompts
    skip_group.add_argument("--skip-dns",action="store_true", help="Skip DNS recon")
    skip_group.add_argument("--skip-whois",action="store_true", help="Skip WHOIS")
    skip_group.add_argument("--skip-subdomains",action="store_true", help="Skip Sublist3r + Subfinder")
    skip_group.add_argument("--skip-crtsh",action="store_true", help="Skip crt.sh lookup")
    skip_group.add_argument("--skip-dnsdump",action="store_true", help="Skip DNSDumpster")
    skip_group.add_argument("--skip-harvester",action="store_true", help="Skip theHarvester")
    skip_group.add_argument("--skip-recon-ng",action="store_true", help="Skip recon-ng")
    skip_group.add_argument("--skip-dorks",action="store_true", help="Skip Google dorks")
    skip_group.add_argument("--skip-shodan",action="store_true", help="Skip Shodan")
    return parser.parse_args()

##############################################################################################################

def main():
    args=parse_arg()
    target=args.target.lower().strip()
    banner()
    print(f"{C_BOLD}Target:{C_RESET} {C_OK}{target}{C_RESET}")
    print(f"{C_BOLD}Started:{C_RESET} {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}")
    print(f"{C_BOLD}Output:{C_RESET} {Path.cwd()/f"TracerTNG_results"}/")
    print(f"\n{C_WARN} ONLY RUN THIS WITH AUTHORIZATION.{C_RESET}")
    shodan_key_status="✓ loaded" if os.environ.get("SHODAN_API_KEY") else "X not set"
    gemini_key_status="✓ loaded" if os.environ.get("GEMINI_API_KEY") else "X not set"
    print(f"\n{C_BOLD}SHODAN_API_KEY:{C_RESET} {shodan_key_status}")
    print(f"\n{C_BOLD}GEMINI_API_KEY:{C_RESET} {gemini_key_status}")
    
    all_data={
        "target":target,
        "timestamp":str(datetime.datetime.now()),
    }

    #flag skips

    if not args.skip_dns:
        all_data["dns"]=dns_recon(target)
    if not args.skip_whois:
        all_data["whois"]=whois_lookup(target)
    if not args.skip_subdomains:
        all_data["subdomains"]=subdomain_enumeration(target)
    if not args.skip_crtsh:
        all_data["crtsh"]=crtsh_lookup(target)
    if not args.skip_dnsdump:
        all_data["dnsdumpster"]=dnsdumpster_lookup(target)
    if not args.skip_harvester:
        all_data["harvester"]=run_Harvester(target)
    if not args.skip_recon_ng:
        all_data["recon_ng"]=run_recon_ng(target)
    if not args.skip_dorks:
        all_data["google_dorks"]=google_dorks(target, args.dorks)
    if not args.skip_shodan:
        all_data["shodan"]=shodan_lookup(target)

    #save log
    save_log(target,all_data)
    #genai report
    gemini_report(target,all_data)
    #finalize
    section("SCAN COMPLETE")
    dim("The net's going black! ... No more infolinks, transmissions of any kind. We'll start again, live in villages...")
    ok(f"Target: {target}")
    ok(f"Finished: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}")
    ok(f"Results saved in: {Path.cwd()/"TracerTNG_results"}/")
if __name__ == "__main__":
    main() #main only runs if the file is executed directly