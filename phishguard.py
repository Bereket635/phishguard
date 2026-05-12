# PhishGuard: Automated phishing detection tool
# Author: Bereket Kasahun 
# GitHub: https://github.com/Bereket635/PhishGuard

import re
import sys
import time
from urllib.parse import urlparse 
import logging 
from colorama import Fore, init, Style 

init(autoreset=True)
#Log configuration 
logging.basicConfig(
    filename="phishguard_logs.txt",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

# suspicious phishing keywords 
phishing_keywords=[
     "update",
     "verify",
     "free",
     "secure",
     "account",
     "bonus",
     "paypal",
     "password",
     "bank",
     "gift",
     "crypto",
     "free-internet",
     "wallet",
     "confirm",
     "reward"
]

# shortener services
shorteners=[
     "bit.ly",
     "tinyurl.com",
     "rb.gy",
     "goo.gl",
     "ow.ly",
     "cutt.ly",
     "t.co"
]

# suspicious domain endings 
suspicious_TLDs=[
    ".xyz",
    ".fun",
    ".skin",
    ".store",
    ".top",
    ".click",
    ".club",
    ".online",
    ".buzz",
    ".li",
    ".at"
]

# type writer effects 
def type_writer(text, delay=0.05):
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()
    
# banner
def banner():
    print(Fore.CYAN + """
==========================================
              PHISHGUARD 
 Python Based Phishing Detection Toolkit
==========================================
    """)
                       
# validate URL 
def is_valid_url():
    regex = re.compile(
        r'^(https?|ftp)://'
        r'([a-zA-Z0-9.-]+)'
        r'(\.[a-zA-Z]{2,})'
        r'(:[0-9]+)?)'
        r'(\/.*)?$'
    )
    
    return re.match(regex, url)
    
# risk bar display 
def show_risk_bar(score):
    
    total = 10
    filled = min(score, total)
    
    bar = "█" * filled + "░" * (total - filled)
    
    print(Fore.MAGENTA + f"\nRisk meter: [{bar}]")
    
# main detection function 
def detect_phishing(url):
    score = 0
    reasons = []
    
    if not is_valid_url:
        print(Fore.RED + f"\n[!] Invalid URL! ")
        return 
        
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    
    # 1. insecure HTTP 
    if url.startswith("http://"):

        score += 2
        reasons.append("Uses insecure HTTP")
     
     #2. too many subdomains 
    if domain.count(".") > 3:
         score +=1
         reasons.append("Uses too many subdomains.")
      
    #3. suspicious symbols 
    if "@" in url:
        score +=2
        reasons.append("Uses '@' in URL")
        
    if "-" in url:
        score +=1
        reasons.append("Uses hyphen in URL. ")
    
    #4. Long URL detection 
    if len(url) > 70:
       score +=2
       reasons.append("Unusually long.")
       
    #5. encoded character 
    if "%" in url:
       score +=1
       reasons.append("Uses encoded character.")
       
    #6. suspicious phishing keywords 
    for word in phishing_keywords:
        if word in url:
            score +=1
            reasons.append(f"Suspicious word detected: {word}")
            
    #7. shortener services 
    for shortener in shorteners:
         if shortener in url:
             score +=3
             reasons.append("Uses shortener service")
             
    #8. suspicious TLDs 
    for tld in suspicious_TLDs:
        if domain.endswith(tld):
            score +=1
            reasons.append(f"Suspicious TLD detected: [{tld}]")
            
    #9. fake HTTPS trik
    if "https" in domain and not domain.startswith(" https"):
        score +=2
        reasons.append("Fake HTTPS keyword in domain")
        
    #result
    print(Fore.CYAN + "\n==============================")
    print(Fore.CYAN + "       SCAN RESULTS")
    print(Fore.CYAN + "==============================")
    
    print(Fore.WHITE + f"\nURL: {url}")
    print(Fore.YELLOW + "Risk Score: {score}")
    
    show_risk_bar(score)
    
    # risk validation 
    if score >=6:
        print(Fore.RED + "\n[High Risk] Possible phishing attack!")
    
    if score >= 3:
        print(Fore.YELLOW + "\n[Warning!] Suspicious link detected." )
        
    else:
        print(Fore.GREEN + "\n[Safe] Link appears mostly safe." )
        
    # reasons 
    if reasons:

        print(Fore.CYAN + "\nDetection Reasons:")

        for reason in reasons:

            print(Fore.WHITE + f" - {reason}")
     
    # save logs 
    logging.info(
        f"URL: {url} | Score: {score} | Reasons: {', '.join(reasons)}"
    )
    
# view logs function 
def view_logs():
    try:
        with open("phishguard_logs.txt", "r") as file:
            logs = file.read()
            print(Fore.CYAN + "\n=========Scan History=========\n")
            print(logs)
            
    except FileNotFoundError:
         print(Fore.RED + "\nNo logs found!")
         
# main menu 
def menu():
    while True:
        print(Fore.CYAN + """ ================ MENU ================

 1. Scan URL
 2. View Scan History
 3. Exit

 ======================================
        """)

        choice = input(Fore.YELLOW + "Select option: ")
        
        # choice 1. scan URL 
        if choice == "1":
            url = input(
                Fore.WHITE + "\nEnter URL to scan: "
            )

            detect_phishing(url)
         
         # choice 2. view logs 
        elif choice == "2":
            view_logs()
        
        # choice 3. exit 
        elif choice == "3":
            print(Fore.GREEN + "\nExit the tool thanks for using my script!")
            break 
        
        else:
            print(Fore.RED +"\nInvalid option")
            
# start the program 
banner()
type_writer("Starting PhishGuard automated phishing detection tool....." )
menu()