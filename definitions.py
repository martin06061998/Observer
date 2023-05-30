import os
from customenum.bugtype import BugType
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
BUILDIN = set()
BUILDIN.add(r"timestamp")
BUILDIN.add(r"status_code")
PLACEHOLDER = set()
for i in range(0, 6):
    PLACEHOLDER.add(r"{{request_id"+f"!{i}"+r"}}")
    PLACEHOLDER.add(r"{{response_body_content"+f"!{i}"+r"}}")

DOM_HOOK_SCRIPT = None
with open(os.path.join(ROOT_DIR, 'gadget', 'nativeJSHook.js')) as f:
    INIT_SCRIPT = f.read()


XSS_PATTERN = {"^q$",
               "^s$",
               "^[a-z0-9_]*search[a-z0-9_]*$",
               "^[a-z0-9_]*lang[a-z0-9_]*$",
               "^[a-z0-9_]*keyword[a-z0-9_]*$",
               "^query$",
               "^page$",
               "^keywords$",
               "^year$",
               "^view$",
               "^type$",
               "^name$",
               "^p$",
               "^callback$",
               "^jsonp$",
               "^api_key$",
               "^api$",
               "^password$",
               "^email$",
               "^emailto$",
               "^token$",
               "^username$",
               "^csrf_token$",
               "^unsubscribe_token$",
               "^id$",
               "^item$",
               "^page_id$",
               "^month$",
               "^immagine$",
               "^list_type$",
               "^url$",
               "^terms$",
               "^categoryid$",
               "^key$",
               "^l$",
               "^begindate$",
               "^enddate$"
               }



FILE_DISCLOSURE_PATTERN = {
    ".*\.action$",
    ".*\.adr$",
    ".*\.ascx$",
    ".*\.asmx$",
    ".*\.axd$",
    ".*\.backup$",
    ".*\.bak$",
    ".*\.bkf$",
    ".*\.bkp$",
    ".*\.bok$",
    ".*\.achee$",
    ".*\.cfg$",
    ".*\.cfm$",
    ".*\.cgi$",
    ".*\.cnf$",
    ".*\.conf$",
    ".*\.config$",
    ".*\.crt$",
    ".*\.png$",
    ".*\.jpg$",
    ".*\.svg$",
    ".*\.gif$",
    ".*\.csr$",
    ".*\.csv$",
    ".*\.dat$",
    ".*\.doc$",
    ".*\.docx$",
    ".*\.eml$",
    ".*\.env$",
    ".*\.exe$",
    ".*\.gz$",
    ".*\.ica$",
    ".*\.inf$",
    ".*\.ini$",
    ".*\.java$",
    ".*\.json$",
    ".*\.key$",
    ".*\.log$",
    ".*\.lst$",
    ".*\.mai$",
    ".*\.mbox$",
    ".*\.mbx$",
    ".*\.md$",
    ".*\.mdb$",
    ".*\.nsf$",
    ".*\.old$",
    ".*\.ora$",
    ".*\.pac$",
    ".*\.passwd$",
    ".*\.pcf$",
    ".*\.pdf$",
    ".*\.pem$",
    ".*\.pgp$",
    ".*\.pl$",
    ".*\.plist$",
    ".*\.pwd$",
    ".*\.rdp$",
    ".*\.reg$",
    ".*\.rtf$",
    ".*\.skr$",
    ".*\.sql$",
    ".*\.swf$",
    ".*\.tpl$",
    ".*\.txt$",
    ".*\.url$",
    ".*\.wml$",
    ".*\.xls$",
    ".*\.xlsx$",
    ".*\.xml$",
    ".*\.xsd$",
    ".*\.yml$"
}

