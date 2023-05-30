from enum import Enum


class BugType(Enum):
    SQLi = "sqli"
    XSS = "xss"
    RCE = "rce"
    LFI = "lfi"
    XXE = "xxe"
    UNKNOWN = "_"
