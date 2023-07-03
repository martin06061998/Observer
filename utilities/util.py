import base64
import hashlib
import logging
import re
import html2text
from mitmproxy.http import Request 
from bs4 import BeautifulSoup
from bs4.element import Tag


def md5(value: str):
    return hashlib.md5(value.encode("utf-8", "ignore")).hexdigest()


def is_valid_url(url: str) -> bool:
    """Return whether the url is a valid url."""
    if url is None or type(url) is not str or len(url) < 1:
        return False
    absolutePattern = re.compile(
        r'^(http|ftp|ws|file|ssh|ldap)s?://'  # http:// or https://
        # domain...
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    relativePattern = re.compile(
        r"^(/[a-z0-9%\-_.]+)+((\?|&)[a-z][a-z0-9]*=[a-z0-9$'\-_.+\-!*()]*)*(#[a-z][a-z0-9]*)?$", re.IGNORECASE)

    if absolutePattern.match(url) or relativePattern.match(url):
        return True
    return False

def parsed_to_wordlist(content: str) -> set[str]:
    h = html2text.HTML2Text()
    h.ignore_links = True
    h.ignore_images = True

    text = h.handle(content)
    lines = text.splitlines()
    wordlist = set()
    for line in lines:
        wordlist.update(line.split())
    return wordlist if len(wordlist) >= 1 else None

def dict_to_url_encoded(data:dict[str:str])->bytes:
    r = Request.make(method="post",url="http://example.com")
    r.urlencoded_form.update(data)
    text = r.content.decode("utf-8","ignore")
    return text

def dict_to_multipart_form(data:dict[bytes:bytes])->bytes:
    r = Request.make(method="post",url="http://example.com")
    r.multipart_form.update(data)
    text = r.content.decode("utf-8","ignore")
    return text


def base64_encode(value) -> str:
    if type(value) is str:
        value=value.encode('utf-8', 'ignore')
        
    return base64.b64encode(value).decode('utf-8', 'ignore')


def base64_decode(value: str) -> str:
    return base64.b64decode(value.encode('utf-8', 'ignore'))


def form2dict(html:bytes):
    ret = []
    soup = BeautifulSoup(html, "html.parser")
    from_tag = soup.find_all(name="form",attrs={"method":re.compile("^post$", re.I)})
    tag:Tag
    for tag in from_tag:
        form_dict = dict()
        form_dict["action"] = tag.get("action")
        form_dict["enctype"] = tag.get("enctype","application/x-www-form-urlencoded")

        parameters = dict()
        input_tags = tag.find_all(name="input")
        for t in input_tags:
            tag_type = t.get("type")
            tag_name = t.get("name")
            tag_value = t.get("value")
            if tag_value:
                parameters[tag_name] = tag_value
            else:
                if tag_type == "email":
                    parameters[tag_name] = "example@gmail.com"
                elif tag_type == "checkbox":
                   parameters[tag_name] = ""
                elif tag_type == "file":
                    parameters[tag_name] = ""
                elif tag_type != "submit":
                    parameters[tag_name] = ""
        selection_tags = tag.find_all(name="select")
        for t in selection_tags:
            tag_name = t.get("name")
            options_tag = t.find_all(name="option")
            value = options_tag[0].get("value") if len(options_tag) > 0 else None
            if value:
                parameters[tag_name] = value

       
        form_dict["parameters"] = parameters
        ret.append(form_dict)
    return ret if len(ret) > 0 else None

