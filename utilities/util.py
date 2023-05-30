import base64
import hashlib
import re
import html2text


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


def parsed_to_wordlist(content: str, IGNORE_CASE: bool) -> set[str]:
    h = html2text.HTML2Text()
    h.ignore_links = True
    h.ignore_images = True

    text = h.handle(content)
    wordlist = set()
    tokens = text.split(" ")
    for token in tokens:
        if IGNORE_CASE:
            token = token.lower()
        wordlist.add(token)
    return wordlist if len(wordlist) >= 1 else None


def base64_encode(value: str) -> str:
    return base64.b64encode(value.encode('utf-8', 'ignore')).decode('utf-8', 'ignore')


def base64_decode(value: str) -> str:
    return base64.b64decode(value.encode('utf-8', 'ignore')).decode('utf-8', 'ignore')
