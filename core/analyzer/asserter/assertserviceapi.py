import logging
from re import Match, search, IGNORECASE, findall
from utilities.util import parsed_to_wordlist


class AsserterServiceAPI:

    @classmethod
    def has_similar_content_wordlist(cls, body_content_1: str|bytes, body_content_2: str|bytes, rate: float = 100) -> bool or None:
        if type(body_content_1) is bytes:
            body_content_1 = body_content_1.decode()
        
        if type(body_content_2) is bytes:
            body_content_2 = body_content_2.decode()
            
        wordlist_1 = parsed_to_wordlist(body_content_1)
        wordlist_2 = parsed_to_wordlist(body_content_2)

        if wordlist_1 is None or wordlist_2 is None:
            return wordlist_1 == wordlist_2 == None
        intersec = wordlist_1.intersection(wordlist_2)
        if len(intersec) == 0:
            return False
        return float(2*len(intersec)/(len(wordlist_1)+len(wordlist_2))*100) > rate

    @classmethod
    def is_delayed_for(cls, timestamp: float, duration: float):

        return timestamp >= duration

    @classmethod
    def has_status_code(cls, code: int, status_code: int) -> bool:
        # logging.warning(code)
        return code == status_code


    @classmethod
    def contain_any_patterns(cls, response_body_content: bytes, patterns: set[str], IGNORE_CASE: bool = True) -> dict[str:list[Match[bytes]]] or None:
        """Search for a list of regex. Return the first match"""
        for _pattern in patterns:
            p = _pattern.encode()
            if IGNORE_CASE:
                match = search(p, response_body_content, IGNORECASE)
            else:
                match = search(p, response_body_content)
            if match:
                return True
        return False

    @classmethod
    def nop(cls):
        return True
