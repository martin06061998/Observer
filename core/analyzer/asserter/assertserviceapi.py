import logging
from re import Match, search, IGNORECASE, findall
from utilities.util import parsed_to_wordlist


class AsserterServiceAPI:

    @classmethod
    def has_similar_content_wordlist(cls, body_content_1: bytes, body_content_2: bytes, rate: float = 100) -> bool or None:
        if type(body_content_1) is not str:
            body_content_1 = body_content_1.decode("utf-8", "replace")
        if type(body_content_2) is not str:
            body_content_2 = body_content_2.decode("utf-8", "replace")
        wordlist_1 = parsed_to_wordlist(body_content_1, False)
        wordlist_2 = parsed_to_wordlist(body_content_2, False)

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
        logging.warning(code)
        return code == status_code

    @classmethod
    def contains_all(cls, target_wordlist: set[str], wordlist: set[str], IGNORE_CASE: bool = False) -> bool:
        if target_wordlist is None or wordlist is None:
            return False
        return wordlist.intersection(target_wordlist) == wordlist

    @classmethod
    def contains_any(cls, target_wordlist: set[str], wordlist: set[str], IGNORE_CASE: bool = False) -> bool:
        if target_wordlist is None or wordlist is None:
            return False
        return len(wordlist.intersection(target_wordlist)) > 0

    @classmethod
    def search_any_regex(cls, content: str, patterns: set[str], IGNORE_CASE: bool = False) -> dict[str:list[Match[bytes]]] or None:
        """Search for a list of regex. Return the first match"""
        if content is None or type(content) is not str:
            return
        for _pattern in patterns:
            if IGNORE_CASE:
                match = search(_pattern, content, IGNORECASE)
            else:
                match = search(_pattern, content)
            if match:
                return {_pattern: match}

    @classmethod
    def search_all_regex(cls, content, patterns: set[str], IGNORE_CASE: bool = False) -> dict[str:list[Match[bytes]]] or None:
        """Search for a list of regex. Return the first match"""
        if content is None or type(content) is not str:
            return
        ret = {}
        for _pattern in patterns:
            matches = []
            if IGNORE_CASE:
                matches = findall(_pattern, content, IGNORECASE)
            else:
                matches = findall(_pattern, content)
            if matches is None or len(matches) < 1:
                return
            ret[_pattern] = matches
        return ret

    @classmethod
    def test(cls, message):
        print(f"receive {message}")
