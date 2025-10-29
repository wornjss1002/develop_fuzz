from typing import Dict, List, Tuple
from urllib.parse import urlparse

class CSPCheck:

    @staticmethod
    def _check_sources(sources_str: str, directive: str) -> Tuple[bool, str]:
        sources_list = sources_str.split()

        if '*' in sources_list:
            return (True, f"'{directive}': '*'")
        return (False, "")

    @staticmethod
    def csp_check(csp: Dict[str, str]) -> Tuple[bool, List[str]]:
        vulnerable_reasons: List[str] = []
        
        if not csp:
            csp = {}

        default_sources_str = csp.get('default-src', '') 
        directives_to_check = ['img-src', 'connect-src', 'navigate-to']

        for directive in directives_to_check:
            sources_str = csp.get(directive)
            
            check_str = sources_str if sources_str is not None else default_sources_str

            if not check_str: 
                continue

            is_bypassable, reason = CSPCheck._check_sources(check_str, directive)
            
            if is_bypassable:
                vulnerable_reasons.append(reason)

        if vulnerable_reasons:
            return (True, vulnerable_reasons)
        else:
            return (False, [])