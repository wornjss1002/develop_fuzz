from typing import Dict, List, Tuple

class CSPCheck:
    def _check_sources(self, sources_str: str, directive: str, callback_server: str) -> Tuple[bool, str]:
        sources_list = sources_str.split()

        if '*' in sources_list:
            return (True, f"'{directive}': '*'")
        
        return (False, "")

    @staticmethod
    def csp_check(csp: Dict[str, str], callback_server: str) -> Tuple[bool, List[str]]:
        vulnerable_reasons: List[str] = []
        
        default_sources_str = csp.get('default-src', '') 
        directives_to_check = ['img-src', 'connect-src']

        for directive in directives_to_check:
            sources_str = csp.get(directive)
            
            check_str = sources_str if sources_str is not None else default_sources_str

            if not check_str: 
                continue

            instance = CSPCheck() 
            is_bypassable, reason = instance._check_sources(check_str, directive, callback_server)
            
            if is_bypassable:
                vulnerable_reasons.append(reason)

        if vulnerable_reasons:
            return (True, vulnerable_reasons)
        else:
            return (False, []) 