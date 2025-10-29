from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from abc import ABC, abstractmethod  

@dataclass
class InjectionPoint:
    url: str
    param_type: str
    selector: Optional[str] = None
    param_name: Optional[str] = None

@dataclass
class AttackResult:
    is_vulnerable: bool
    successful_payload: Optional[str] = None
    payload_template: Optional[str] = None

@dataclass
class CookieInfo:
    name: str
    httponly: bool
    samesite: Optional[str] = None

@dataclass
class DefenseAnalysis:
    csp_rules: Dict[str, str] = field(default_factory=dict)
    all_cookies: List[CookieInfo] = field(default_factory=list)


@dataclass
class PageContext:
    dom_findings: Dict[str, str] = field(default_factory=dict)
    csrf_token_info: Optional[Dict[str, str]] = None


# --- 4. 컨트롤러가 익스플로잇 모듈로 전달하는 데이터 ---

@dataclass
class FinalReportData:
    """[➡️ 생성: Controller | ⬅️ 사용: ExploitModule]"""
    point: InjectionPoint
    result: AttackResult
    defenses: DefenseAnalysis
    context: PageContext

# --- 5. ExploitModule이 사용할 '부품(플러그인)' 설계도 ---

@dataclass
class ExploitScenario:
    scenario_name: str  # 예: "쿠키 탈취", "실시간 도청"
    is_possible: bool   # 이 공격이 가능한가?
    severity: str       # 'Critical', 'High', 'Medium', 'Info'
    des: Optional[str] = None  # 불가능할 경우의 이유 (예: "HttpOnly 방어됨")
    poc_code: Optional[str] = None # 가능할 경우의 PoC 코드

class IExploitCheck(ABC):
    @abstractmethod
    def check(self, data: FinalReportData, callback_server: str) -> Optional[ExploitScenario]:
        pass

@dataclass
class FinalExploitReport:
    injection_point: InjectionPoint
    successful_payload: str
    scenarios: List[ExploitScenario] = field(default_factory=list)