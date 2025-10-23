# data_models.py (업데이트된 최종본)

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from abc import ABC, abstractmethod  # ◀◀◀ '규칙'을 만들기 위해 import

# --- 1~3. 기존 데이터 모델 (크롤러, 공격, 분석 모듈용) ---

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
    """
    [변경] dom_findings를 List[str]에서 Dict[str, str]로 변경
    (예: {"email": "input[name='user_email']"})
    """
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
    """
    [➡️ 생성: IExploitCheck (개별 플러그인)]
    개별 익스플로잇 시나리오의 '결과'입니다.
    """
    scenario_name: str  # 예: "쿠키 탈취", "실시간 도청"
    is_possible: bool   # 이 공격이 가능한가?
    severity: str       # 'Critical', 'High', 'Medium', 'Info'
    des: Optional[str] = None  # 불가능할 경우의 이유 (예: "HttpOnly 방어됨")
    poc_code: Optional[str] = None # 가능할 경우의 PoC 코드

class IExploitCheck(ABC):
    """
    [⬅️ 구현: 모든 '플러그인' 클래스]
    모든 익스플로잇 시나리오 '부품(플러그인)'들이 따라야 하는 '규칙(Interface)'입니다.
    """
    @abstractmethod
    def check(self, data: FinalReportData, callback_server: str) -> Optional[ExploitScenario]:
        """
        데이터를 받아, 시나리오가 가능하면 ExploitScenario 객체를,
        불가능하거나 해당 없으면 None을 반환합니다.
        """
        pass

@dataclass
class FinalExploitReport:
    """
    [➡️ 생성: ExploitModule (메인보드) | ⬅️ 사용: Controller (최종 보고서용)]
    'ExploitModule'이 생성하는 최종 리포트 객체입니다.
    """
    injection_point: InjectionPoint
    successful_payload: str
    scenarios: List[ExploitScenario] = field(default_factory=list)