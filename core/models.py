"""
Modèles de données pour le scanner
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional


@dataclass
class DonneesReconnaissance:
    """Données collectées pendant la phase de reconnaissance"""
    url_cible: str
    sousdomaines: List[str] = field(default_factory=list)
    ports_ouverts: Dict[int, str] = field(default_factory=dict)
    technologies: Dict[str, str] = field(default_factory=dict)
    repertoires: List[str] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)


@dataclass
class Vulnerabilite:
    """Représente une vulnérabilité détectée"""
    type: str
    severite: str
    url: str
    description: str
    payload: Optional[str] = None
    preuve: Optional[str] = None
    remediation: Optional[str] = None
    cvss_score: Optional[float] = None
    cve_id: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    validee: bool = False
    exploit_disponible: bool = False
    exploit_code: Optional[str] = None

    def to_dict(self) -> Dict:
        return {
            'type': self.type,
            'gravite': self.severite,  # Mapping severite -> gravite pour le frontend
            'url': self.url,
            'description': self.description,
            'payload': self.payload,
            'preuve': self.preuve,
            'remediation': self.remediation,
            'cvss_score': self.cvss_score,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'validee': self.validee,
            'exploit_disponible': self.exploit_disponible
        }


@dataclass
class RapportScan:
    """Rapport complet d'un scan"""
    url_cible: str
    date_debut: datetime
    date_fin: datetime
    duree: float
    vulnerabilites: List[Vulnerabilite]
    donnees_recon: DonneesReconnaissance
    score_risque_global: float
    chaines_exploit: List[Dict] = field(default_factory=list)
    statistiques: Dict = field(default_factory=dict)


@dataclass
class WaybackResult:
    """Résultats de l'analyse Wayback Machine"""
    urls_discovered: List[str] = field(default_factory=list)
    robots_paths: List[str] = field(default_factory=list)
    hidden_endpoints: Dict[str, List[str]] = field(default_factory=dict)
    parameters: Dict[str, int] = field(default_factory=dict)
    total_urls: int = 0


@dataclass
class GitHubAsset:
    """Asset découvert via GitHub"""
    type: str  # 'subdomain', 'credential', 'api_key'
    value: str
    source: str
    repository: str = ""
    path: str = ""
    severity: str = "INFO"  # 'CRITICAL' si credential


@dataclass
class PassiveReconData:
    """Données complètes de reconnaissance passive"""
    wayback_result: Optional[WaybackResult] = None
    github_subdomains: List[str] = field(default_factory=list)
    github_credentials: List[GitHubAsset] = field(default_factory=list)
    github_api_keys: List[GitHubAsset] = field(default_factory=list)
    total_assets_discovered: int = 0
    execution_time: float = 0.0
