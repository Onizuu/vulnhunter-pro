"""
Modèles de base de données avec SQLAlchemy
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, Text, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


class Scan(Base):
    """
    Modèle pour stocker les scans
    """
    __tablename__ = 'scans'

    id = Column(String(36), primary_key=True)
    url_cible = Column(String(500), nullable=False)
    date_debut = Column(DateTime, default=datetime.utcnow)
    date_fin = Column(DateTime)
    duree = Column(Float)
    score_risque = Column(Float)
    nb_vulnerabilites = Column(Integer, default=0)
    statut = Column(String(50), default='en_cours')
    
    # Relations
    vulnerabilites = relationship('Vulnerabilite', back_populates='scan', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f"<Scan {self.id} - {self.url_cible}>"


class Vulnerabilite(Base):
    """
    Modèle pour stocker les vulnérabilités
    """
    __tablename__ = 'vulnerabilites'

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(36), ForeignKey('scans.id'))
    
    type = Column(String(100), nullable=False)
    severite = Column(String(20), nullable=False)
    url = Column(String(500), nullable=False)
    description = Column(Text)
    payload = Column(Text)
    preuve = Column(Text)
    remediation = Column(Text)
    cvss_score = Column(Float)
    cve_id = Column(String(50))
    validee = Column(Boolean, default=False)
    exploit_disponible = Column(Boolean, default=False)
    exploit_code = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    # Relations
    scan = relationship('Scan', back_populates='vulnerabilites')
    
    def __repr__(self):
        return f"<Vulnerabilite {self.type} - {self.severite}>"


class Exploit(Base):
    """
    Modèle pour stocker les exploits connus
    """
    __tablename__ = 'exploits'

    id = Column(Integer, primary_key=True, autoincrement=True)
    titre = Column(String(200), nullable=False)
    description = Column(Text)
    code = Column(Text)
    type_vuln = Column(String(100))
    severite = Column(String(20))
    cve_id = Column(String(50))
    edb_id = Column(String(50))
    date_publication = Column(DateTime)
    auteur = Column(String(100))
    plateforme = Column(String(100))
    tags = Column(Text)
    
    def __repr__(self):
        return f"<Exploit {self.titre}>"


class PayloadPattern(Base):
    """
    Modèle pour stocker les patterns de payloads
    """
    __tablename__ = 'payload_patterns'

    id = Column(Integer, primary_key=True, autoincrement=True)
    type_vuln = Column(String(100), nullable=False)
    payload = Column(Text, nullable=False)
    technique = Column(String(100))
    description = Column(Text)
    efficacite = Column(Float, default=0.0)
    nb_utilisations = Column(Integer, default=0)
    nb_succes = Column(Integer, default=0)
    date_creation = Column(DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f"<PayloadPattern {self.type_vuln} - {self.technique}>"


# Fonction pour créer les tables
def creer_tables(engine):
    """
    Crée toutes les tables dans la base de données
    
    Args:
        engine: Engine SQLAlchemy
    """
    Base.metadata.create_all(engine)


# Fonction pour initialiser la base de données
def init_db(database_url: str = "sqlite:///base_de_donnees/vulnhunter.db"):
    """
    Initialise la connexion à la base de données
    
    Args:
        database_url: URL de connexion à la base
        
    Returns:
        Session: Session SQLAlchemy
    """
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    
    engine = create_engine(database_url)
    creer_tables(engine)
    
    Session = sessionmaker(bind=engine)
    return Session()

