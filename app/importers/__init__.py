from app.importers.google_password_manager import GooglePasswordManagerImporter
from app.importers.lastpass import LastPassImporter

IMPORTERS = [
    LastPassImporter(),
    GooglePasswordManagerImporter(),
]
