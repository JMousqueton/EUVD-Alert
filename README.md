# EUVD-Alert

**EUVD-Alert** est un outil de veille automatisée basé sur la base de données de vulnérabilités de l'ENISA (EUVD). Il récupère quotidiennement les vulnérabilités publiées, les filtre selon des mots-clés et des seuils de sévérité (CVSS), puis génère des alertes envoyées par e-mail.

## 🔍 Fonctionnalités

- Récupération quotidienne des vulnérabilités depuis l’API ENISA EUVD
- Filtrage par score CVSS (ex: alerte à partir de 8.0)
- Détection basée sur des mots-clés (produits / éditeurs spécifiques)
- Génération de rapports HTML (quotidien et par alerte)
- Envoi automatique par e-mail
- Génération de graphiques radar CVSS
- Historisation des vulnérabilités traitées

## ⚙️ Configuration

Le fichier `.env` permet de configurer :

```dotenv
VULN_FILE=euvd.json
KEYWORDS_FILE=vendors.json
SENT_IDS_DAILY_FILE=sent_ids_daily.json
SENT_IDS_ALERT_FILE=sent_ids_alert.json
MIN_CVSS_TO_ALERT=8
RADAR_FOLDER=./web/radars
DAILY_FOLDER=./web/daily
RADAR_URL=https://vuln.mousqueton.io/radars
DAILY_URL=https://vuln.mousqueton.io/daily
MAIL_SMTP_SERVER=localhost
MAIL_SMTP_PORT=25
MAIL_FROM=Vulnerability report <no-reply@example.com>
MAIL_TO=example@example.com
```

Le fichier `vendors.json` doit contenir la liste des **vendors** que vous souhaitez surveiller, par exemple :

```json
[
  "Cisco",
  "Microsoft",
  "Fortinet",
  "Palo Alto Networks"
]
```

## 📁 Fichiers principaux

- `Get-EUVD.py` : télécharge les vulnérabilités depuis l’API ENISA
- `AlerAndReport.py` : génère les rapports quotidiens, mensuels et envoie les alertes
- `euvd.json` : base locale des vulnérabilités
- `sent_ids_daily.json` & `sent_ids_alert.json` : suivi des vulnérabilités déjà envoyées

## 🚀 Utilisation

### Mise à jour des vulnérabilités :
```bash
python Get-EUVD.py
```

### Génération des rapports et envoi des alertes :
```bash
python AlertAndReport.py
```

## ✅ Dépendances

- `requests`
- `python-dotenv`
- `matplotlib`
- `numpy`
- `smtplib` (librairie standard Python)

Installez-les avec :

```bash
pip install -r requirements.txt
```

## 📬 Auteurs

Projet personnel de **Julien Mousqueton**    
Source des vulnérabilités : [ENISA EUVD](https://euvd.enisa.europa.eu/)

---

© 2025 Julien Mousqueton – All rights reserved.
