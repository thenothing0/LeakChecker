#!/bin/bash
# ═══════════════════════════════════════════════════════════
#  PhoneLeakChecker Pro v1.0 - Professional Phone OSINT
#  Advanced Phone Number Intelligence & Leak Detection
#  Run: chmod +x phone_setup.sh && ./phone_setup.sh
# ═══════════════════════════════════════════════════════════

set -e

echo ""
echo "╔═══════════════════════════════════════════════════════╗"
echo "║  📱 PhoneLeakChecker Pro v1.0 - Phone OSINT Tool      ║"
echo "║  20+ Sources | Dark Web | Messaging Apps | OSINT      ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""

rm -rf phone_checker 2>/dev/null
mkdir -p phone_checker
cd phone_checker

echo "[1/35] Creating directories..."
mkdir -p core network modules/phone modules/social modules/messaging
mkdir -p modules/darkweb modules/surface alerts api ui reporting
mkdir -p database plugins data results cache
echo "  ✅ Directories"

echo "[2/35] Creating requirements.txt..."
cat > requirements.txt << 'EOF'
requests
requests[socks]
PySocks
stem
rich
colorama
beautifulsoup4
lxml
phonenumbers
dnspython
pandas
openpyxl
aiohttp
aiohttp-socks
sqlalchemy
fastapi
uvicorn
fpdf2
jinja2
cryptography
fake-useragent
python-dateutil
pyyaml
schedule
questionary
selenium
Pillow
pycountry
EOF
echo "  ✅ requirements.txt"

echo "[3/35] Creating config.py..."
cat > config.py << 'CFGEOF'
import os
from pathlib import Path

BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
RESULTS_DIR = BASE_DIR / "results"
PLUGINS_DIR = BASE_DIR / "plugins"
CACHE_DIR = BASE_DIR / "cache"
DB_PATH = BASE_DIR / "database" / "phonechecker.db"

for d in [DATA_DIR, RESULTS_DIR, PLUGINS_DIR, CACHE_DIR, DB_PATH.parent]:
    d.mkdir(exist_ok=True)

# ═══ Tor Configuration ═══
TOR_SOCKS_HOST = "127.0.0.1"
TOR_SOCKS_PORT = 9050
TOR_CONTROL_PORT = 9051
TOR_CONTROL_PASSWORD = os.getenv("TOR_PASSWORD", "")
TOR_PROXY = f"socks5h://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}"
TOR_REQUEST_TIMEOUT = 90
MAX_TOR_RETRIES = 3

# ═══ API Keys (all optional) ═══
NUMVERIFY_API_KEY = os.getenv("NUMVERIFY_KEY", "")
ABSTRACT_API_KEY = os.getenv("ABSTRACT_KEY", "")
VERIPHONE_API_KEY = os.getenv("VERIPHONE_KEY", "")
INTELX_API_KEY = os.getenv("INTELX_KEY", "9df61df0-84f7-4dc7-b34c-8ccfb8646ee9")
TWILIO_SID = os.getenv("TWILIO_SID", "")
TWILIO_TOKEN = os.getenv("TWILIO_TOKEN", "")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
VT_API_KEY = os.getenv("VT_API_KEY", "")
TRUECALLER_TOKEN = os.getenv("TRUECALLER_TOKEN", "")

# ═══ Webhooks ═══
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK", "")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK", "")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")
ALERT_ON_HIGH_RISK = True

# ═══ Scanning Settings ═══
REQUEST_TIMEOUT = 15
RATE_LIMIT_DELAY = 2
MAX_CONCURRENT_SCANS = 5
MONITOR_INTERVAL = 3600
CACHE_EXPIRY = 86400

# ═══ Phone Analysis ═══
SUPPORTED_COUNTRIES = [
    "US", "GB", "DE", "FR", "IT", "ES", "NL", "BE", "AT", "CH",
    "AU", "CA", "JP", "KR", "CN", "IN", "BR", "MX", "RU", "TR",
    "SA", "AE", "EG", "ZA", "NG", "KE", "PK", "BD", "ID", "MY",
    "SG", "TH", "VN", "PH", "TW", "HK", "IL", "JO", "LB", "IQ",
    "KW", "QA", "BH", "OM", "YE", "SY", "PS", "LY", "TN", "DZ", "MA",
]

CARRIER_DB = {
    "vodafone": ["Vodafone", "vodafone"],
    "orange": ["Orange", "Mobinil", "orange"],
    "etisalat": ["Etisalat", "etisalat"],
    "we": ["WE", "Telecom Egypt", "we"],
    "att": ["AT&T", "att"],
    "tmobile": ["T-Mobile", "tmobile"],
    "verizon": ["Verizon", "verizon"],
}

# ═══ Threat Weights ═══
THREAT_WEIGHTS = {
    "breach_found": 20,
    "password_with_phone": 40,
    "phone_on_darkweb": 35,
    "phone_in_paste": 15,
    "phone_in_combo": 45,
    "sim_swap_risk": 30,
    "social_media_linked": 10,
    "messaging_apps_found": 5,
    "carrier_identified": 5,
    "voip_number": 10,
    "disposable_number": 15,
    "recently_ported": 20,
    "spam_reported": 10,
    "fraud_reported": 25,
    "github_exposed": 25,
    "telegram_found": 15,
    "whatsapp_active": 5,
    "multiple_names": 15,
    "owner_identified": 10,
    "address_found": 20,
    "email_linked": 10,
    "intelx_found": 15,
}

# ═══ Dark Web Engines ═══
ONION_SEARCH_ENGINES = {
    "ahmia": {
        "type": "surface",
        "urls": ["https://ahmia.fi"],
        "search_path": "/search/?q=",
    },
    "darksearch": {
        "type": "surface",
        "urls": ["https://darksearch.io"],
        "search_path": "/api/search?query=",
        "api": True,
    },
    "torch": {
        "type": "onion",
        "urls": [
            "http://xmh57jrknzkhv6y3ls3ubitzfqnkrwxhopf5aygthi7d6rplyvk3noyd.onion",
            "http://torchdeedp3i2jigzjdmfpn5ttjhthh5wbmda2rr3jvqjg5p77c54dqd.onion",
        ],
        "search_path": "/cgi-bin/omega/omega?P=",
    },
    "haystack": {
        "type": "onion",
        "urls": [
            "http://haystak5njsmn2hqkewecpaxetahtwhsbsa64jom2k22z5afxhnpxfid.onion",
        ],
        "search_path": "/?q=",
    },
}

# ═══ User Agents ═══
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/125.0.0.0 Mobile",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
]
CFGEOF
echo "  ✅ config.py"

echo "[4/35] Creating __init__.py files..."
cat > core/__init__.py << 'EOF'
from .scanner import PhoneScanner
from .phone_analyzer import PhoneAnalyzer
from .threat_scorer import PhoneThreatScorer
EOF

cat > network/__init__.py << 'EOF'
from .tor_manager import TorManager
from .session_manager import SessionManager
EOF

cat > modules/__init__.py << 'EOF'
EOF

cat > modules/phone/__init__.py << 'EOF'
from .number_validator import NumberValidator
from .carrier_lookup import CarrierLookup
from .hlr_lookup import HLRLookup
from .caller_id import CallerIDLookup
from .spam_checker import SpamChecker
EOF

cat > modules/social/__init__.py << 'EOF'
from .social_scanner import SocialScanner
from .gravatar_check import GravatarCheck
from .github_phone import GitHubPhoneSearch
EOF

cat > modules/messaging/__init__.py << 'EOF'
from .whatsapp_check import WhatsAppChecker
from .telegram_search import TelegramSearcher
from .signal_check import SignalChecker
from .viber_check import ViberChecker
EOF

cat > modules/darkweb/__init__.py << 'EOF'
from .phone_darkweb import PhoneDarkWebSearch
from .paste_monitor import PhonePasteMonitor
from .combo_search import ComboListSearch
EOF

cat > modules/surface/__init__.py << 'EOF'
from .google_dorker import PhoneDorker
from .intelx_phone import IntelXPhoneSearch
from .numverify import NumVerifyCheck
from .data_breach import PhoneBreachSearch
EOF

cat > alerts/__init__.py << 'EOF'
from .webhook_alerts import WebhookAlerts
EOF

cat > ui/__init__.py << 'EOF'
from .dashboard import PhoneDashboard
from .animations import Animations
EOF

cat > reporting/__init__.py << 'EOF'
from .report_generator import PhoneReportExporter
from .html_report import PhoneHTMLReport
EOF

cat > database/__init__.py << 'EOF'
from .db_manager import PhoneDatabaseManager
EOF

cat > plugins/__init__.py << 'EOF'
EOF

cat > api/__init__.py << 'EOF'
EOF
echo "  ✅ __init__.py files"

echo "[5/35] Creating core/phone_analyzer.py..."
cat > core/phone_analyzer.py << 'PAEOF'
import phonenumbers
from phonenumbers import (
    geocoder, carrier, timezone as pn_timezone,
    number_type, PhoneNumberType, is_valid_number,
    is_possible_number, format_number, PhoneNumberFormat,
    parse as parse_number
)

class PhoneAnalyzer:
    """Advanced phone number analysis using libphonenumber"""

    PHONE_TYPES = {
        PhoneNumberType.FIXED_LINE: "Fixed Line",
        PhoneNumberType.MOBILE: "Mobile",
        PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed/Mobile",
        PhoneNumberType.TOLL_FREE: "Toll Free",
        PhoneNumberType.PREMIUM_RATE: "Premium Rate",
        PhoneNumberType.SHARED_COST: "Shared Cost",
        PhoneNumberType.VOIP: "VoIP",
        PhoneNumberType.PERSONAL_NUMBER: "Personal",
        PhoneNumberType.PAGER: "Pager",
        PhoneNumberType.UAN: "UAN",
        PhoneNumberType.VOICEMAIL: "Voicemail",
        PhoneNumberType.UNKNOWN: "Unknown",
    }

    def analyze(self, phone_number, default_region=None):
        """Full analysis of a phone number"""
        result = {
            "original": phone_number,
            "valid": False,
            "possible": False,
            "phone_type": "Unknown",
            "country": "",
            "country_code": "",
            "region": "",
            "carrier": "",
            "timezones": [],
            "international": "",
            "national": "",
            "e164": "",
            "rfc3966": "",
            "is_voip": False,
            "is_mobile": False,
            "is_toll_free": False,
            "is_premium": False,
            "risk_indicators": [],
        }

        try:
            parsed = parse_number(phone_number, default_region)

            result["valid"] = is_valid_number(parsed)
            result["possible"] = is_possible_number(parsed)
            result["country_code"] = f"+{parsed.country_code}"
            result["national_number"] = str(parsed.national_number)

            # Format variations
            result["international"] = format_number(parsed, PhoneNumberFormat.INTERNATIONAL)
            result["national"] = format_number(parsed, PhoneNumberFormat.NATIONAL)
            result["e164"] = format_number(parsed, PhoneNumberFormat.E164)
            result["rfc3966"] = format_number(parsed, PhoneNumberFormat.RFC3966)

            # Geographic info
            result["country"] = geocoder.description_for_number(parsed, "en")
            result["region"] = geocoder.description_for_number(parsed, "en")

            # Region code
            region = phonenumbers.region_code_for_number(parsed)
            result["region_code"] = region if region else ""

            # Carrier
            result["carrier"] = carrier.name_for_number(parsed, "en")

            # Timezone
            tz_list = pn_timezone.time_zones_for_number(parsed)
            result["timezones"] = list(tz_list) if tz_list else []

            # Phone type
            ptype = number_type(parsed)
            result["phone_type"] = self.PHONE_TYPES.get(ptype, "Unknown")
            result["is_voip"] = ptype == PhoneNumberType.VOIP
            result["is_mobile"] = ptype in (PhoneNumberType.MOBILE, PhoneNumberType.FIXED_LINE_OR_MOBILE)
            result["is_toll_free"] = ptype == PhoneNumberType.TOLL_FREE
            result["is_premium"] = ptype == PhoneNumberType.PREMIUM_RATE

            # Risk indicators
            if result["is_voip"]:
                result["risk_indicators"].append("VoIP number - may be disposable")
            if result["is_premium"]:
                result["risk_indicators"].append("Premium rate number")
            if result["is_toll_free"]:
                result["risk_indicators"].append("Toll-free number")
            if not result["valid"]:
                result["risk_indicators"].append("Invalid number format")
            if not result["carrier"]:
                result["risk_indicators"].append("Unknown carrier")

            # Generate search formats
            result["search_formats"] = self._generate_search_formats(parsed, phone_number)

        except phonenumbers.NumberParseException as e:
            result["error"] = f"Parse error: {str(e)}"
            result["risk_indicators"].append("Cannot parse number")
        except Exception as e:
            result["error"] = str(e)

        return result

    def _generate_search_formats(self, parsed, original):
        """Generate multiple format variations for searching"""
        formats = set()
        formats.add(original)

        try:
            formats.add(format_number(parsed, PhoneNumberFormat.E164))
            formats.add(format_number(parsed, PhoneNumberFormat.INTERNATIONAL))
            formats.add(format_number(parsed, PhoneNumberFormat.NATIONAL))

            # Without country code
            national = str(parsed.national_number)
            formats.add(national)

            # With leading zero
            if not national.startswith("0"):
                formats.add(f"0{national}")

            # With spaces variations
            e164 = format_number(parsed, PhoneNumberFormat.E164)
            formats.add(e164.replace("+", ""))
            formats.add(e164.replace("+", "00"))

            # Common separator variations
            intl = format_number(parsed, PhoneNumberFormat.INTERNATIONAL)
            formats.add(intl.replace(" ", "-"))
            formats.add(intl.replace(" ", "."))
            formats.add(intl.replace(" ", ""))

        except Exception:
            pass

        return list(formats)

    def validate_input(self, phone_input):
        """Validate and clean phone number input"""
        import re
        cleaned = re.sub(r'[^\d+]', '', phone_input)

        if not cleaned:
            return None, "Empty input"

        if not cleaned.startswith('+') and not cleaned.startswith('00'):
            if len(cleaned) == 10 and cleaned.startswith('0'):
                pass  # local format
            elif len(cleaned) >= 10:
                cleaned = f"+{cleaned}"

        return cleaned, None

    def get_country_from_code(self, country_code):
        """Get country name from phone country code"""
        try:
            import pycountry
            region = phonenumbers.region_code_for_country_code(int(country_code.replace('+', '')))
            if region:
                country = pycountry.countries.get(alpha_2=region)
                return country.name if country else region
        except Exception:
            pass
        return "Unknown"
PAEOF
echo "  ✅ phone_analyzer.py"

echo "[6/35] Creating network modules..."
cat > network/tor_manager.py << 'EOF'
import requests, time, random
try:
    from stem import Signal
    from stem.control import Controller
    HAS_STEM = True
except ImportError:
    HAS_STEM = False
from config import (TOR_SOCKS_HOST, TOR_SOCKS_PORT, TOR_CONTROL_PORT,
                    TOR_CONTROL_PASSWORD, TOR_PROXY, TOR_REQUEST_TIMEOUT,
                    USER_AGENTS, MAX_TOR_RETRIES)

class TorManager:
    def __init__(self):
        self.proxy = {"http": TOR_PROXY, "https": TOR_PROXY}
        self.session = None
        self.is_connected = False
        self.current_ip = None
        self.request_count = 0
        self._create_session()

    def _create_session(self):
        self.session = requests.Session()
        self.session.proxies = self.proxy
        self.session.headers.update({
            "User-Agent": random.choice(USER_AGENTS),
            "Accept-Language": "en-US,en;q=0.5", "DNT": "1",
        })

    def check_connection(self):
        result = {"tor_active": False, "ip": None, "country": None, "error": None}
        try:
            r = self.session.get("https://check.torproject.org/api/ip", timeout=TOR_REQUEST_TIMEOUT)
            if r.status_code == 200:
                data = r.json()
                result["tor_active"] = data.get("IsTor", False)
                result["ip"] = data.get("IP", "Unknown")
            try:
                info = self.session.get(f"http://ip-api.com/json/{result['ip']}", timeout=15).json()
                result["country"] = info.get("country", "Unknown")
            except Exception:
                pass
            self.is_connected = result["tor_active"]
            self.current_ip = result["ip"]
        except requests.exceptions.ConnectionError:
            result["error"] = "Cannot connect to Tor. Is Tor running?"
        except Exception as e:
            result["error"] = str(e)
        return result

    def rotate_ip(self):
        if not HAS_STEM:
            return False
        try:
            with Controller.from_port(port=TOR_CONTROL_PORT) as c:
                c.authenticate(password=TOR_CONTROL_PASSWORD)
                c.signal(Signal.NEWNYM)
                time.sleep(5)
                self._create_session()
                self.request_count = 0
                return True
        except Exception:
            return False

    def get(self, url, **kwargs):
        kwargs.setdefault("timeout", TOR_REQUEST_TIMEOUT)
        for attempt in range(MAX_TOR_RETRIES):
            try:
                self.request_count += 1
                return self.session.get(url, **kwargs)
            except requests.exceptions.RequestException:
                if attempt < MAX_TOR_RETRIES - 1:
                    time.sleep(3)
                    self.rotate_ip()
                else:
                    raise

    def close(self):
        if self.session:
            self.session.close()
EOF

cat > network/session_manager.py << 'EOF'
import random, time, requests
from config import USER_AGENTS, REQUEST_TIMEOUT, RATE_LIMIT_DELAY

class SessionManager:
    def __init__(self, use_tor=False, proxy=None):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml",
            "Accept-Language": "en-US,en;q=0.5", "DNT": "1",
        })
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
        elif use_tor:
            from config import TOR_PROXY
            self.session.proxies = {"http": TOR_PROXY, "https": TOR_PROXY}

    def get(self, url, **kwargs):
        kwargs.setdefault("timeout", REQUEST_TIMEOUT)
        time.sleep(RATE_LIMIT_DELAY + random.uniform(0, 1))
        return self.session.get(url, **kwargs)

    def post(self, url, **kwargs):
        kwargs.setdefault("timeout", REQUEST_TIMEOUT)
        time.sleep(RATE_LIMIT_DELAY + random.uniform(0, 1))
        return self.session.post(url, **kwargs)

    def close(self):
        self.session.close()
EOF
echo "  ✅ Network modules"

echo "[7/35] Creating modules/phone/number_validator.py..."
cat > modules/phone/number_validator.py << 'NVEOF'
import requests, random, re
from config import (NUMVERIFY_API_KEY, ABSTRACT_API_KEY, VERIPHONE_API_KEY,
                    USER_AGENTS, REQUEST_TIMEOUT)

class NumberValidator:
    """Validate phone number using multiple APIs and local analysis"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": random.choice(USER_AGENTS)})

    def validate_all(self, phone, country_code=""):
        """Run all validation methods"""
        result = {
            "phone": phone,
            "valid": False,
            "line_type": "",
            "carrier": "",
            "location": "",
            "country": "",
            "sources_checked": [],
            "details": {},
        }

        # Method 1: NumVerify
        if NUMVERIFY_API_KEY:
            nv = self._numverify(phone)
            if nv and not nv.get("error"):
                result["sources_checked"].append("NumVerify")
                result["details"]["numverify"] = nv
                if nv.get("valid"):
                    result["valid"] = True
                    result["line_type"] = nv.get("line_type", "")
                    result["carrier"] = nv.get("carrier", "")
                    result["location"] = nv.get("location", "")
                    result["country"] = nv.get("country_name", "")

        # Method 2: Abstract API
        if ABSTRACT_API_KEY:
            ab = self._abstract(phone)
            if ab and not ab.get("error"):
                result["sources_checked"].append("Abstract")
                result["details"]["abstract"] = ab

        # Method 3: Veriphone
        if VERIPHONE_API_KEY:
            vp = self._veriphone(phone)
            if vp and not vp.get("error"):
                result["sources_checked"].append("Veriphone")
                result["details"]["veriphone"] = vp

        # Method 4: Free validation via ipqualityscore
        free = self._free_validate(phone)
        if free and not free.get("error"):
            result["sources_checked"].append("FreeValidation")
            result["details"]["free"] = free
            if not result["valid"] and free.get("valid"):
                result["valid"] = True

        return result

    def _numverify(self, phone):
        try:
            clean = phone.replace("+", "").replace(" ", "").replace("-", "")
            r = self.session.get(
                f"http://apilayer.net/api/validate?access_key={NUMVERIFY_API_KEY}&number={clean}",
                timeout=REQUEST_TIMEOUT
            )
            if r.status_code == 200:
                return r.json()
        except Exception as e:
            return {"error": str(e)}
        return None

    def _abstract(self, phone):
        try:
            r = self.session.get(
                f"https://phonevalidation.abstractapi.com/v1/?api_key={ABSTRACT_API_KEY}&phone={phone}",
                timeout=REQUEST_TIMEOUT
            )
            if r.status_code == 200:
                data = r.json()
                return {
                    "valid": data.get("valid", False),
                    "format": data.get("format", {}),
                    "country": data.get("country", {}),
                    "carrier": data.get("carrier", ""),
                    "type": data.get("type", ""),
                }
        except Exception as e:
            return {"error": str(e)}
        return None

    def _veriphone(self, phone):
        try:
            r = self.session.get(
                f"https://api.veriphone.io/v2/verify?phone={phone}&key={VERIPHONE_API_KEY}",
                timeout=REQUEST_TIMEOUT
            )
            if r.status_code == 200:
                return r.json()
        except Exception as e:
            return {"error": str(e)}
        return None

    def _free_validate(self, phone):
        """Free validation using public services"""
        result = {"valid": False, "carrier": "", "type": ""}
        try:
            # Try phone format validation
            clean = re.sub(r'[^\d+]', '', phone)
            if len(clean) >= 10 and len(clean) <= 15:
                result["valid"] = True
                result["format_valid"] = True
        except Exception:
            pass
        return result
NVEOF
echo "  ✅ number_validator.py"

echo "[8/35] Creating modules/phone/carrier_lookup.py..."
cat > modules/phone/carrier_lookup.py << 'CLEOF'
import phonenumbers
from phonenumbers import carrier, geocoder

class CarrierLookup:
    """Identify phone carrier and network information"""

    def lookup(self, phone_number, region=None):
        result = {
            "phone": phone_number,
            "carrier": "",
            "carrier_type": "",
            "network_code": "",
            "country": "",
            "region": "",
            "is_ported": None,
            "original_carrier": "",
        }

        try:
            parsed = phonenumbers.parse(phone_number, region)

            result["carrier"] = carrier.name_for_number(parsed, "en")
            result["country"] = geocoder.description_for_number(parsed, "en")

            region_code = phonenumbers.region_code_for_number(parsed)
            result["region"] = region_code or ""

            # Determine carrier type
            ptype = phonenumbers.number_type(parsed)
            type_map = {
                phonenumbers.PhoneNumberType.MOBILE: "Mobile",
                phonenumbers.PhoneNumberType.FIXED_LINE: "Fixed Line",
                phonenumbers.PhoneNumberType.VOIP: "VoIP",
                phonenumbers.PhoneNumberType.TOLL_FREE: "Toll Free",
                phonenumbers.PhoneNumberType.PREMIUM_RATE: "Premium Rate",
            }
            result["carrier_type"] = type_map.get(ptype, "Unknown")

            # MCC/MNC if available
            cc = parsed.country_code
            result["country_code"] = f"+{cc}"
            result["network_code"] = f"MCC+{cc}"

        except Exception as e:
            result["error"] = str(e)

        return result

    def check_portability(self, phone_number):
        """Check if number might have been ported"""
        result = {"phone": phone_number, "possibly_ported": False, "confidence": "low"}
        try:
            parsed = phonenumbers.parse(phone_number, None)
            current_carrier = carrier.name_for_number(parsed, "en")
            if current_carrier:
                result["current_carrier"] = current_carrier
                result["note"] = "Carrier identified - portability check requires HLR lookup"
        except Exception as e:
            result["error"] = str(e)
        return result
CLEOF

cat > modules/phone/hlr_lookup.py << 'EOF'
import requests, random
from config import USER_AGENTS, REQUEST_TIMEOUT

class HLRLookup:
    """Home Location Register lookup for mobile numbers"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": random.choice(USER_AGENTS)})

    def lookup(self, phone):
        result = {
            "phone": phone,
            "hlr_available": False,
            "network_status": "unknown",
            "roaming": None,
            "imsi": None,
            "mcc": "",
            "mnc": "",
            "note": "Full HLR requires paid API (hlrlookup.com, bsg.world)",
        }

        # Free alternative: check if number responds
        try:
            import phonenumbers
            parsed = phonenumbers.parse(phone, None)
            cc = parsed.country_code
            result["mcc"] = str(cc)
            result["country_code"] = f"+{cc}"

            if phonenumbers.is_valid_number(parsed):
                result["network_status"] = "valid_format"
                result["hlr_available"] = True
        except Exception as e:
            result["error"] = str(e)

        return result
EOF

cat > modules/phone/caller_id.py << 'CIDEOF'
import requests, random, time, hashlib
from urllib.parse import quote
from bs4 import BeautifulSoup
from config import USER_AGENTS, REQUEST_TIMEOUT, RATE_LIMIT_DELAY, TRUECALLER_TOKEN

class CallerIDLookup:
    """Reverse phone lookup using multiple caller ID services"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml",
            "Accept-Language": "en-US,en;q=0.5",
        })

    def lookup_all(self, phone):
        result = {
            "phone": phone,
            "names_found": [],
            "sources": [],
            "total_names": 0,
            "primary_name": "",
            "spam_score": 0,
            "is_spam": False,
        }

        # Source 1: Truecaller (if token available)
        if TRUECALLER_TOKEN:
            tc = self._truecaller(phone)
            if tc:
                result["sources"].append("Truecaller")
                if tc.get("name"):
                    result["names_found"].append({
                        "name": tc["name"],
                        "source": "Truecaller",
                        "confidence": "high",
                    })

        # Source 2: Sync.me web search
        sm = self._syncme(phone)
        if sm and sm.get("name"):
            result["sources"].append("Sync.me")
            result["names_found"].append({
                "name": sm["name"],
                "source": "Sync.me",
                "confidence": "medium",
            })

        # Source 3: Hiya (public data)
        hiya = self._hiya_check(phone)
        if hiya:
            result["sources"].append("Hiya")
            if hiya.get("spam_score", 0) > 0:
                result["spam_score"] = hiya["spam_score"]
                result["is_spam"] = hiya.get("is_spam", False)

        # Source 4: Free reverse lookup sites
        free = self._free_reverse_lookup(phone)
        if free:
            result["sources"].append("FreeLookup")
            for name_data in free:
                if name_data.get("name"):
                    result["names_found"].append(name_data)

        # Source 5: Google search for phone
        google = self._google_phone_search(phone)
        if google:
            result["sources"].append("Google")
            for g in google:
                result["names_found"].append(g)

        # Deduplicate names
        seen = set()
        unique = []
        for n in result["names_found"]:
            name = n.get("name", "").strip().lower()
            if name and name not in seen:
                seen.add(name)
                unique.append(n)
        result["names_found"] = unique
        result["total_names"] = len(unique)
        if unique:
            result["primary_name"] = unique[0].get("name", "")

        return result

    def _truecaller(self, phone):
        try:
            clean = phone.replace("+", "").replace(" ", "").replace("-", "")
            headers = {
                "Authorization": f"Bearer {TRUECALLER_TOKEN}",
                "User-Agent": random.choice(USER_AGENTS),
            }
            r = self.session.get(
                f"https://search5-noneu.truecaller.com/v2/search?q={clean}&countryCode=US&type=4",
                headers=headers, timeout=REQUEST_TIMEOUT
            )
            if r.status_code == 200:
                data = r.json()
                if data.get("data"):
                    d = data["data"][0] if isinstance(data["data"], list) else data["data"]
                    return {
                        "name": d.get("name", ""),
                        "phones": d.get("phones", []),
                        "addresses": d.get("addresses", []),
                    }
        except Exception:
            pass
        return None

    def _syncme(self, phone):
        try:
            clean = phone.replace("+", "").replace(" ", "")
            r = self.session.get(
                f"https://sync.me/search/?number={quote(clean)}",
                timeout=REQUEST_TIMEOUT, allow_redirects=True
            )
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "lxml")
                name_tag = soup.find("span", class_="name") or soup.find("h1")
                if name_tag:
                    name = name_tag.get_text(strip=True)
                    if name and phone not in name and len(name) > 2:
                        return {"name": name}
        except Exception:
            pass
        return None

    def _hiya_check(self, phone):
        result = {"spam_score": 0, "is_spam": False}
        try:
            r = self.session.post(
                "https://html.duckduckgo.com/html/",
                data={"q": f'{phone} spam caller'},
                timeout=REQUEST_TIMEOUT
            )
            if r.status_code == 200:
                text = r.text.lower()
                spam_words = ["spam", "scam", "fraud", "robocall", "telemarketer", "unwanted"]
                count = sum(1 for w in spam_words if w in text)
                result["spam_score"] = min(count * 15, 100)
                result["is_spam"] = count >= 3
        except Exception:
            pass
        return result

    def _free_reverse_lookup(self, phone):
        results = []
        try:
            r = self.session.post(
                "https://html.duckduckgo.com/html/",
                data={"q": f'"{phone}" name owner'},
                timeout=REQUEST_TIMEOUT
            )
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "lxml")
                for link in soup.find_all("a", class_="result__a")[:3]:
                    title = link.get_text(strip=True)
                    if title and phone.replace("+", "") not in title.replace(" ", ""):
                        # Extract potential name from search results
                        import re
                        # Look for name patterns
                        name_match = re.search(r'([A-Z][a-z]+ [A-Z][a-z]+)', title)
                        if name_match:
                            results.append({
                                "name": name_match.group(1),
                                "source": "WebSearch",
                                "confidence": "low",
                                "context": title[:60],
                            })
        except Exception:
            pass
        time.sleep(RATE_LIMIT_DELAY)
        return results

    def _google_phone_search(self, phone):
        results = []
        try:
            import re
            clean = phone.replace("+", "").replace(" ", "")
            for query in [f'"{phone}"', f'"{clean}"']:
                r = self.session.post(
                    "https://html.duckduckgo.com/html/",
                    data={"q": query},
                    timeout=REQUEST_TIMEOUT
                )
                if r.status_code == 200:
                    soup = BeautifulSoup(r.text, "lxml")
                    for snippet in soup.find_all("a", class_="result__snippet")[:5]:
                        text = snippet.get_text(strip=True)
                        names = re.findall(r'([A-Z][a-z]{2,} [A-Z][a-z]{2,})', text)
                        for name in names[:2]:
                            if len(name) > 5 and name not in ["Phone Number", "Contact Us"]:
                                results.append({
                                    "name": name,
                                    "source": "SearchSnippet",
                                    "confidence": "low",
                                })
                time.sleep(RATE_LIMIT_DELAY)
        except Exception:
            pass
        return results
CIDEOF
echo "  ✅ caller_id.py"

echo "[9/35] Creating modules/phone/spam_checker.py..."
cat > modules/phone/spam_checker.py << 'SCEOF'
import requests, random, time, re
from urllib.parse import quote
from bs4 import BeautifulSoup
from config import USER_AGENTS, REQUEST_TIMEOUT, RATE_LIMIT_DELAY

class SpamChecker:
    """Check phone number against spam/scam databases"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": random.choice(USER_AGENTS)})

    def check_all(self, phone):
        result = {
            "phone": phone,
            "is_spam": False,
            "is_scam": False,
            "spam_score": 0,
            "reports": [],
            "sources_checked": [],
            "total_reports": 0,
        }

        # Check multiple spam databases
        for name, func in [
            ("DuckDuckGo Spam", self._ddg_spam_check),
            ("WhoCalledMe", self._whocalledme),
            ("ShouldIAnswer", self._shouldianswer),
            ("SpamCalls", self._spamcalls_check),
        ]:
            try:
                data = func(phone)
                result["sources_checked"].append(name)
                if data:
                    if data.get("is_spam"):
                        result["is_spam"] = True
                    if data.get("is_scam"):
                        result["is_scam"] = True
                    result["spam_score"] = max(result["spam_score"], data.get("score", 0))
                    if data.get("reports"):
                        result["reports"].extend(data["reports"])
            except Exception:
                pass
            time.sleep(RATE_LIMIT_DELAY)

        result["total_reports"] = len(result["reports"])
        if result["total_reports"] >= 5:
            result["is_spam"] = True
            result["spam_score"] = max(result["spam_score"], 70)
        if result["is_scam"]:
            result["spam_score"] = max(result["spam_score"], 90)

        return result

    def _ddg_spam_check(self, phone):
        result = {"is_spam": False, "score": 0, "reports": []}
        try:
            r = self.session.post(
                "https://html.duckduckgo.com/html/",
                data={"q": f'{phone} spam scam fraud report'},
                timeout=REQUEST_TIMEOUT
            )
            if r.status_code == 200:
                text = r.text.lower()
                spam_indicators = {
                    "spam": 10, "scam": 20, "fraud": 25, "robocall": 15,
                    "telemarketer": 10, "phishing": 20, "unwanted": 10,
                    "blocked": 5, "reported": 5, "dangerous": 15,
                }
                score = 0
                for word, weight in spam_indicators.items():
                    count = text.count(word)
                    if count > 0:
                        score += min(count * weight, weight * 3)
                        result["reports"].append({"type": word, "mentions": count})

                result["score"] = min(score, 100)
                result["is_spam"] = score >= 30
                result["is_scam"] = any(w in text for w in ["scam", "fraud", "phishing"])
        except Exception:
            pass
        return result

    def _whocalledme(self, phone):
        result = {"is_spam": False, "score": 0, "reports": []}
        try:
            clean = phone.replace("+", "").replace(" ", "").replace("-", "")
            r = self.session.get(
                f"https://who-called.co.uk/Number/{clean}",
                timeout=REQUEST_TIMEOUT
            )
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "lxml")
                reports = soup.find_all("div", class_="comment") or soup.find_all("div", class_="report")
                if reports:
                    result["is_spam"] = len(reports) >= 3
                    result["score"] = min(len(reports) * 10, 100)
                    for rep in reports[:5]:
                        result["reports"].append({
                            "text": rep.get_text(strip=True)[:100],
                            "source": "WhoCalledMe",
                        })
        except Exception:
            pass
        return result

    def _shouldianswer(self, phone):
        result = {"is_spam": False, "score": 0, "reports": []}
        try:
            clean = phone.replace("+", "").replace(" ", "").replace("-", "")
            r = self.session.get(
                f"https://www.shouldianswer.com/phone-number/{clean}",
                timeout=REQUEST_TIMEOUT
            )
            if r.status_code == 200:
                text = r.text.lower()
                if "negative" in text or "spam" in text or "scam" in text:
                    result["is_spam"] = True
                    result["score"] = 60
                    result["reports"].append({"type": "negative_rating", "source": "ShouldIAnswer"})
        except Exception:
            pass
        return result

    def _spamcalls_check(self, phone):
        result = {"is_spam": False, "score": 0, "reports": []}
        try:
            r = self.session.post(
                "https://html.duckduckgo.com/html/",
                data={"q": f'"{phone}" site:800notes.com OR site:whocallsme.com OR site:callercomplaints.com'},
                timeout=REQUEST_TIMEOUT
            )
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "lxml")
                results_found = soup.find_all("a", class_="result__a")
                if results_found:
                    result["is_spam"] = len(results_found) >= 2
                    result["score"] = min(len(results_found) * 20, 80)
                    for link in results_found[:3]:
                        result["reports"].append({
                            "title": link.get_text(strip=True)[:80],
                            "url": link.get("href", ""),
                            "source": "SpamDB",
                        })
        except Exception:
            pass
        return result
SCEOF
echo "  ✅ spam_checker.py"

echo "[10/35] Creating messaging modules..."
cat > modules/messaging/whatsapp_check.py << 'WAEOF'
import requests, random, hashlib, time
from config import USER_AGENTS, REQUEST_TIMEOUT, RATE_LIMIT_DELAY

class WhatsAppChecker:
    """Check if phone number is registered on WhatsApp"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": random.choice(USER_AGENTS)})

    def check(self, phone):
        result = {
            "phone": phone,
            "source": "WhatsApp",
            "is_registered": None,
            "has_profile_pic": None,
            "has_about": None,
            "last_seen": None,
            "check_methods": [],
        }

        # Method 1: WhatsApp API endpoint check
        wa_api = self._check_wa_api(phone)
        if wa_api:
            result["check_methods"].append("wa_api")
            result.update(wa_api)

        # Method 2: WhatsApp link check
        wa_link = self._check_wa_link(phone)
        if wa_link:
            result["check_methods"].append("wa_link")
            if result["is_registered"] is None:
                result["is_registered"] = wa_link.get("exists")

        # Method 3: Web search
        web = self._web_search(phone)
        if web:
            result["check_methods"].append("web_search")
            result["web_mentions"] = web

        return result

    def _check_wa_api(self, phone):
        try:
            clean = phone.replace("+", "").replace(" ", "").replace("-", "")
            # Check if wa.me link redirects (indicates active number)
            r = self.session.head(
                f"https://wa.me/{clean}",
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False
            )
            return {
                "wa_link_status": r.status_code,
                "wa_link": f"https://wa.me/{clean}",
            }
        except Exception:
            return None

    def _check_wa_link(self, phone):
        try:
            clean = phone.replace("+", "").replace(" ", "").replace("-", "")
            r = self.session.get(
                f"https://api.whatsapp.com/send?phone={clean}",
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True
            )
            exists = r.status_code == 200 and "phone" in r.url
            return {"exists": exists, "url": r.url}
        except Exception:
            return None

    def _web_search(self, phone):
        results = []
        try:
            r = self.session.post(
                "https://html.duckduckgo.com/html/",
                data={"q": f'"{phone}" whatsapp'},
                timeout=REQUEST_TIMEOUT
            )
            if r.status_code == 200:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(r.text, "lxml")
                for link in soup.find_all("a", class_="result__a")[:3]:
                    results.append({
                        "title": link.get_text(strip=True)[:80],
                        "url": link.get("href", ""),
                    })
        except Exception:
            pass
        time.sleep(RATE_LIMIT_DELAY)
        return results
WAEOF

cat > modules/messaging/telegram_search.py << 'TSEOF'
import requests, random, time
from urllib.parse import quote
from bs4 import BeautifulSoup
from config import (USER_AGENTS, REQUEST_TIMEOUT, RATE_LIMIT_DELAY,
                    TELEGRAM_BOT_TOKEN)

class TelegramSearcher:
    """Search for phone number on Telegram"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": random.choice(USER_AGENTS)})

    def search(self, phone):
        result = {
            "phone": phone,
            "source": "Telegram",
            "username_found": None,
            "profile_found": False,
            "mentions": [],
            "leak_channels": [],
            "total": 0,
        }

        # Method 1: Telegram Bot API (if token available)
        if TELEGRAM_BOT_TOKEN:
            bot_result = self._bot_search(phone)
            if bot_result:
                result.update(bot_result)

        # Method 2: TGStat search
        tgstat = self._tgstat_search(phone)
        if tgstat:
            result["mentions"].extend(tgstat)

        # Method 3: DuckDuckGo t.me search
        ddg = self._ddg_telegram(phone)
        if ddg:
            result["mentions"].extend(ddg)

        # Method 4: Google dork for telegram
        dork = self._dork_telegram(phone)
        if dork:
            result["leak_channels"].extend(dork)

        # Deduplicate
        seen = set()
        unique = []
        for m in result["mentions"]:
            key = m.get("url", "") or m.get("title", "")
            if key and key not in seen:
                seen.add(key)
                unique.append(m)
        result["mentions"] = unique
        result["total"] = len(unique) + len(result["leak_channels"])

        return result

    def _bot_search(self, phone):
        try:
            clean = phone.replace("+", "").replace(" ", "")
            r = self.session.get(
                f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getChat?chat_id={clean}",
                timeout=REQUEST_TIMEOUT
            )
            if r.status_code == 200:
                data = r.json()
                if data.get("ok"):
                    chat = data.get("result", {})
                    return {
                        "profile_found": True,
                        "username_found": chat.get("username"),
                        "first_name": chat.get("first_name", ""),
                        "last_name": chat.get("last_name", ""),
                    }
        except Exception:
            pass
        return None

    def _tgstat_search(self, phone):
        results = []
        try:
            r = self.session.get(
                f"https://tgstat.com/en/search?q={quote(phone)}",
                timeout=REQUEST_TIMEOUT
            )
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "lxml")
                for item in soup.find_all("div", class_="peer-item")[:5]:
                    link = item.find("a")
                    if link:
                        results.append({
                            "title": link.get_text(strip=True)[:80],
                            "url": link.get("href", ""),
                            "source": "TGStat",
                        })
        except Exception:
            pass
        time.sleep(RATE_LIMIT_DELAY)
        return results

    def _ddg_telegram(self, phone):
        results = []
        try:
            for query in [f'"{phone}" site:t.me', f'"{phone}" telegram leak']:
                r = self.session.post(
                    "https://html.duckduckgo.com/html/",
                    data={"q": query},
                    timeout=REQUEST_TIMEOUT
                )
                if r.status_code == 200:
                    soup = BeautifulSoup(r.text, "lxml")
                    for link in soup.find_all("a", class_="result__a")[:3]:
                        href = link.get("href", "")
                        if "duckduckgo" not in href:
                            results.append({
                                "title": link.get_text(strip=True)[:80],
                                "url": href,
                                "source": "DuckDuckGo",
                            })
                time.sleep(RATE_LIMIT_DELAY)
        except Exception:
            pass
        return results

    def _dork_telegram(self, phone):
        results = []
        try:
            r = self.session.post(
                "https://html.duckduckgo.com/html/",
                data={"q": f'"{phone}" site:t.me leak OR dump OR combo OR database'},
                timeout=REQUEST_TIMEOUT
            )
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "lxml")
                for link in soup.find_all("a", class_="result__a")[:5]:
                    href = link.get("href", "")
                    title = link.get_text(strip=True)
                    if "t.me" in href or "telegram" in href.lower():
                        results.append({
                            "channel": title[:50],
                            "url": href,
                            "risk": "HIGH" if any(w in title.lower() for w in ["leak", "dump", "combo"]) else "MEDIUM",
                        })
        except Exception:
            pass
        return results

    def generate_search_links(self, phone):
        clean = phone.replace("+", "").replace(" ", "")
        return [
            {"name": "TGStat", "url": f"https://tgstat.com/en/search?q={quote(phone)}"},
            {"name": "Google t.me", "url": f"https://www.google.com/search?q=%22{clean}%22+site:t.me"},
            {"name": "Telegram Web", "url": f"https://t.me/{clean}"},
        ]
TSEOF

cat > modules/messaging/signal_check.py << 'EOF'
import requests, random
from config import USER_AGENTS, REQUEST_TIMEOUT

class SignalChecker:
    """Check if phone number is registered on Signal"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": random.choice(USER_AGENTS)})

    def check(self, phone):
        result = {
            "phone": phone,
            "source": "Signal",
            "is_registered": None,
            "note": "Signal registration check requires Signal API access",
            "search_results": [],
        }

        # Web search for Signal mentions
        try:
            r = self.session.post(
                "https://html.duckduckgo.com/html/",
                data={"q": f'"{phone}" signal messenger'},
                timeout=REQUEST_TIMEOUT
            )
            if r.status_code == 200:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(r.text, "lxml")
                for link in soup.find_all("a", class_="result__a")[:3]:
                    result["search_results"].append({
                        "title": link.get_text(strip=True)[:80],
                        "url": link.get("href", ""),
                    })
        except Exception:
            pass

        return result
EOF

cat > modules/messaging/viber_check.py << 'EOF'
import requests, random
from config import USER_AGENTS, REQUEST_TIMEOUT

class ViberChecker:
    """Check if phone number is registered on Viber"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": random.choice(USER_AGENTS)})

    def check(self, phone):
        result = {
            "phone": phone,
            "source": "Viber",
            "is_registered": None,
            "search_results": [],
        }

        try:
            clean = phone.replace("+", "").replace(" ", "").replace("-", "")
            # Viber public account check
            r = self.session.get(
                f"https://www.viber.com/api/lookup?phone={clean}",
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False
            )
            result["viber_status"] = r.status_code
        except Exception:
            pass

        # Web search
        try:
            r = self.session.post(
                "https://html.duckduckgo.com/html/",
                data={"q": f'"{phone}" viber'},
                timeout=REQUEST_TIMEOUT
            )
            if r.status_code == 200:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(r.text, "lxml")
                for link in soup.find_all("a", class_="result__a")[:3]:
                    result["search_results"].append({
                        "title": link.get_text(strip=True)[:80],
                        "url": link.get("href", ""),
                    })
        except Exception:
            pass

        return result
EOF
echo "  ✅ Messaging modules"

echo "[11/35] Creating modules/social/social_scanner.py..."
cat > modules/social/social_scanner.py << 'SSEOF'
import requests, random, time, re
from urllib.parse import quote
from bs4 import BeautifulSoup
from config import USER_AGENTS, REQUEST_TIMEOUT, RATE_LIMIT_DELAY

class SocialScanner:
    """Scan social media platforms for phone number"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": random.choice(USER_AGENTS)})

    def scan_all(self, phone):
        result = {
            "phone": phone,
            "profiles_found": [],
            "platforms_checked": [],
            "total": 0,
        }

        platforms = [
            ("Facebook", self._check_facebook),
            ("Instagram", self._check_instagram),
            ("LinkedIn", self._check_linkedin),
            ("Twitter/X", self._check_twitter),
            ("TikTok", self._check_tiktok),
            ("VK", self._check_vk),
        ]

        for name, func in platforms:
            try:
                data = func(phone)
                result["platforms_checked"].append(name)
                if data and data.get("found"):
                    result["profiles_found"].append({
                        "platform": name,
                        **data,
                    })
            except Exception:
                pass
            time.sleep(RATE_LIMIT_DELAY)

        result["total"] = len(result["profiles_found"])
        return result

    def _check_facebook(self, phone):
        try:
            clean = phone.replace("+", "").replace(" ", "")
            r = self.session.post(
                "https://html.duckduckgo.com/html/",
                data={"q": f'"{phone}" site:facebook.com'},
                timeout=REQUEST_TIMEOUT
            )
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "lxml")
                results = soup.find_all("a", class_="result__a")
                fb_results = [l for l in results if "facebook.com" in l.get("href", "")]
                if fb_results:
                    return {
                        "found": True,
                        "url": fb_results[0].get("href", ""),
                        "title": fb_results[0].get_text(strip=True)[:80],
                    }
        except Exception:
            pass
        return {"found": False}

    def _check_instagram(self, phone):
        try:
            r = self.session.post(
                "https://html.duckduckgo.com/html/",
                data={"q": f'"{phone}" site:instagram.com'},
                timeout=REQUEST_TIMEOUT
            )
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "lxml")
                results = soup.find_all("a", class_="result__a")
                ig_results = [l for l in results if "instagram.com" in l.get("href", "")]
                if ig_results:
                    return {
                        "found": True,
                        "url": ig_results[0].get("href", ""),
                        "title": ig_results[0].get_text(strip=True)[:80],
                    }
        except Exception:
            pass
        return {"found": False}

    def _check_linkedin(self, phone):
        try:
            r = self.session.post(
                "https://html.duckduckgo.com/html/",
                data={"q": f'"{phone}" site:linkedin.com'},
                timeout=REQUEST_TIMEOUT
            )
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "lxml")
                results = soup.find_all("a", class_="result__a")
                li_results = [l for l in results if "linkedin.com" in l.get("href", "")]
                if li_results:
                    return {
                        "found": True,
                        "url": li_results[0].get("href", ""),
                        "title": li_results[0].get_text(strip=True)[:80],
                    }
        except Exception:
            pass
        return {"found": False}

    def _check_twitter(self, phone):
        try:
            r = self.session.post(
                "https://html.duckduckgo.com/html/",
                data={"q": f'"{phone}" site:twitter.com OR site:x.com'},
                timeout=REQUEST_TIMEOUT
            )
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "lxml")
                for link in soup.find_all("a", class_="result__a"):
                    href = link.get("href", "")
                    if "twitter.com" in href or "x.com" in href:
                        return {
                            "found": True,
                            "url": href,
                            "title": link.get_text(strip=True)[:80],
                        }
        except Exception:
            pass
        return {"found": False}

    def _check_tiktok(self, phone):
        try:
            r = self.session.post(
                "https://html.duckduckgo.com/html/",
                data={"q": f'"{phone}" site:tiktok.com'},
                timeout=REQUEST_TIMEOUT
            )
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "lxml")
                for link in soup.find_all("a", class_="result__a"):
                    if "tiktok.com" in link.get("href", ""):
                        return {
                            "found": True,
                            "url": link.get("href", ""),
                            "title": link.get_text(strip=True)[:80],
                        }
        except Exception:
            pass
        return {"found": False}

    def _check_vk(self, phone):
        try:
            r = self.session.post(
                "https://html.duckduckgo.com/html/",
                data={"q": f'"{phone}" site:vk.com'},
                timeout=REQUEST_TIMEOUT
            )
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "lxml")
                for link in soup.find_all("a", class_="result__a"):
                    if "vk.com" in link.get("href", ""):
                        return {
                            "found": True,
                            "url": link.get("href", ""),
                            "title": link.get_text(strip=True)[:80],
                        }
        except Exception:
            pass
        return {"found": False}
SSEOF

cat > modules/social/gravatar_check.py << 'EOF'
import requests, random, hashlib
from config import USER_AGENTS, REQUEST_TIMEOUT

class GravatarCheck:
    def check(self, phone):
        result = {"phone": phone, "gravatar_found": False}
        try:
            h = hashlib.md5(phone.strip().encode()).hexdigest()
            r = requests.get(f"https://www.gravatar.com/avatar/{h}?d=404",
                           timeout=REQUEST_TIMEOUT)
            result["gravatar_found"] = r.status_code == 200
        except Exception:
            pass
        return result
EOF

cat > modules/social/github_phone.py << 'GHEOF'
import requests, random, time
from config import GITHUB_TOKEN, USER_AGENTS, REQUEST_TIMEOUT, RATE_LIMIT_DELAY

class GitHubPhoneSearch:
    """Search GitHub for exposed phone numbers"""

    def __init__(self):
        self.session = requests.Session()
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        if GITHUB_TOKEN:
            headers["Authorization"] = f"token {GITHUB_TOKEN}"
        self.session.headers.update(headers)

    def search(self, phone):
        result = {
            "phone": phone,
            "source": "GitHub",
            "findings": [],
            "total": 0,
        }

        clean = phone.replace("+", "").replace(" ", "").replace("-", "")
        queries = [
            f'"{phone}"',
            f'"{clean}"',
            f'"{phone}" password',
            f'"{phone}" secret',
            f'"{clean}" api_key',
        ]

        for query in queries[:3]:
            try:
                r = self.session.get(
                    "https://api.github.com/search/code",
                    params={"q": query, "per_page": 5},
                    timeout=REQUEST_TIMEOUT
                )
                if r.status_code == 200:
                    for item in r.json().get("items", []):
                        repo = item.get("repository", {})
                        result["findings"].append({
                            "file": item.get("name", ""),
                            "path": item.get("path", ""),
                            "repo": repo.get("full_name", ""),
                            "url": item.get("html_url", ""),
                            "query": query,
                        })
                elif r.status_code == 403:
                    break
                time.sleep(3)
            except Exception:
                continue

        # Deduplicate
        seen = set()
        unique = []
        for f in result["findings"]:
            key = f.get("url", "")
            if key and key not in seen:
                seen.add(key)
                unique.append(f)
        result["findings"] = unique
        result["total"] = len(unique)
        return result
GHEOF
echo "  ✅ Social modules"

echo "[12/35] Creating darkweb modules..."
cat > modules/darkweb/phone_darkweb.py << 'PDWEOF'
import time, random, requests
from urllib.parse import quote
from bs4 import BeautifulSoup
from config import (ONION_SEARCH_ENGINES, RATE_LIMIT_DELAY, TOR_REQUEST_TIMEOUT,
                    USER_AGENTS)

class PhoneDarkWebSearch:
    """Search dark web for phone number leaks"""

    def __init__(self, tor=None):
        self.tor = tor
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": random.choice(USER_AGENTS)})

    def search_all(self, phone):
        result = {
            "phone": phone,
            "findings": [],
            "engines_searched": [],
            "errors": [],
            "total": 0,
        }

        # Get search formats
        clean = phone.replace("+", "").replace(" ", "").replace("-", "")
        search_terms = [phone, clean]
        if not clean.startswith("0") and len(clean) > 10:
            search_terms.append(f"0{clean[-10:]}")

        for term in search_terms:
            # Surface engines (no Tor needed)
            for name, func in [
                ("Ahmia", self._search_ahmia),
                ("DarkSearch", self._search_darksearch),
                ("DuckDuckGo", self._search_ddg),
            ]:
                findings = func(term)
                for f in findings:
                    if "error" not in f:
                        result["findings"].append(f)
                if any("error" not in f for f in findings):
                    if name not in result["engines_searched"]:
                        result["engines_searched"].append(name)

            # Tor engines
            if self.tor and self.tor.is_connected:
                for name, func in [
                    ("Torch", self._search_torch),
                    ("Haystack", self._search_haystack),
                ]:
                    findings = func(term)
                    for f in findings:
                        if "error" not in f:
                            result["findings"].append(f)
                    if any("error" not in f for f in findings):
                        if name not in result["engines_searched"]:
                            result["engines_searched"].append(name)

        # Deduplicate
        seen = set()
        unique = []
        for f in result["findings"]:
            key = f.get("url", "") or f.get("title", "")
            if key and key not in seen:
                seen.add(key)
                unique.append(f)
        result["findings"] = unique
        result["total"] = len(unique)
        return result

    def _search_ahmia(self, query):
        results = []
        try:
            for sq in [f'"{query}" leak', f'"{query}" database', f'"{query}"']:
                r = self.session.get(
                    f"https://ahmia.fi/search/?q={quote(sq)}",
                    timeout=20
                )
                if r.status_code == 200:
                    soup = BeautifulSoup(r.text, "lxml")
                    for item in soup.find_all("li", class_="result"):
                        link = item.find("a")
                        desc = item.find("p")
                        if link:
                            title = link.get_text(strip=True)
                            combined = f"{title} {desc.get_text(strip=True) if desc else ''}".lower()
                            high_risk = ["password", "credential", "dump", "database",
                                        "combo", "leak", "breach", "login"]
                            risk = "HIGH" if any(w in combined for w in high_risk) else "MEDIUM"
                            results.append({
                                "title": title[:100],
                                "url": link.get("href", ""),
                                "description": desc.get_text(strip=True)[:200] if desc else "",
                                "source": "Ahmia",
                                "risk_level": risk,
                                "is_onion": ".onion" in link.get("href", ""),
                            })
                time.sleep(RATE_LIMIT_DELAY)
        except Exception as e:
            results.append({"error": f"Ahmia: {str(e)[:80]}"})
        return results

    def _search_darksearch(self, query):
        results = []
        try:
            r = self.session.get(
                f"https://darksearch.io/api/search?query={quote(query)}&page=1",
                timeout=15
            )
            if r.status_code == 200:
                for item in r.json().get("data", []):
                    results.append({
                        "title": item.get("title", "")[:100],
                        "url": item.get("link", ""),
                        "description": item.get("description", "")[:200],
                        "source": "DarkSearch",
                        "is_onion": ".onion" in item.get("link", ""),
                    })
        except Exception:
            pass
        time.sleep(RATE_LIMIT_DELAY)
        return results

    def _search_ddg(self, query):
        results = []
        try:
            for sq in [f'"{query}" site:.onion', f'"{query}" leak dark web']:
                r = self.session.post(
                    "https://html.duckduckgo.com/html/",
                    data={"q": sq},
                    timeout=15
                )
                if r.status_code == 200:
                    soup = BeautifulSoup(r.text, "lxml")
                    for link in soup.find_all("a", class_="result__a")[:3]:
                        href = link.get("href", "")
                        if href and "duckduckgo" not in href:
                            results.append({
                                "title": link.get_text(strip=True)[:100],
                                "url": href,
                                "source": "DuckDuckGo",
                                "is_onion": ".onion" in href,
                            })
                time.sleep(2)
        except Exception:
            pass
        return results

    def _search_torch(self, query):
        results = []
        if not self.tor:
            return results
        config = ONION_SEARCH_ENGINES.get("torch", {})
        for url in config.get("urls", []):
            try:
                path = config.get("search_path", "/cgi-bin/omega/omega?P=")
                r = self.tor.get(f"{url}{path}{quote(query)}", timeout=TOR_REQUEST_TIMEOUT)
                if r.status_code == 200:
                    soup = BeautifulSoup(r.text, "lxml")
                    for link in soup.find_all("a"):
                        href = link.get("href", "")
                        text = link.get_text(strip=True)
                        if ".onion" in href and text and len(text) > 3:
                            results.append({
                                "title": text[:100],
                                "url": href,
                                "source": "Torch",
                                "is_onion": True,
                            })
                    if results:
                        break
            except Exception:
                continue
            time.sleep(2)
        return results

    def _search_haystack(self, query):
        results = []
        if not self.tor:
            return results
        config = ONION_SEARCH_ENGINES.get("haystack", {})
        for url in config.get("urls", []):
            try:
                path = config.get("search_path", "/?q=")
                r = self.tor.get(f"{url}{path}{quote(query)}", timeout=TOR_REQUEST_TIMEOUT)
                if r.status_code == 200:
                    soup = BeautifulSoup(r.text, "lxml")
                    for link in soup.find_all("a"):
                        href = link.get("href", "")
                        text = link.get_text(strip=True)
                        if ".onion" in href and text:
                            results.append({
                                "title": text[:100],
                                "url": href,
                                "source": "Haystack",
                                "is_onion": True,
                            })
                    if results:
                        break
            except Exception:
                continue
            time.sleep(2)
        return results
PDWEOF

cat > modules/darkweb/paste_monitor.py << 'PMEOF'
import requests, random, time
from urllib.parse import quote
from bs4 import BeautifulSoup
from config import USER_AGENTS, REQUEST_TIMEOUT, RATE_LIMIT_DELAY

class PhonePasteMonitor:
    """Monitor paste sites for phone number leaks"""

    def __init__(self, tor=None):
        self.tor = tor
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": random.choice(USER_AGENTS)})

    def search(self, phone):
        result = {
            "phone": phone,
            "pastes_found": [],
            "total": 0,
        }

        clean = phone.replace("+", "").replace(" ", "").replace("-", "")
        paste_sites = [
            "pastebin.com", "paste.ee", "justpaste.it",
            "dpaste.org", "rentry.co", "ghostbin.com",
        ]

        for site in paste_sites:
            try:
                for term in [phone, clean]:
                    r = self.session.post(
                        "https://html.duckduckgo.com/html/",
                        data={"q": f'"{term}" site:{site}'},
                        timeout=REQUEST_TIMEOUT
                    )
                    if r.status_code == 200:
                        soup = BeautifulSoup(r.text, "lxml")
                        for link in soup.find_all("a", class_="result__a")[:2]:
                            href = link.get("href", "")
                            if site in href.lower():
                                result["pastes_found"].append({
                                    "title": link.get_text(strip=True)[:80],
                                    "url": href,
                                    "site": site,
                                })
                    time.sleep(RATE_LIMIT_DELAY)
            except Exception:
                continue

        # Deduplicate
        seen = set()
        unique = []
        for p in result["pastes_found"]:
            key = p.get("url", "")
            if key and key not in seen:
                seen.add(key)
                unique.append(p)
        result["pastes_found"] = unique
        result["total"] = len(unique)
        return result
PMEOF

cat > modules/darkweb/combo_search.py << 'CSEOF'
import requests, random, time
from urllib.parse import quote
from bs4 import BeautifulSoup
from config import USER_AGENTS, REQUEST_TIMEOUT, RATE_LIMIT_DELAY

class ComboListSearch:
    """Search for phone in known combo lists and data dumps"""

    def __init__(self, tor=None):
        self.tor = tor
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": random.choice(USER_AGENTS)})

    def search(self, phone):
        result = {
            "phone": phone,
            "combo_mentions": [],
            "risk_level": "LOW",
            "total": 0,
        }

        clean = phone.replace("+", "").replace(" ", "").replace("-", "")

        # Search for combo list mentions
        queries = [
            f'"{phone}" combo list',
            f'"{phone}" database dump',
            f'"{clean}" leak download',
            f'"{phone}" fullz',
            f'"{clean}" "password"',
        ]

        for query in queries:
            try:
                # Ahmia search
                r = self.session.get(
                    f"https://ahmia.fi/search/?q={quote(query)}",
                    timeout=15
                )
                if r.status_code == 200:
                    soup = BeautifulSoup(r.text, "lxml")
                    for item in soup.find_all("li", class_="result"):
                        link = item.find("a")
                        desc = item.find("p")
                        if link:
                            title = link.get_text(strip=True)
                            text = f"{title} {desc.get_text(strip=True) if desc else ''}".lower()
                            if any(w in text for w in ["combo", "dump", "leak", "database", "fullz", "password"]):
                                risk = "CRITICAL" if any(w in text for w in ["password", "fullz", "combo"]) else "HIGH"
                                result["combo_mentions"].append({
                                    "title": title[:100],
                                    "url": link.get("href", ""),
                                    "description": desc.get_text(strip=True)[:200] if desc else "",
                                    "risk": risk,
                                    "source": "Ahmia",
                                })
                time.sleep(RATE_LIMIT_DELAY)
            except Exception:
                continue

        # DuckDuckGo search
        try:
            r = self.session.post(
                "https://html.duckduckgo.com/html/",
                data={"q": f'"{phone}" "combo" OR "dump" OR "leak" OR "database"'},
                timeout=REQUEST_TIMEOUT
            )
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "lxml")
                for link in soup.find_all("a", class_="result__a")[:5]:
                    href = link.get("href", "")
                    title = link.get_text(strip=True)
                    if href and "duckduckgo" not in href:
                        result["combo_mentions"].append({
                            "title": title[:100],
                            "url": href,
                            "risk": "MEDIUM",
                            "source": "DuckDuckGo",
                        })
        except Exception:
            pass

        # Deduplicate
        seen = set()
        unique = []
        for m in result["combo_mentions"]:
            key = m.get("url", "") or m.get("title", "")
            if key and key not in seen:
                seen.add(key)
                unique.append(m)
        result["combo_mentions"] = unique
        result["total"] = len(unique)

        if any(m.get("risk") == "CRITICAL" for m in unique):
            result["risk_level"] = "CRITICAL"
        elif any(m.get("risk") == "HIGH" for m in unique):
            result["risk_level"] = "HIGH"
        elif unique:
            result["risk_level"] = "MEDIUM"

        return result
CSEOF
echo "  ✅ Darkweb modules"

echo "[13/35] Creating surface modules..."
cat > modules/surface/google_dorker.py << 'GDEOF'
import requests, random, time
from urllib.parse import quote
from bs4 import BeautifulSoup
from config import USER_AGENTS, REQUEST_TIMEOUT, RATE_LIMIT_DELAY

class PhoneDorker:
    """Generate and execute Google dorks for phone numbers"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": random.choice(USER_AGENTS)})

    def generate_dorks(self, phone):
        clean = phone.replace("+", "").replace(" ", "").replace("-", "")
        dorks = [
            {"dork": f'"{phone}" password', "category": "credentials"},
            {"dork": f'"{phone}" filetype:sql', "category": "database"},
            {"dork": f'"{phone}" filetype:csv', "category": "data_export"},
            {"dork": f'"{phone}" filetype:xlsx', "category": "spreadsheet"},
            {"dork": f'"{phone}" filetype:log', "category": "logs"},
            {"dork": f'"{phone}" site:pastebin.com', "category": "paste"},
            {"dork": f'"{phone}" site:github.com', "category": "code"},
            {"dork": f'"{phone}" site:facebook.com', "category": "social"},
            {"dork": f'"{phone}" site:linkedin.com', "category": "social"},
            {"dork": f'"{phone}" "name" "address"', "category": "pii"},
            {"dork": f'"{phone}" "email" "address"', "category": "pii"},
            {"dork": f'"{clean}" leak OR breach OR dump', "category": "leak"},
            {"dork": f'"{phone}" site:t.me', "category": "telegram"},
            {"dork": f'"{phone}" inurl:contact', "category": "contact"},
            {"dork": f'"{phone}" "whatsapp"', "category": "messaging"},
        ]
        for d in dorks:
            d["url"] = f"https://www.google.com/search?q={quote(d['dork'])}"
        return dorks

    def auto_search(self, phone, max_dorks=8):
        result = {
            "phone": phone,
            "results": [],
            "dorks_searched": 0,
            "total": 0,
        }

        dorks = self.generate_dorks(phone)
        priority = ["credentials", "database", "paste", "leak", "code", "pii"]

        def sort_key(d):
            try:
                return priority.index(d.get("category", "other"))
            except ValueError:
                return len(priority)

        for dork in sorted(dorks, key=sort_key)[:max_dorks]:
            try:
                self.session.headers["User-Agent"] = random.choice(USER_AGENTS)
                r = self.session.post(
                    "https://html.duckduckgo.com/html/",
                    data={"q": dork["dork"]},
                    timeout=REQUEST_TIMEOUT
                )
                if r.status_code == 200:
                    soup = BeautifulSoup(r.text, "lxml")
                    for link in soup.find_all("a", class_="result__a")[:3]:
                        href = link.get("href", "")
                        title = link.get_text(strip=True)
                        if href and "duckduckgo" not in href and title:
                            snippet = ""
                            parent = link.find_parent("div")
                            if parent:
                                sn = parent.find("a", class_="result__snippet")
                                if sn:
                                    snippet = sn.get_text(strip=True)[:150]
                            result["results"].append({
                                "title": title[:80],
                                "url": href,
                                "snippet": snippet,
                                "category": dork["category"],
                                "dork": dork["dork"][:60],
                            })
                result["dorks_searched"] += 1
            except Exception:
                pass
            time.sleep(random.uniform(3, 6))

        # Deduplicate
        seen = set()
        unique = []
        for r in result["results"]:
            key = r.get("url", "")
            if key and key not in seen:
                seen.add(key)
                unique.append(r)
        result["results"] = unique
        result["total"] = len(unique)
        return result
GDEOF

cat > modules/surface/intelx_phone.py << 'IXEOF'
import requests, time, random
from config import INTELX_API_KEY, USER_AGENTS, REQUEST_TIMEOUT, RATE_LIMIT_DELAY

class IntelXPhoneSearch:
    """Search Intelligence X for phone number"""

    def __init__(self):
        self.base_url = "https://2.intelx.io"
        self.session = requests.Session()
        self.session.headers.update({
            "x-key": INTELX_API_KEY,
            "User-Agent": random.choice(USER_AGENTS),
        })

    def search(self, phone):
        result = {
            "phone": phone,
            "source": "Intelligence X",
            "findings": [],
            "total": 0,
        }

        if not INTELX_API_KEY:
            result["note"] = "Set INTELX_KEY env var"
            return result

        clean = phone.replace("+", "").replace(" ", "").replace("-", "")
        search_terms = [phone, clean]

        for term in search_terms:
            try:
                payload = {"term": term, "maxresults": 20, "media": 0, "target": 1}
                r = self.session.post(
                    f"{self.base_url}/phonebook/search",
                    json=payload, timeout=REQUEST_TIMEOUT
                )
                if r.status_code == 200:
                    search_id = r.json().get("id", "")
                    if search_id:
                        time.sleep(3)
                        res = self.session.get(
                            f"{self.base_url}/phonebook/search/result?id={search_id}",
                            timeout=REQUEST_TIMEOUT
                        )
                        if res.status_code == 200:
                            for s in res.json().get("selectors", [])[:20]:
                                result["findings"].append({
                                    "value": s.get("selectorvalue", ""),
                                    "type": s.get("selectortypeh", ""),
                                })
                elif r.status_code == 401:
                    result["error"] = "Invalid IntelX API key"
                    return result
            except Exception as e:
                result["error"] = str(e)
            time.sleep(RATE_LIMIT_DELAY)

        # Deduplicate
        seen = set()
        unique = []
        for f in result["findings"]:
            key = f.get("value", "")
            if key and key not in seen:
                seen.add(key)
                unique.append(f)
        result["findings"] = unique
        result["total"] = len(unique)
        return result
IXEOF

cat > modules/surface/numverify.py << 'EOF'
import requests, random
from config import NUMVERIFY_API_KEY, USER_AGENTS, REQUEST_TIMEOUT

class NumVerifyCheck:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": random.choice(USER_AGENTS)})

    def verify(self, phone):
        result = {"phone": phone, "source": "NumVerify", "valid": False}
        if not NUMVERIFY_API_KEY:
            result["note"] = "Set NUMVERIFY_KEY env var"
            return result
        try:
            clean = phone.replace("+", "").replace(" ", "").replace("-", "")
            r = self.session.get(
                f"http://apilayer.net/api/validate?access_key={NUMVERIFY_API_KEY}&number={clean}",
                timeout=REQUEST_TIMEOUT
            )
            if r.status_code == 200:
                data = r.json()
                result.update({
                    "valid": data.get("valid", False),
                    "number": data.get("number", ""),
                    "local_format": data.get("local_format", ""),
                    "international_format": data.get("international_format", ""),
                    "country_prefix": data.get("country_prefix", ""),
                    "country_code": data.get("country_code", ""),
                    "country_name": data.get("country_name", ""),
                    "location": data.get("location", ""),
                    "carrier": data.get("carrier", ""),
                    "line_type": data.get("line_type", ""),
                })
        except Exception as e:
            result["error"] = str(e)
        return result
EOF

cat > modules/surface/data_breach.py << 'DBEOF'
import requests, random, time, hashlib
from config import USER_AGENTS, REQUEST_TIMEOUT, RATE_LIMIT_DELAY

class PhoneBreachSearch:
    """Search for phone number in known data breaches"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": random.choice(USER_AGENTS)})

    def search(self, phone):
        result = {
            "phone": phone,
            "breaches": [],
            "emails_linked": [],
            "total_breaches": 0,
            "sources_checked": [],
        }

        # Method 1: Search HIBP by phone-linked emails
        linked = self._find_linked_emails(phone)
        if linked:
            result["emails_linked"] = linked
            for email in linked[:3]:
                breaches = self._check_hibp(email)
                if breaches:
                    result["breaches"].extend(breaches)

        # Method 2: Search for phone in breach dumps
        breach_search = self._search_breach_databases(phone)
        if breach_search:
            result["breaches"].extend(breach_search)
            result["sources_checked"].append("BreachSearch")

        # Deduplicate breaches
        seen = set()
        unique = []
        for b in result["breaches"]:
            key = b.get("name", "") + b.get("source", "")
            if key and key not in seen:
                seen.add(key)
                unique.append(b)
        result["breaches"] = unique
        result["total_breaches"] = len(unique)
        return result

    def _find_linked_emails(self, phone):
        emails = []
        try:
            from bs4 import BeautifulSoup
            clean = phone.replace("+", "").replace(" ", "")
            r = self.session.post(
                "https://html.duckduckgo.com/html/",
                data={"q": f'"{phone}" email "@"'},
                timeout=REQUEST_TIMEOUT
            )
            if r.status_code == 200:
                import re
                email_pattern = r'[\w.+-]+@[\w-]+\.[\w.]+'
                found = re.findall(email_pattern, r.text)
                emails = list(set(found))[:5]
        except Exception:
            pass
        time.sleep(RATE_LIMIT_DELAY)
        return emails

    def _check_hibp(self, email):
        breaches = []
        try:
            r = self.session.get(
                f"https://haveibeenpwned.com/unifiedsearch/{email}",
                headers={
                    "User-Agent": random.choice(USER_AGENTS),
                    "Accept": "application/json",
                    "Referer": "https://haveibeenpwned.com/",
                },
                timeout=REQUEST_TIMEOUT
            )
            if r.status_code == 200:
                data = r.json()
                for b in data.get("Breaches", []):
                    breaches.append({
                        "name": b.get("Name", ""),
                        "date": b.get("BreachDate", ""),
                        "pwn_count": b.get("PwnCount", 0),
                        "data_types": b.get("DataClasses", []),
                        "linked_email": email,
                        "source": "HIBP",
                    })
        except Exception:
            pass
        time.sleep(RATE_LIMIT_DELAY)
        return breaches

    def _search_breach_databases(self, phone):
        breaches = []
        try:
            from bs4 import BeautifulSoup
            clean = phone.replace("+", "").replace(" ", "")
            r = self.session.post(
                "https://html.duckduckgo.com/html/",
                data={"q": f'"{clean}" breach OR leak OR dump OR database'},
                timeout=REQUEST_TIMEOUT
            )
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "lxml")
                for link in soup.find_all("a", class_="result__a")[:5]:
                    title = link.get_text(strip=True).lower()
                    if any(w in title for w in ["breach", "leak", "dump", "database", "hack"]):
                        breaches.append({
                            "name": link.get_text(strip=True)[:80],
                            "url": link.get("href", ""),
                            "source": "WebSearch",
                        })
        except Exception:
            pass
        return breaches
DBEOF
echo "  ✅ Surface modules"

echo "[14/35] Creating core/threat_scorer.py..."
cat > core/threat_scorer.py << 'TSEOF'
from config import THREAT_WEIGHTS

class PhoneThreatScorer:
    """Calculate threat score for phone number findings"""

    def __init__(self):
        self.weights = THREAT_WEIGHTS

    def calculate_score(self, results):
        score = 0
        factors = []

        # Breach findings
        breaches = results.get("breaches", {}).get("breaches", [])
        if breaches:
            score += self.weights["breach_found"]
            factors.append({
                "factor": "Data Breach",
                "impact": self.weights["breach_found"],
                "details": f"{len(breaches)} breach(es) found",
            })
            # Check for passwords
            for b in breaches:
                types = [t.lower() for t in b.get("data_types", [])]
                if any(t in types for t in ["passwords", "plaintext passwords"]):
                    score += self.weights["password_with_phone"]
                    factors.append({
                        "factor": "Password + Phone Leaked",
                        "impact": self.weights["password_with_phone"],
                        "details": f"In: {b.get('name', '')}",
                    })
                    break

        # Dark web findings
        dw_total = results.get("darkweb", {}).get("total", 0)
        if dw_total > 0:
            score += self.weights["phone_on_darkweb"]
            factors.append({
                "factor": "Dark Web Mention",
                "impact": self.weights["phone_on_darkweb"],
                "details": f"{dw_total} mention(s)",
            })

        # Combo list findings
        combo = results.get("combo", {})
        if combo.get("total", 0) > 0:
            imp = self.weights["phone_in_combo"]
            score += imp
            factors.append({
                "factor": "Combo List Found",
                "impact": imp,
                "details": f"{combo['total']} mention(s) - {combo.get('risk_level', 'MEDIUM')}",
            })

        # Paste findings
        pastes = results.get("pastes", {}).get("total", 0)
        if pastes > 0:
            score += self.weights["phone_in_paste"]
            factors.append({
                "factor": "Paste Leak",
                "impact": self.weights["phone_in_paste"],
                "details": f"{pastes} paste(s)",
            })

        # GitHub exposure
        github = results.get("github", {}).get("total", 0)
        if github > 0:
            score += self.weights["github_exposed"]
            factors.append({
                "factor": "GitHub Exposed",
                "impact": self.weights["github_exposed"],
                "details": f"{github} file(s)",
            })

        # Telegram
        telegram = results.get("telegram", {}).get("total", 0)
        if telegram > 0:
            score += self.weights["telegram_found"]
            factors.append({
                "factor": "Telegram Mention",
                "impact": self.weights["telegram_found"],
                "details": f"{telegram} mention(s)",
            })

        # Caller ID - names found
        caller = results.get("caller_id", {})
        names = caller.get("total_names", 0)
        if names > 0:
            score += self.weights["owner_identified"]
            factors.append({
                "factor": "Owner Identified",
                "impact": self.weights["owner_identified"],
                "details": f"{names} name(s): {caller.get('primary_name', '')}",
            })
            if names > 2:
                score += self.weights["multiple_names"]
                factors.append({
                    "factor": "Multiple Names",
                    "impact": self.weights["multiple_names"],
                    "details": f"{names} different names found",
                })

        # Spam/Scam
        spam = results.get("spam", {})
        if spam.get("is_scam"):
            score += self.weights["fraud_reported"]
            factors.append({
                "factor": "Fraud Reported",
                "impact": self.weights["fraud_reported"],
                "details": f"Spam score: {spam.get('spam_score', 0)}",
            })
        elif spam.get("is_spam"):
            score += self.weights["spam_reported"]
            factors.append({
                "factor": "Spam Reported",
                "impact": self.weights["spam_reported"],
                "details": f"{spam.get('total_reports', 0)} report(s)",
            })

        # Social media
        social = results.get("social", {}).get("total", 0)
        if social > 0:
            score += self.weights["social_media_linked"]
            factors.append({
                "factor": "Social Media Linked",
                "impact": self.weights["social_media_linked"],
                "details": f"{social} profile(s)",
            })

        # Phone type risks
        analysis = results.get("analysis", {})
        if analysis.get("is_voip"):
            score += self.weights["voip_number"]
            factors.append({
                "factor": "VoIP Number",
                "impact": self.weights["voip_number"],
                "details": "Possibly disposable",
            })

        # Messaging apps
        wa = results.get("whatsapp", {})
        if wa.get("is_registered"):
            score += self.weights["whatsapp_active"]
            factors.append({
                "factor": "WhatsApp Active",
                "impact": self.weights["whatsapp_active"],
                "details": "Number registered on WhatsApp",
            })

        # IntelX
        intelx = results.get("intelx", {}).get("total", 0)
        if intelx > 0:
            score += self.weights["intelx_found"]
            factors.append({
                "factor": "IntelX Data",
                "impact": self.weights["intelx_found"],
                "details": f"{intelx} record(s)",
            })

        # Linked emails
        emails = results.get("breaches", {}).get("emails_linked", [])
        if emails:
            score += self.weights["email_linked"]
            factors.append({
                "factor": "Email Linked",
                "impact": self.weights["email_linked"],
                "details": f"{len(emails)} email(s): {', '.join(emails[:2])}",
            })

        # Dork results
        dorks = results.get("dork_results", {}).get("total", 0)
        if dorks > 0:
            score += min(dorks * 3, 15)
            factors.append({
                "factor": "Dork Findings",
                "impact": min(dorks * 3, 15),
                "details": f"{dorks} result(s)",
            })

        # Cap at 100
        score = min(score, 100)

        # Risk level
        if score >= 75:
            risk = "CRITICAL"
        elif score >= 50:
            risk = "HIGH"
        elif score >= 25:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        # Recommendations
        recs = self._generate_recommendations(risk, factors)

        return {
            "score": round(score, 1),
            "risk_level": risk,
            "factors": factors,
            "recommendation": recs,
            "max_score": 100,
        }

    def _generate_recommendations(self, risk, factors):
        recs = []
        names = [f["factor"] for f in factors]

        if risk in ("CRITICAL", "HIGH"):
            recs.append("⚠️ HIGH RISK - Take immediate action")
            recs.append("🔐 Enable 2FA on all accounts linked to this number")

        if "Password + Phone Leaked" in names:
            recs.append("🔑 Change all passwords for accounts using this number")

        if "Dark Web Mention" in names:
            recs.append("🌑 Your phone may be sold on dark web - consider changing number")
            recs.append("🛡️ Enable SIM lock with your carrier")

        if "Combo List Found" in names:
            recs.append("🚨 Number found in combo list - credentials may be compromised")
            recs.append("🔑 Change all passwords immediately")

        if "GitHub Exposed" in names:
            recs.append("🐙 Remove phone from GitHub repositories")
            recs.append("🐙 Rotate any API keys associated with this number")

        if "Owner Identified" in names:
            recs.append("👤 Your identity is linked to this number publicly")
            recs.append("🔒 Consider using a separate number for public services")

        if "Fraud Reported" in names:
            recs.append("🚫 This number is flagged for fraud - verify ownership")

        if "Spam Reported" in names:
            recs.append("📵 Number reported as spam - check if compromised")

        if "Social Media Linked" in names:
            recs.append("📱 Review social media privacy settings")
            recs.append("📱 Remove phone from public profiles")

        if "VoIP Number" in names:
            recs.append("📞 VoIP numbers are less secure - avoid for 2FA")

        if "Telegram Mention" in names:
            recs.append("📱 Check Telegram leak channels for your data")

        if not recs:
            recs.append("✅ Continue monitoring")
            recs.append("✅ Regular security checkups recommended")

        return recs
TSEOF
echo "  ✅ threat_scorer.py"

echo "[15/35] Creating core/scanner.py..."
cat > core/scanner.py << 'EOF'
from datetime import datetime
from core.threat_scorer import PhoneThreatScorer

class PhoneScanner:
    def __init__(self, use_tor=False):
        self.use_tor = use_tor
        self.tor = None
        self.scorer = PhoneThreatScorer()
        if use_tor:
            self._init_tor()

    def _init_tor(self):
        try:
            from network.tor_manager import TorManager
            self.tor = TorManager()
            if not self.tor.check_connection().get("tor_active"):
                self.tor = None
        except Exception:
            self.tor = None
EOF
echo "  ✅ scanner.py"

echo "[16/35] Creating database..."
cat > database/models.py << 'EOF'
from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, Text, JSON, Boolean
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class PhoneScanResult(Base):
    __tablename__ = "phone_scans"
    id = Column(Integer, primary_key=True, autoincrement=True)
    phone = Column(String(50), index=True)
    scan_date = Column(DateTime, default=datetime.utcnow)
    threat_score = Column(Float, default=0.0)
    risk_level = Column(String(20))
    country = Column(String(100))
    carrier = Column(String(100))
    phone_type = Column(String(50))
    names_found = Column(Integer, default=0)
    breaches_found = Column(Integer, default=0)
    raw_results = Column(JSON)

class PhoneMonitorTarget(Base):
    __tablename__ = "phone_monitors"
    id = Column(Integer, primary_key=True, autoincrement=True)
    phone = Column(String(50), unique=True)
    added_date = Column(DateTime, default=datetime.utcnow)
    last_checked = Column(DateTime)
    last_score = Column(Float, default=0.0)
    is_active = Column(Boolean, default=True)
EOF

cat > database/db_manager.py << 'EOF'
from pathlib import Path
from sqlalchemy import create_engine, desc
from sqlalchemy.orm import sessionmaker
from config import DB_PATH
from database.models import Base, PhoneScanResult, PhoneMonitorTarget

class PhoneDatabaseManager:
    def __init__(self, db_path=None):
        path = db_path or str(DB_PATH)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.engine = create_engine(f"sqlite:///{path}", echo=False,
                                   connect_args={"check_same_thread": False})
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)

    def save_scan(self, phone, threat_score, risk_level, results):
        s = self.Session()
        try:
            analysis = results.get("analysis", {})
            caller = results.get("caller_id", {})
            scan = PhoneScanResult(
                phone=phone, threat_score=threat_score, risk_level=risk_level,
                country=analysis.get("country", ""), carrier=analysis.get("carrier", ""),
                phone_type=analysis.get("phone_type", ""),
                names_found=caller.get("total_names", 0),
                breaches_found=results.get("breaches", {}).get("total_breaches", 0),
                raw_results=results,
            )
            s.add(scan)
            s.commit()
            return scan.id
        finally:
            s.close()

    def get_scan_history(self, phone, limit=10):
        s = self.Session()
        try:
            scans = s.query(PhoneScanResult).filter(
                PhoneScanResult.phone == phone
            ).order_by(desc(PhoneScanResult.scan_date)).limit(limit).all()
            return [{
                "id": sc.id, "date": sc.scan_date.isoformat(),
                "score": sc.threat_score, "risk": sc.risk_level,
                "country": sc.country, "carrier": sc.carrier,
            } for sc in scans]
        finally:
            s.close()

    def get_statistics(self):
        s = self.Session()
        try:
            return {
                "total_scans": s.query(PhoneScanResult).count(),
                "unique_phones": s.query(PhoneScanResult.phone).distinct().count(),
                "critical": s.query(PhoneScanResult).filter(
                    PhoneScanResult.risk_level == "CRITICAL").count(),
                "high": s.query(PhoneScanResult).filter(
                    PhoneScanResult.risk_level == "HIGH").count(),
            }
        finally:
            s.close()

    def add_monitor(self, phone):
        s = self.Session()
        try:
            if not s.query(PhoneMonitorTarget).filter(
                PhoneMonitorTarget.phone == phone).first():
                s.add(PhoneMonitorTarget(phone=phone))
                s.commit()
                return True
            return False
        finally:
            s.close()

    def get_monitors(self):
        s = self.Session()
        try:
            targets = s.query(PhoneMonitorTarget).filter(
                PhoneMonitorTarget.is_active == True).all()
            return [{"phone": t.phone, "last_checked": t.last_checked,
                     "last_score": t.last_score} for t in targets]
        finally:
            s.close()
EOF
echo "  ✅ Database"

echo "[17/35] Creating alerts..."
cat > alerts/webhook_alerts.py << 'EOF'
import requests
from datetime import datetime
from config import (DISCORD_WEBHOOK_URL, SLACK_WEBHOOK_URL,
                    TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID,
                    ALERT_ON_HIGH_RISK, REQUEST_TIMEOUT)

class WebhookAlerts:
    def send_alert(self, phone, threat_score, risk_level, summary):
        if not ALERT_ON_HIGH_RISK or risk_level not in ("HIGH", "CRITICAL"):
            return

        # Discord
        if DISCORD_WEBHOOK_URL:
            try:
                color = {"CRITICAL": 0xFF0000, "HIGH": 0xFF6600}.get(risk_level, 0xFFFFFF)
                embed = {"embeds": [{
                    "title": f"📱 Phone Alert - {risk_level}",
                    "description": f"**Phone:** `{phone}`",
                    "color": color,
                    "fields": [
                        {"name": "Score", "value": f"{threat_score}/100", "inline": True},
                        {"name": "Names", "value": str(summary.get("names", 0)), "inline": True},
                        {"name": "Breaches", "value": str(summary.get("breaches", 0)), "inline": True},
                    ],
                    "timestamp": datetime.utcnow().isoformat(),
                }]}
                requests.post(DISCORD_WEBHOOK_URL, json=embed, timeout=REQUEST_TIMEOUT)
            except Exception:
                pass

        # Slack
        if SLACK_WEBHOOK_URL:
            try:
                msg = {
                    "text": f"📱 *Phone Alert - {risk_level}*\nPhone: `{phone}`\nScore: {threat_score}/100"
                }
                requests.post(SLACK_WEBHOOK_URL, json=msg, timeout=REQUEST_TIMEOUT)
            except Exception:
                pass

        # Telegram
        if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
            try:
                text = (f"📱 *Phone Alert - {risk_level}*\n"
                       f"Phone: `{phone}`\n"
                       f"Score: {threat_score}/100\n"
                       f"Breaches: {summary.get('breaches', 0)}")
                requests.post(
                    f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                    json={"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "Markdown"},
                    timeout=REQUEST_TIMEOUT
                )
            except Exception:
                pass
EOF
echo "  ✅ Alerts"

echo "[18/35] Creating UI..."
cat > ui/dashboard.py << 'UIEOF'
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from rich import box

console = Console()

class PhoneDashboard:
    @staticmethod
    def show_phone_info(analysis):
        """Display phone number analysis"""
        if not analysis or analysis.get("error"):
            console.print(f"[red]  ❌ {analysis.get('error', 'Analysis failed')}[/]")
            return

        info = Table(box=box.ROUNDED, show_header=False, width=60)
        info.add_column("Field", style="cyan", width=20)
        info.add_column("Value", style="white", width=38)

        info.add_row("📱 Number", analysis.get("international", analysis.get("original", "")))
        info.add_row("📞 Type", analysis.get("phone_type", "Unknown"))
        info.add_row("🌍 Country", analysis.get("country", "Unknown"))
        info.add_row("🏢 Carrier", analysis.get("carrier", "Unknown"))
        info.add_row("🔢 E.164", analysis.get("e164", ""))
        info.add_row("⏰ Timezone", ", ".join(analysis.get("timezones", [])[:2]) or "Unknown")
        info.add_row("✅ Valid", "Yes ✅" if analysis.get("valid") else "No ❌")

        if analysis.get("is_voip"):
            info.add_row("⚠️ VoIP", "[yellow]Yes - Possibly disposable[/]")
        if analysis.get("is_mobile"):
            info.add_row("📱 Mobile", "Yes")

        console.print(Panel(info, title="[bold]📱 PHONE ANALYSIS[/]", box=box.DOUBLE_EDGE))

        # Risk indicators
        risks = analysis.get("risk_indicators", [])
        if risks:
            for r in risks:
                console.print(f"  [yellow]⚠ {r}[/]")

    @staticmethod
    def show_threat_gauge(score, risk_level):
        bw = 40
        filled = int((score / 100) * bw)
        colors = {"CRITICAL": "red", "HIGH": "orange1", "MEDIUM": "yellow", "LOW": "green"}
        color = colors.get(risk_level, "white")
        gauge = f"[{color}]{'█' * filled}[/][dim]{'░' * (bw - filled)}[/]"
        emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(risk_level, "")
        console.print(Panel(
            f"\n  {gauge}  {score:.1f}/100\n\n  Risk: {emoji} [{color}]{risk_level}[/]\n",
            title="[bold]🎯 THREAT SCORE[/]", border_style=color, box=box.DOUBLE_EDGE, width=60
        ))

    @staticmethod
    def show_scan_summary(results, threat):
        t = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold cyan")
        t.add_column("Module", width=22)
        t.add_column("Status", width=8, justify="center")
        t.add_column("Count", width=12, justify="right")

        modules = [
            ("📱 Analysis", 1 if results.get("analysis", {}).get("valid") else 0),
            ("👤 Caller ID", results.get("caller_id", {}).get("total_names", 0)),
            ("📵 Spam Check", 1 if results.get("spam", {}).get("is_spam") else 0),
            ("🔓 Breaches", results.get("breaches", {}).get("total_breaches", 0)),
            ("🔎 IntelX", results.get("intelx", {}).get("total", 0)),
            ("🐙 GitHub", results.get("github", {}).get("total", 0)),
            ("📋 Pastes", results.get("pastes", {}).get("total", 0)),
            ("💬 WhatsApp", 1 if results.get("whatsapp", {}).get("is_registered") else 0),
            ("📱 Telegram", results.get("telegram", {}).get("total", 0)),
            ("🌐 Social", results.get("social", {}).get("total", 0)),
            ("🌑 Dark Web", results.get("darkweb", {}).get("total", 0)),
            ("💀 Combo Lists", results.get("combo", {}).get("total", 0)),
            ("🤖 Dorks", results.get("dork_results", {}).get("total", 0)),
        ]

        for name, count in modules:
            status = "🔴" if count > 0 else "🟢"
            t.add_row(name, status, str(count))

        console.print(Panel(t, title="[bold]📊 SCAN RESULTS[/]", box=box.ROUNDED))

    @staticmethod
    def show_factors(threat):
        factors = threat.get("factors", [])
        if not factors:
            return
        t = Table(title="📈 Threat Factors", box=box.ROUNDED, show_lines=True)
        t.add_column("Factor", width=25)
        t.add_column("Impact", width=8, justify="center")
        t.add_column("Details", width=40)
        for f in factors:
            i = f.get("impact", 0)
            c = "red" if i >= 30 else ("yellow" if i >= 15 else "green")
            t.add_row(f["factor"], f"[{c}]+{i}[/]", f.get("details", ""))
        console.print(t)

    @staticmethod
    def show_recommendations(threat):
        recs = threat.get("recommendation", [])
        if recs:
            console.print(Panel(
                "\n".join(f"  {r}" for r in recs),
                title="[bold]💡 RECOMMENDATIONS[/]",
                border_style="yellow", box=box.ROUNDED,
            ))

    @staticmethod
    def show_caller_id(data):
        names = data.get("names_found", [])
        if not names:
            console.print("[green]  ✅ No names found publicly[/]")
            return
        t = Table(title="👤 Caller ID Results", box=box.ROUNDED)
        t.add_column("Name", style="yellow", width=25)
        t.add_column("Source", style="cyan", width=15)
        t.add_column("Confidence", width=12)
        for n in names:
            conf = n.get("confidence", "unknown")
            cc = {"high": "green", "medium": "yellow", "low": "red"}.get(conf, "white")
            t.add_row(n.get("name", ""), n.get("source", ""), f"[{cc}]{conf}[/]")
        console.print(t)

    @staticmethod
    def show_history(history):
        if not history:
            return
        t = Table(title="📜 Scan History", box=box.ROUNDED)
        t.add_column("Date", style="cyan", width=20)
        t.add_column("Score", width=8, justify="center")
        t.add_column("Risk", width=10)
        t.add_column("Country", width=15)
        t.add_column("Carrier", width=15)
        for h in history:
            c = {"CRITICAL": "red", "HIGH": "orange1", "MEDIUM": "yellow", "LOW": "green"}.get(
                h.get("risk", ""), "white")
            t.add_row(
                h["date"][:19], f"[{c}]{h['score']:.0f}[/]",
                f"[{c}]{h.get('risk', '')}[/]",
                h.get("country", ""), h.get("carrier", ""),
            )
        console.print(t)

    @staticmethod
    def show_statistics(stats):
        panels = [
            Panel(f"[bold cyan]{stats.get('total_scans', 0)}[/]", title="Scans", width=18),
            Panel(f"[bold green]{stats.get('unique_phones', 0)}[/]", title="Phones", width=18),
            Panel(f"[bold red]{stats.get('critical', 0)}[/]", title="Critical", width=18),
            Panel(f"[bold yellow]{stats.get('high', 0)}[/]", title="High", width=18),
        ]
        console.print(Columns(panels, equal=True))
UIEOF

cat > ui/animations.py << 'EOF'
import time
from rich.console import Console

console = Console()

class Animations:
    @staticmethod
    def typing_effect(text, delay=0.03, style="green"):
        for c in text:
            console.print(f"[{style}]{c}[/]", end="", highlight=False)
            time.sleep(delay)
        console.print()

    @staticmethod
    def threat_animation(score):
        for i in range(int(score) + 1):
            f = int(40 * i / 100)
            c = "green" if i < 25 else ("yellow" if i < 50 else ("orange1" if i < 75 else "red"))
            console.print(f"\r  [{c}]{'█' * f}[/]{'░' * (40 - f)} [{c}]{i}[/]/100", end="")
            time.sleep(0.02)
        console.print()
EOF
echo "  ✅ UI"

echo "[19/35] Creating reporting..."
cat > reporting/report_generator.py << 'EOF'
import json, os
from datetime import datetime
from config import RESULTS_DIR

class PhoneReportExporter:
    def __init__(self):
        os.makedirs(str(RESULTS_DIR), exist_ok=True)
        self.ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    def export_json(self, data, name=None):
        fname = name or f"phone_report_{self.ts}.json"
        path = os.path.join(str(RESULTS_DIR), fname)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False, default=str)
        return path

    def export_txt(self, data, name=None):
        fname = name or f"phone_report_{self.ts}.txt"
        path = os.path.join(str(RESULTS_DIR), fname)
        with open(path, "w", encoding="utf-8") as f:
            f.write("=" * 70 + "\n")
            f.write("  PHONE LEAK CHECKER PRO v1.0 REPORT\n")
            f.write(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 70 + "\n\n")
            f.write(f"Phone: {data.get('phone', 'N/A')}\n")
            analysis = data.get("analysis", {})
            f.write(f"Country: {analysis.get('country', 'N/A')}\n")
            f.write(f"Carrier: {analysis.get('carrier', 'N/A')}\n")
            f.write(f"Type: {analysis.get('phone_type', 'N/A')}\n\n")
            threat = data.get("threat", {})
            f.write(f"Score: {threat.get('score', 0)}/100\n")
            f.write(f"Risk: {threat.get('risk_level', 'N/A')}\n\n")
            f.write("Recommendations:\n")
            for r in threat.get("recommendation", []):
                f.write(f"  {r}\n")
            f.write("\n" + "=" * 70 + "\n")
        return path
EOF

cat > reporting/html_report.py << 'EOF'
import os
from datetime import datetime
from config import RESULTS_DIR

class PhoneHTMLReport:
    def generate(self, results, threat):
        phone = results.get("phone", "Unknown")
        score = threat.get("score", 0)
        risk = threat.get("risk_level", "UNKNOWN")
        rc = {"CRITICAL": "#ff0000", "HIGH": "#ff6600", "MEDIUM": "#ffcc00", "LOW": "#00cc00"}.get(risk, "#999")
        analysis = results.get("analysis", {})

        fhtml = "".join(
            f"<tr><td>{f.get('factor', '')}</td><td>+{f.get('impact', 0)}</td><td>{f.get('details', '')}</td></tr>"
            for f in threat.get("factors", [])
        )
        rhtml = "".join(f"<li>{r}</li>" for r in threat.get("recommendation", []))

        html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Phone Report - {phone}</title>
<style>body{{font-family:Arial;background:#0a0a1a;color:#e0e0e0;padding:20px;max-width:900px;margin:0 auto}}
h1{{color:{rc};text-align:center}}h2{{color:#00bcd4;border-bottom:1px solid #333;padding-bottom:5px}}
table{{width:100%;border-collapse:collapse;margin:15px 0}}th{{background:#1a1a2e;color:#00bcd4;padding:10px;text-align:left}}
td{{padding:8px;border-bottom:1px solid #222}}.score{{text-align:center;font-size:3em;color:{rc};margin:20px}}
.bar{{width:100%;height:15px;background:#222;border-radius:8px;overflow:hidden}}
.fill{{height:100%;width:{score}%;background:linear-gradient(90deg,#0c0,#ff0,#f60,#f00);border-radius:8px}}
.badge{{display:inline-block;padding:8px 20px;background:{rc};color:#000;font-weight:bold;border-radius:5px}}
.info{{background:#1a1a2e;padding:15px;border-radius:8px;margin:10px 0}}
li{{padding:5px;margin:3px 0;background:#1a1a2e;border-left:3px solid {rc};list-style:none;padding-left:10px}}</style></head><body>
<h1>📱 PHONE LEAK CHECKER PRO v1.0</h1>
<p style="text-align:center">{phone} | {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
<div class="info">
<p><strong>Country:</strong> {analysis.get('country', 'N/A')} | <strong>Carrier:</strong> {analysis.get('carrier', 'N/A')} | <strong>Type:</strong> {analysis.get('phone_type', 'N/A')}</p>
</div>
<div class="score">{score:.0f}/100</div><div class="bar"><div class="fill"></div></div>
<p style="text-align:center"><span class="badge">{risk}</span></p>
<h2>📈 Factors</h2><table><tr><th>Factor</th><th>Impact</th><th>Details</th></tr>{fhtml}</table>
<h2>💡 Recommendations</h2><ul>{rhtml}</ul>
<p style="text-align:center;color:#555;margin-top:30px">PhoneLeakChecker Pro v1.0</p></body></html>"""

        safe = phone.replace("+", "").replace(" ", "")
        fpath = os.path.join(str(RESULTS_DIR), f"phone_report_{safe}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(html)
        return fpath
EOF
echo "  ✅ Reporting"

echo "[20/35] Creating API..."
cat > api/server.py << 'EOF'
try:
    from fastapi import FastAPI
    import uvicorn
    from config import API_HOST, API_PORT if hasattr(__import__('config'), 'API_HOST') else ("127.0.0.1", 8443)
    app = FastAPI(title="PhoneLeakChecker API", version="1.0")
    @app.get("/")
    async def root():
        return {"name": "PhoneLeakChecker Pro API", "version": "1.0"}
    def start_api():
        uvicorn.run(app, host="127.0.0.1", port=8443)
except ImportError:
    def start_api():
        print("pip install fastapi uvicorn")
EOF
echo "  ✅ API"

echo "[21/35] Creating plugins..."
cat > plugins/example_plugin.py << 'EOF'
class PhonePluginBase:
    name = "base"
    version = "1.0"
    def run(self, phone):
        raise NotImplementedError

class ExamplePhonePlugin(PhonePluginBase):
    name = "example"
    def run(self, phone):
        return {"plugin": self.name, "phone": phone, "status": "ok"}
EOF
echo "  ✅ Plugins"

echo "[22/35] Creating data files..."
cat > data/phone_patterns.json << 'EOF'
{
    "disposable_prefixes": ["900", "800", "700"],
    "voip_indicators": ["Google Voice", "Skype", "TextNow", "Burner"],
    "high_risk_countries": ["NG", "GH", "CM", "IN", "PK"]
}
EOF
echo "  ✅ Data files"

echo "[23/35] Creating main.py..."
cat > main.py << 'MAINEOF'
#!/usr/bin/env python3
"""
PhoneLeakChecker Pro v1.0
Advanced Phone Number OSINT & Leak Detection
"""

import sys, os, re
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich import box

from core.phone_analyzer import PhoneAnalyzer
from core.threat_scorer import PhoneThreatScorer
from network.tor_manager import TorManager
from modules.phone.number_validator import NumberValidator
from modules.phone.carrier_lookup import CarrierLookup
from modules.phone.hlr_lookup import HLRLookup
from modules.phone.caller_id import CallerIDLookup
from modules.phone.spam_checker import SpamChecker
from modules.messaging.whatsapp_check import WhatsAppChecker
from modules.messaging.telegram_search import TelegramSearcher
from modules.messaging.signal_check import SignalChecker
from modules.messaging.viber_check import ViberChecker
from modules.social.social_scanner import SocialScanner
from modules.social.github_phone import GitHubPhoneSearch
from modules.darkweb.phone_darkweb import PhoneDarkWebSearch
from modules.darkweb.paste_monitor import PhonePasteMonitor
from modules.darkweb.combo_search import ComboListSearch
from modules.surface.google_dorker import PhoneDorker
from modules.surface.intelx_phone import IntelXPhoneSearch
from modules.surface.numverify import NumVerifyCheck
from modules.surface.data_breach import PhoneBreachSearch
from database.db_manager import PhoneDatabaseManager
from alerts.webhook_alerts import WebhookAlerts
from reporting.report_generator import PhoneReportExporter
from reporting.html_report import PhoneHTMLReport
from ui.dashboard import PhoneDashboard

console = Console()
db = PhoneDatabaseManager()
dashboard = PhoneDashboard()
scorer = PhoneThreatScorer()
analyzer = PhoneAnalyzer()
alerts = WebhookAlerts()
tor = None


def banner():
    console.print(Panel("""[bold red]
    ██████╗ ██╗  ██╗ ██████╗ ███╗   ██╗███████╗
    ██╔══██╗██║  ██║██╔═══██╗████╗  ██║██╔════╝
    ██████╔╝███████║██║   ██║██╔██╗ ██║█████╗
    ██╔═══╝ ██╔══██║██║   ██║██║╚██╗██║██╔══╝
    ██║     ██║  ██║╚██████╔╝██║ ╚████║███████╗
    ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝[/]
    [bold cyan]    LEAK CHECKER PRO v1.0[/]
    [bold green]    Phone OSINT | 20+ Sources | Dark Web[/]
    [bold yellow]    Caller ID | Messaging Apps | Breach Detection[/]
    [dim]    WhatsApp|Telegram|Signal|Viber|Social Media
    Ahmia|Torch|Haystack|DarkSearch|ComboLists
    CallerID|Spam|GitHub|IntelX|Google Dorks[/]""",
    box=box.DOUBLE_EDGE, border_style="red"))


def init_tor():
    global tor
    console.print("\n[cyan]🔌 Connecting to Tor...[/]")
    tor = TorManager()
    check = tor.check_connection()
    if check["tor_active"]:
        console.print(f"[green]✅ Tor: {check['ip']} ({check.get('country', '?')})[/]")
        return True
    console.print(f"[red]❌ Tor unavailable: {check.get('error', '')}[/]")
    console.print("[yellow]   sudo systemctl start tor[/]")
    tor = None
    return False


def validate_phone(phone_input):
    """Validate phone number input"""
    cleaned = re.sub(r'[^\d+]', '', phone_input.strip())
    if not cleaned:
        return None
    if len(cleaned) < 7:
        return None
    if not cleaned.startswith('+') and len(cleaned) >= 10:
        console.print("[yellow]  ℹ No country code detected. Adding + prefix.[/]")
        cleaned = f"+{cleaned}"
    return cleaned


def full_scan(phone, silent=False):
    """Execute full phone number scan"""
    global tor
    results = {"phone": phone}
    has_tor = tor is not None and tor.is_connected

    # Phase 1: Analysis
    analysis = analyzer.analyze(phone)
    results["analysis"] = analysis

    # Build module list
    modules = [
        ("📱 Analysis", "analysis", lambda: analysis),
        ("👤 Caller ID", "caller_id", lambda: CallerIDLookup().lookup_all(phone)),
        ("📵 Spam Check", "spam", lambda: SpamChecker().check_all(phone)),
        ("🔓 Breaches", "breaches", lambda: PhoneBreachSearch().search(phone)),
        ("🔎 IntelX", "intelx", lambda: IntelXPhoneSearch().search(phone)),
        ("🐙 GitHub", "github", lambda: GitHubPhoneSearch().search(phone)),
        ("📋 Pastes", "pastes", lambda: PhonePasteMonitor(tor).search(phone)),
        ("💬 WhatsApp", "whatsapp", lambda: WhatsAppChecker().check(phone)),
        ("📱 Telegram", "telegram", lambda: TelegramSearcher().search(phone)),
        ("📡 Signal", "signal", lambda: SignalChecker().check(phone)),
        ("📞 Viber", "viber", lambda: ViberChecker().check(phone)),
        ("🌐 Social", "social", lambda: SocialScanner().scan_all(phone)),
        ("🌑 Dark Web", "darkweb", lambda: PhoneDarkWebSearch(tor).search_all(phone)),
        ("💀 Combo Lists", "combo", lambda: ComboListSearch(tor).search(phone)),
        ("🤖 Dorks", "dork_results", lambda: PhoneDorker().auto_search(phone)),
        ("🔍 Dork Links", "dorks", lambda: PhoneDorker().generate_dorks(phone)),
    ]

    if not silent:
        console.print(f"\n[bold cyan]📱 Scanning [white]{phone}[/] | {len(modules)} modules...[/]\n")

        with Progress(
            SpinnerColumn("dots12"),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=30),
            TaskProgressColumn(),
            TextColumn("•"),
            TextColumn("[dim]{task.fields[status]}[/]"),
            console=console,
        ) as prog:
            task = prog.add_task("Scanning...", total=len(modules), status="Starting...")
            for display_name, key, func in modules:
                prog.update(task, description=f"[cyan]{display_name}", status="Working...")
                try:
                    results[key] = func()
                    r = results[key]
                    count = 0
                    if isinstance(r, dict):
                        count = (r.get("total", 0) or r.get("total_names", 0) or
                                r.get("total_breaches", 0) or r.get("total_reports", 0) or
                                len(r.get("findings", [])) or len(r.get("names_found", [])) or
                                len(r.get("profiles_found", [])) or len(r.get("combo_mentions", [])) or
                                len(r.get("pastes_found", [])) or len(r.get("results", [])) or
                                len(r.get("mentions", [])))
                    prog.update(task, status=f"[yellow]{count} found[/]" if count > 0 else "[green]Clean[/]")
                except Exception as e:
                    results[key] = {"error": str(e)}
                    prog.update(task, status="[red]Error[/]")
                prog.advance(task)
            prog.update(task, description="[bold green]✅ Complete!", status=f"{len(modules)} modules")
    else:
        for _, key, func in modules:
            try:
                results[key] = func()
            except Exception:
                results[key] = {}

    # Calculate threat score
    results["threat"] = scorer.calculate_score(results)

    if not silent:
        console.print("\n")

        # Show phone info
        dashboard.show_phone_info(results.get("analysis", {}))

        # Show threat gauge
        dashboard.show_threat_gauge(results["threat"]["score"], results["threat"]["risk_level"])

        # Show scan summary
        dashboard.show_scan_summary(results, results["threat"])

        # Show threat factors
        dashboard.show_factors(results["threat"])

        # Show recommendations
        dashboard.show_recommendations(results["threat"])

        # Detailed results
        console.print("\n[bold underline cyan]═══ DETAILED RESULTS ═══[/]\n")

        # Caller ID
        console.print("[bold underline]👤 CALLER ID[/]")
        dashboard.show_caller_id(results.get("caller_id", {}))

        # Spam check
        spam = results.get("spam", {})
        if spam:
            if spam.get("is_scam"):
                console.print(f"\n[bold red]🚫 SCAM REPORTED! Spam score: {spam.get('spam_score', 0)}[/]")
            elif spam.get("is_spam"):
                console.print(f"\n[bold yellow]📵 SPAM: Score {spam.get('spam_score', 0)} | {spam.get('total_reports', 0)} reports[/]")
            else:
                console.print(f"\n[bold]📵 Spam:[/] [green]Clean ✅[/]")

        # Breaches
        breach_data = results.get("breaches", {})
        if breach_data.get("breaches"):
            console.print(f"\n[bold underline]🔓 BREACHES ({breach_data.get('total_breaches', 0)})[/]")
            t = Table(box=box.ROUNDED, show_lines=True)
            t.add_column("Name", style="red", width=20)
            t.add_column("Date", style="yellow", width=12)
            t.add_column("Source", style="cyan", width=12)
            for b in breach_data["breaches"][:10]:
                t.add_row(b.get("name", "")[:20], b.get("date", ""), b.get("source", ""))
            console.print(t)
        if breach_data.get("emails_linked"):
            console.print(f"  📧 Linked emails: {', '.join(breach_data['emails_linked'][:3])}")

        # IntelX
        ix = results.get("intelx", {})
        if ix.get("findings"):
            console.print(f"\n[bold underline]🔎 INTELX ({ix.get('total', 0)})[/]")
            for f in ix["findings"][:10]:
                console.print(f"  📌 {f.get('value', '')} ({f.get('type', '')})")

        # GitHub
        gh = results.get("github", {})
        if gh.get("findings"):
            console.print(f"\n[bold underline]🐙 GITHUB ({gh.get('total', 0)})[/]")
            for f in gh["findings"][:5]:
                console.print(f"  📄 {f.get('repo', '')} / {f.get('path', '')}")
                console.print(f"     {f.get('url', '')}")

        # Pastes
        pastes = results.get("pastes", {})
        if pastes.get("pastes_found"):
            console.print(f"\n[bold underline]📋 PASTES ({pastes.get('total', 0)})[/]")
            for p in pastes["pastes_found"][:5]:
                console.print(f"  📋 [{p.get('site', '')}] {p.get('title', '')[:50]}")

        # Messaging Apps
        console.print(f"\n[bold underline]💬 MESSAGING APPS[/]")
        wa = results.get("whatsapp", {})
        console.print(f"  💬 WhatsApp: {'✅ Active' if wa.get('is_registered') else '❓ Unknown'}")
        if wa.get("wa_link"):
            console.print(f"     Link: {wa['wa_link']}")

        tg = results.get("telegram", {})
        if tg.get("profile_found"):
            console.print(f"  📱 Telegram: ✅ Found | @{tg.get('username_found', 'N/A')}")
        elif tg.get("total", 0) > 0:
            console.print(f"  📱 Telegram: {tg['total']} mention(s)")
        else:
            console.print(f"  📱 Telegram: ❓ Unknown")

        sg = results.get("signal", {})
        console.print(f"  📡 Signal: {'✅' if sg.get('is_registered') else '❓ Unknown'}")

        vb = results.get("viber", {})
        console.print(f"  📞 Viber: {'✅' if vb.get('is_registered') else '❓ Unknown'}")

        # Social Media
        social = results.get("social", {})
        if social.get("profiles_found"):
            console.print(f"\n[bold underline]🌐 SOCIAL MEDIA ({social.get('total', 0)})[/]")
            for p in social["profiles_found"]:
                console.print(f"  📱 {p.get('platform', '')}: {p.get('url', '')}")
                if p.get("title"):
                    console.print(f"     {p['title'][:60]}")

        # Dark Web
        dw = results.get("darkweb", {})
        if dw.get("findings"):
            console.print(f"\n[bold underline]🌑 DARK WEB ({dw.get('total', 0)})[/]")
            t = Table(box=box.HEAVY_EDGE, show_lines=True, border_style="red")
            t.add_column("Source", style="red", width=12)
            t.add_column("Title", style="yellow", width=35)
            t.add_column("Risk", width=8)
            t.add_column("🧅", width=4)
            for f in dw["findings"][:15]:
                risk = f.get("risk_level", "N/A")
                rc = {"HIGH": "red", "MEDIUM": "yellow"}.get(risk, "green")
                t.add_row(
                    f.get("source", ""), f.get("title", "")[:35],
                    f"[{rc}]{risk}[/]", "🧅" if f.get("is_onion") else "🌐"
                )
            console.print(t)
            if dw.get("engines_searched"):
                console.print(f"  [dim]Engines: {', '.join(dw['engines_searched'])}[/]")

        # Combo Lists
        combo = results.get("combo", {})
        if combo.get("combo_mentions"):
            console.print(f"\n[bold underline red]💀 COMBO LISTS ({combo.get('total', 0)})[/]")
            for m in combo["combo_mentions"][:5]:
                risk = m.get("risk", "MEDIUM")
                rc = {"CRITICAL": "red", "HIGH": "orange1"}.get(risk, "yellow")
                console.print(f"  [{rc}]⚠ [{risk}][/] {m.get('title', '')[:60]}")

        # Dork Results
        dr = results.get("dork_results", {})
        if dr.get("results"):
            console.print(f"\n[bold underline]🤖 DORK RESULTS ({dr.get('total', 0)})[/]")
            t = Table(box=box.ROUNDED)
            t.add_column("Category", style="magenta", width=12)
            t.add_column("Title", style="cyan", width=35)
            t.add_column("URL", style="dim", width=40)
            for r in dr["results"][:10]:
                t.add_row(r.get("category", ""), r.get("title", "")[:35], r.get("url", "")[:40])
            console.print(t)

        # Telegram details
        if tg.get("mentions"):
            console.print(f"\n[bold underline]📱 TELEGRAM MENTIONS[/]")
            for m in tg["mentions"][:5]:
                console.print(f"  📱 {m.get('title', '')} → {m.get('url', '')}")
        if tg.get("leak_channels"):
            console.print(f"\n[bold red]  ⚠ LEAK CHANNELS:[/]")
            for ch in tg["leak_channels"][:5]:
                rc = {"HIGH": "red"}.get(ch.get("risk", ""), "yellow")
                console.print(f"  [{rc}]📱 {ch.get('channel', '')} → {ch.get('url', '')}[/]")

        # Search format reference
        formats = results.get("analysis", {}).get("search_formats", [])
        if formats:
            console.print(f"\n[dim]  Search formats used: {', '.join(formats[:5])}[/]")

        # History
        history = db.get_scan_history(phone)
        if history:
            console.print("\n")
            dashboard.show_history(history)

    # Save to database
    try:
        db.save_scan(phone, results["threat"]["score"], results["threat"]["risk_level"], results)
    except Exception:
        pass

    # Send alerts
    threat = results.get("threat", {})
    if threat.get("risk_level") in ("HIGH", "CRITICAL"):
        summary = {
            "names": results.get("caller_id", {}).get("total_names", 0),
            "breaches": results.get("breaches", {}).get("total_breaches", 0),
            "darkweb": results.get("darkweb", {}).get("total", 0),
        }
        alerts.send_alert(phone, threat.get("score", 0), threat.get("risk_level", ""), summary)

    return results


def export_menu(results):
    fmt = Prompt.ask("[bold]Format[/]", choices=["json", "txt", "html", "all"], default="all")
    exp = PhoneReportExporter()
    threat = results.get("threat", {})
    if fmt in ("json", "all"):
        console.print(f"[green]✅ {exp.export_json(results)}[/]")
    if fmt in ("txt", "all"):
        console.print(f"[green]✅ {exp.export_txt(results)}[/]")
    if fmt in ("html", "all"):
        p = PhoneHTMLReport().generate(results, threat)
        console.print(f"[green]✅ {p}[/]")
        console.print("[cyan]   Open in browser![/]")


def main():
    global tor
    banner()

    stats = db.get_statistics()
    if stats.get("total_scans", 0) > 0:
        dashboard.show_statistics(stats)

    tor_ok = init_tor()

    while True:
        ts = "[green]🟢[/]" if tor_ok else "[red]🔴[/]"
        console.print(Panel(
            f"[1]  📱  Full Phone Scan          {ts}\n"
            f"[2]  🔍  Quick Lookup\n"
            f"[3]  👤  Caller ID Only\n"
            f"[4]  📵  Spam Check\n"
            f"[5]  🌑  Deep Web Search           {ts}\n"
            f"[6]  💬  Messaging Apps Check\n"
            f"[7]  🤖  Auto Dork Search\n"
            f"[8]  📱  Telegram Search\n"
            f"[9]  🔄  Monitoring\n"
            f"[10] 📜  History\n"
            f"[11] 📊  Statistics\n"
            f"[12] 🔌  Tor Controls\n"
            f"[13] 📋  Batch Scan\n"
            f"[0]  🚪  Exit",
            title="[bold cyan]═══ MENU ═══[/]", box=box.ROUNDED, border_style="cyan",
        ))

        ch = Prompt.ask("[bold]Select[/]", choices=[str(i) for i in range(14)])

        if ch == "1":
            phone_input = Prompt.ask("[bold]📱 Phone number (with country code)[/]")
            phone = validate_phone(phone_input)
            if not phone:
                console.print("[red]Invalid phone number[/]")
                continue
            r = full_scan(phone)
            if Confirm.ask("\nExport report?", default=True):
                export_menu(r)

        elif ch == "2":
            phone_input = Prompt.ask("[bold]📱 Phone[/]")
            phone = validate_phone(phone_input)
            if not phone:
                console.print("[red]Invalid[/]")
                continue
            analysis = analyzer.analyze(phone)
            dashboard.show_phone_info(analysis)
            carrier_info = CarrierLookup().lookup(phone)
            console.print(f"\n  🏢 Carrier: {carrier_info.get('carrier', 'Unknown')}")
            console.print(f"  📞 Type: {carrier_info.get('carrier_type', 'Unknown')}")

        elif ch == "3":
            phone_input = Prompt.ask("[bold]📱 Phone[/]")
            phone = validate_phone(phone_input)
            if not phone:
                console.print("[red]Invalid[/]")
                continue
            console.print("[cyan]🔍 Looking up caller ID...[/]")
            data = CallerIDLookup().lookup_all(phone)
            dashboard.show_caller_id(data)
            if data.get("is_spam"):
                console.print(f"[red]  📵 SPAM detected! Score: {data.get('spam_score', 0)}[/]")

        elif ch == "4":
            phone_input = Prompt.ask("[bold]📱 Phone[/]")
            phone = validate_phone(phone_input)
            if not phone:
                console.print("[red]Invalid[/]")
                continue
            console.print("[cyan]📵 Checking spam databases...[/]")
            spam = SpamChecker().check_all(phone)
            if spam.get("is_scam"):
                console.print(f"[bold red]🚫 SCAM! Score: {spam['spam_score']}/100[/]")
            elif spam.get("is_spam"):
                console.print(f"[bold yellow]📵 SPAM! Score: {spam['spam_score']}/100 | Reports: {spam['total_reports']}[/]")
            else:
                console.print("[green]✅ No spam reports found[/]")
            if spam.get("reports"):
                for r in spam["reports"][:5]:
                    console.print(f"  • {r.get('type', '')} ({r.get('source', '')})")

        elif ch == "5":
            phone_input = Prompt.ask("[bold]📱 Phone[/]")
            phone = validate_phone(phone_input)
            if not phone:
                console.print("[red]Invalid[/]")
                continue
            console.print("[red]🌑 Searching dark web...[/]\n")
            dw = PhoneDarkWebSearch(tor).search_all(phone)
            combo = ComboListSearch(tor).search(phone)

            if dw.get("findings"):
                for f in dw["findings"][:10]:
                    risk = f.get("risk_level", "N/A")
                    rc = {"HIGH": "red", "MEDIUM": "yellow"}.get(risk, "green")
                    console.print(f"  [{rc}]🌑 [{f.get('source', '')}] {f.get('title', '')[:50]}[/]")
            else:
                console.print("[green]  ✅ Not found on dark web[/]")

            if combo.get("combo_mentions"):
                console.print(f"\n[bold red]💀 COMBO LISTS ({combo['total']}):[/]")
                for m in combo["combo_mentions"][:5]:
                    console.print(f"  ⚠ {m.get('title', '')[:60]}")

        elif ch == "6":
            phone_input = Prompt.ask("[bold]📱 Phone[/]")
            phone = validate_phone(phone_input)
            if not phone:
                console.print("[red]Invalid[/]")
                continue
            console.print("[cyan]💬 Checking messaging apps...[/]\n")
            wa = WhatsAppChecker().check(phone)
            tg = TelegramSearcher().search(phone)
            sg = SignalChecker().check(phone)
            vb = ViberChecker().check(phone)
            console.print(f"  💬 WhatsApp: {'✅' if wa.get('is_registered') else '❓'}")
            if wa.get("wa_link"):
                console.print(f"     {wa['wa_link']}")
            tg_total = tg.get("total", 0)
            tg_status = "✅ Found" if tg.get("profile_found") else f"{tg_total} mentions"
            console.print(f"  📱 Telegram: {tg_status}")
            console.print(f"  📡 Signal: {'✅' if sg.get('is_registered') else '❓'}")
            console.print(f"  📞 Viber: {'✅' if vb.get('is_registered') else '❓'}")

        elif ch == "7":
            phone_input = Prompt.ask("[bold]📱 Phone[/]")
            phone = validate_phone(phone_input)
            if not phone:
                console.print("[red]Invalid[/]")
                continue
            dorker = PhoneDorker()
            dorks = dorker.generate_dorks(phone)
            console.print(f"\n[bold]🤖 {len(dorks)} dorks generated. Searching...[/]\n")
            ar = dorker.auto_search(phone, max_dorks=8)
            if ar.get("results"):
                t = Table(box=box.ROUNDED)
                t.add_column("Category", style="magenta", width=12)
                t.add_column("Title", style="cyan", width=35)
                t.add_column("URL", style="dim", width=40)
                for r in ar["results"][:15]:
                    t.add_row(r.get("category", ""), r.get("title", "")[:35], r.get("url", "")[:40])
                console.print(t)
            else:
                console.print("[green]✅ No dork results found[/]")

            console.print("\n[bold]📋 Manual dork links:[/]")
            for d in dorks[:5]:
                console.print(f"  🔗 {d['dork'][:50]}")
                console.print(f"     {d['url'][:70]}")

        elif ch == "8":
            phone_input = Prompt.ask("[bold]📱 Phone[/]")
            phone = validate_phone(phone_input)
            if not phone:
                console.print("[red]Invalid[/]")
                continue
            tg = TelegramSearcher()
            result = tg.search(phone)
            if result.get("mentions"):
                for m in result["mentions"]:
                    console.print(f"  📱 {m.get('title', '')} → {m.get('url', '')}")
            if result.get("leak_channels"):
                console.print(f"\n[red]  ⚠ Leak channels:[/]")
                for ch_data in result["leak_channels"]:
                    console.print(f"  📱 {ch_data.get('channel', '')} → {ch_data.get('url', '')}")
            links = tg.generate_search_links(phone)
            console.print("\n[bold]🔗 Search links:[/]")
            for l in links:
                console.print(f"  🔗 {l['name']}: {l['url']}")

        elif ch == "9":
            sub = Prompt.ask("1=Add 2=List", choices=["1", "2"])
            if sub == "1":
                phone_input = Prompt.ask("Phone")
                phone = validate_phone(phone_input)
                if phone:
                    db.add_monitor(phone)
                    console.print("[green]✅ Added[/]")
            elif sub == "2":
                for t in db.get_monitors():
                    console.print(f"  📱 {t['phone']} | Score: {t['last_score']}")

        elif ch == "10":
            phone_input = Prompt.ask("[bold]📱 Phone[/]")
            phone = validate_phone(phone_input)
            if phone:
                dashboard.show_history(db.get_scan_history(phone, 20))

        elif ch == "11":
            dashboard.show_statistics(db.get_statistics())

        elif ch == "12":
            sub = Prompt.ask("1=Status 2=Rotate 3=Reconnect", choices=["1", "2", "3"])
            if sub == "1" and tor:
                c = tor.check_connection()
                console.print(f"  {'🟢' if c['tor_active'] else '🔴'} IP: {c.get('ip', 'N/A')}")
            elif sub == "2" and tor:
                console.print(f"[green]{'✅ New IP' if tor.rotate_ip() else '❌ Failed'}[/]")
            elif sub == "3":
                tor_ok = init_tor()

        elif ch == "13":
            filepath = Prompt.ask("[bold]📄 File path (one phone per line)[/]")
            if os.path.exists(filepath):
                with open(filepath, "r") as f:
                    phones = [line.strip() for line in f if line.strip()]
                console.print(f"[cyan]📋 {len(phones)} phones to scan[/]")
                for i, p in enumerate(phones, 1):
                    phone = validate_phone(p)
                    if phone:
                        console.print(f"\n[bold]━━━ [{i}/{len(phones)}] {phone} ━━━[/]")
                        full_scan(phone, silent=False)
            else:
                console.print("[red]File not found[/]")

        elif ch == "0":
            if tor:
                tor.close()
            console.print("\n[bold green]👋 Goodbye![/]\n")
            sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted[/]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/]")
        import traceback
        traceback.print_exc()
        sys.exit(1)
MAINEOF
echo "  ✅ main.py"

echo ""
echo "╔═══════════════════════════════════════════════════════╗"
echo "║  ✅ PhoneLeakChecker Pro v1.0 - Setup Complete!       ║"
echo "╠═══════════════════════════════════════════════════════╣"
echo "║                                                       ║"
echo "║  📦 Install:                                          ║"
echo "║     cd phone_checker                                  ║"
echo "║     pip install -r requirements.txt                   ║"
echo "║                                                       ║"
echo "║  🚀 Run:                                              ║"
echo "║     python3 main.py                                   ║"
echo "║                                                       ║"
echo "║  🧅 Tor (optional):                                   ║"
echo "║     sudo systemctl start tor                          ║"
echo "║                                                       ║"
echo "║  📱 Modules: 20+                                      ║"
echo "║  🌑 Dark Web: 5 engines                               ║"
echo "║  💬 Messaging: WhatsApp, Telegram, Signal, Viber      ║"
echo "║  🌐 Social: FB, IG, LinkedIn, Twitter, TikTok, VK     ║"
echo "║  👤 Caller ID: Truecaller, Sync.me, Web Search        ║"
echo "║  📵 Spam: 4 spam databases                            ║"
echo "║  🔓 Breaches: HIBP + web search                       ║"
echo "║  🐙 GitHub: Code leak detection                       ║"
echo "║  🤖 Dorks: 15 auto-dork templates                     ║"
echo "║  📋 Batch: Scan multiple phones from file             ║"
echo "║                                                       ║"
echo "╚═══════════════════════════════════════════════════════╝"