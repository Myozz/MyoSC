"""Secret detection patterns.

Patterns are organized by provider/type. Each pattern includes:
- Regex pattern for matching
- Description
- Confidence level (low/medium/high)
- Whether to require keyword proximity for low-entropy matches
"""

import re
from dataclasses import dataclass
from enum import Enum


class Confidence(str, Enum):
    """Detection confidence level."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class SecretPattern:
    """Definition of a secret pattern."""

    id: str
    name: str
    pattern: re.Pattern[str]
    confidence: Confidence
    require_keyword: bool = False
    keywords: tuple[str, ...] = ()

    def match(self, text: str) -> list[re.Match[str]]:
        """Find all matches in text."""
        return list(self.pattern.finditer(text))


# AWS patterns
AWS_ACCESS_KEY = SecretPattern(
    id="aws-access-key",
    name="AWS Access Key ID",
    pattern=re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
    confidence=Confidence.HIGH,
)

AWS_SECRET_KEY = SecretPattern(
    id="aws-secret-key",
    name="AWS Secret Access Key",
    pattern=re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"),
    confidence=Confidence.HIGH,
)

AWS_MWS_KEY = SecretPattern(
    id="aws-mws-key",
    name="AWS MWS Key",
    pattern=re.compile(r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
    confidence=Confidence.HIGH,
)

# GitHub patterns
GITHUB_TOKEN = SecretPattern(
    id="github-token",
    name="GitHub Token",
    pattern=re.compile(r"\b(ghp_[a-zA-Z0-9]{36})\b"),  # Personal access token
    confidence=Confidence.HIGH,
)

GITHUB_OAUTH = SecretPattern(
    id="github-oauth",
    name="GitHub OAuth Token",
    pattern=re.compile(r"\b(gho_[a-zA-Z0-9]{36})\b"),
    confidence=Confidence.HIGH,
)

GITHUB_APP_TOKEN = SecretPattern(
    id="github-app-token",
    name="GitHub App Token",
    pattern=re.compile(r"\b(ghu_[a-zA-Z0-9]{36}|ghs_[a-zA-Z0-9]{36})\b"),
    confidence=Confidence.HIGH,
)

GITHUB_REFRESH_TOKEN = SecretPattern(
    id="github-refresh-token",
    name="GitHub Refresh Token",
    pattern=re.compile(r"\b(ghr_[a-zA-Z0-9]{36})\b"),
    confidence=Confidence.HIGH,
)

# Google patterns
GOOGLE_API_KEY = SecretPattern(
    id="google-api-key",
    name="Google API Key",
    pattern=re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    confidence=Confidence.HIGH,
)

GOOGLE_OAUTH_ID = SecretPattern(
    id="google-oauth-id",
    name="Google OAuth Client ID",
    pattern=re.compile(r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"),
    confidence=Confidence.HIGH,
)

# Slack patterns
SLACK_TOKEN = SecretPattern(
    id="slack-token",
    name="Slack Token",
    pattern=re.compile(r"\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*)\b"),
    confidence=Confidence.HIGH,
)

SLACK_WEBHOOK = SecretPattern(
    id="slack-webhook",
    name="Slack Webhook URL",
    pattern=re.compile(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+"),
    confidence=Confidence.HIGH,
)

# Database patterns
POSTGRES_URI = SecretPattern(
    id="postgres-uri",
    name="PostgreSQL Connection URI",
    pattern=re.compile(r"postgres(?:ql)?://[^:]+:[^@]+@[^/]+/[^\s\"']+"),
    confidence=Confidence.HIGH,
)

MYSQL_URI = SecretPattern(
    id="mysql-uri",
    name="MySQL Connection URI",
    pattern=re.compile(r"mysql://[^:]+:[^@]+@[^/]+/[^\s\"']+"),
    confidence=Confidence.HIGH,
)

MONGODB_URI = SecretPattern(
    id="mongodb-uri",
    name="MongoDB Connection URI",
    pattern=re.compile(r"mongodb(?:\+srv)?://[^:]+:[^@]+@[^\s\"']+"),
    confidence=Confidence.HIGH,
)

REDIS_URI = SecretPattern(
    id="redis-uri",
    name="Redis Connection URI",
    pattern=re.compile(r"redis://[^:]*:[^@]+@[^\s\"']+"),
    confidence=Confidence.MEDIUM,
)

# Private key patterns
RSA_PRIVATE_KEY = SecretPattern(
    id="rsa-private-key",
    name="RSA Private Key",
    pattern=re.compile(r"-----BEGIN RSA PRIVATE KEY-----"),
    confidence=Confidence.HIGH,
)

SSH_PRIVATE_KEY = SecretPattern(
    id="ssh-private-key",
    name="SSH Private Key",
    pattern=re.compile(r"-----BEGIN (?:OPENSSH|DSA|EC|PGP) PRIVATE KEY-----"),
    confidence=Confidence.HIGH,
)

# JWT patterns
JWT_TOKEN = SecretPattern(
    id="jwt-token",
    name="JSON Web Token",
    pattern=re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    confidence=Confidence.MEDIUM,
)

# Generic patterns (lower confidence, use keyword proximity)
GENERIC_API_KEY = SecretPattern(
    id="generic-api-key",
    name="Generic API Key",
    pattern=re.compile(r"(?i)(?:api[_-]?key|apikey)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})['\"]?"),
    confidence=Confidence.MEDIUM,
    require_keyword=True,
    keywords=("api", "key", "token", "secret"),
)

GENERIC_SECRET = SecretPattern(
    id="generic-secret",
    name="Generic Secret",
    pattern=re.compile(r"(?i)(?:secret|password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"]{8,})['\"]?"),
    confidence=Confidence.LOW,
    require_keyword=True,
    keywords=("secret", "password", "passwd", "pwd", "credential"),
)

GENERIC_TOKEN = SecretPattern(
    id="generic-token",
    name="Generic Token",
    pattern=re.compile(r"(?i)(?:token|auth)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})['\"]?"),
    confidence=Confidence.LOW,
    require_keyword=True,
    keywords=("token", "auth", "bearer"),
)

# Stripe
STRIPE_API_KEY = SecretPattern(
    id="stripe-api-key",
    name="Stripe API Key",
    pattern=re.compile(r"\b(sk_live_[0-9a-zA-Z]{24,})\b"),
    confidence=Confidence.HIGH,
)

STRIPE_PUBLISHABLE_KEY = SecretPattern(
    id="stripe-publishable-key",
    name="Stripe Publishable Key",
    pattern=re.compile(r"\b(pk_live_[0-9a-zA-Z]{24,})\b"),
    confidence=Confidence.MEDIUM,  # publishable keys are less sensitive
)

# Twilio
TWILIO_API_KEY = SecretPattern(
    id="twilio-api-key",
    name="Twilio API Key",
    pattern=re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
    confidence=Confidence.HIGH,
)

# SendGrid
SENDGRID_API_KEY = SecretPattern(
    id="sendgrid-api-key",
    name="SendGrid API Key",
    pattern=re.compile(r"\bSG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}\b"),
    confidence=Confidence.HIGH,
)

# NPM
NPM_TOKEN = SecretPattern(
    id="npm-token",
    name="NPM Access Token",
    pattern=re.compile(r"\b(npm_[a-zA-Z0-9]{36})\b"),
    confidence=Confidence.HIGH,
)

# PyPI
PYPI_TOKEN = SecretPattern(
    id="pypi-token",
    name="PyPI API Token",
    pattern=re.compile(r"\b(pypi-[a-zA-Z0-9_-]{50,})\b"),
    confidence=Confidence.HIGH,
)

# Discord
DISCORD_TOKEN = SecretPattern(
    id="discord-token",
    name="Discord Bot Token",
    pattern=re.compile(r"\b([MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27})\b"),
    confidence=Confidence.HIGH,
)

DISCORD_WEBHOOK = SecretPattern(
    id="discord-webhook",
    name="Discord Webhook URL",
    pattern=re.compile(r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+"),
    confidence=Confidence.HIGH,
)

# Heroku
HEROKU_API_KEY = SecretPattern(
    id="heroku-api-key",
    name="Heroku API Key",
    pattern=re.compile(r"(?i)heroku.{0,20}['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]"),
    confidence=Confidence.HIGH,
)

# All patterns list
ALL_PATTERNS: list[SecretPattern] = [
    # AWS
    AWS_ACCESS_KEY,
    AWS_SECRET_KEY,
    AWS_MWS_KEY,
    # GitHub
    GITHUB_TOKEN,
    GITHUB_OAUTH,
    GITHUB_APP_TOKEN,
    GITHUB_REFRESH_TOKEN,
    # Google
    GOOGLE_API_KEY,
    GOOGLE_OAUTH_ID,
    # Slack
    SLACK_TOKEN,
    SLACK_WEBHOOK,
    # Database
    POSTGRES_URI,
    MYSQL_URI,
    MONGODB_URI,
    REDIS_URI,
    # Private keys
    RSA_PRIVATE_KEY,
    SSH_PRIVATE_KEY,
    # JWT
    JWT_TOKEN,
    # Stripe
    STRIPE_API_KEY,
    STRIPE_PUBLISHABLE_KEY,
    # Twilio
    TWILIO_API_KEY,
    # SendGrid
    SENDGRID_API_KEY,
    # NPM/PyPI
    NPM_TOKEN,
    PYPI_TOKEN,
    # Discord
    DISCORD_TOKEN,
    DISCORD_WEBHOOK,
    # Heroku
    HEROKU_API_KEY,
    # Generic (lower confidence)
    GENERIC_API_KEY,
    GENERIC_SECRET,
    GENERIC_TOKEN,
]


def get_patterns_by_confidence(min_confidence: Confidence) -> list[SecretPattern]:
    """Get patterns with at least the specified confidence."""
    order = [Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW]
    min_idx = order.index(min_confidence)
    allowed = set(order[: min_idx + 1])
    return [p for p in ALL_PATTERNS if p.confidence in allowed]
