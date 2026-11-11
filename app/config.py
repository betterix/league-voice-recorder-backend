"""Application configuration module using pydantic-settings."""

from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

INSECURE_KEY_SUBSTRINGS = (
    "generate-secure-random",
    "changeme",
    "change-me",
    "secret",
    "password",
    "admin123",
)


class Settings(BaseSettings):
    """Application settings with environment validation."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Server Configuration
    DOMAIN_NAME: str = Field(default="voice.example.com", description="Direct-access public domain")
    PORT: int = Field(default=8443, ge=1, le=65535, description="Direct HTTPS listener port")
    ENVIRONMENT: Literal["production", "development", "test"] = Field(
        default="production", description="Runtime environment"
    )

    # Storage Paths
    STORAGE_DIR: Path = Field(
        default=Path("/app/data/recordings"),
        description="Persistent directory for MP3 audio files",
    )
    DB_DIR: Path = Field(
        default=Path("/app/data/db"),
        description="Persistent directory for SQLite database",
    )

    # Authentication Keys
    UPLOAD_KEY: str = Field(
        default="generate-secure-random-upload-secret",
        description="Secret key for recording clients / players",
    )
    PULL_KEY: str = Field(
        default="generate-secure-random-pull-secret",
        description="Secret key for read-only analysts / coaches",
    )
    ADMIN_KEY: str | None = Field(
        default=None,
        description="Optional secret key for full administrative access",
    )

    # TLS / SSL Certificates
    SSL_CERT: Path = Field(
        default=Path("/app/certs/cert.pem"),
        description="Path to TLS certificate file",
    )
    SSL_KEY: Path = Field(
        default=Path("/app/certs/key.pem"),
        description="Path to TLS private key file",
    )
    DEV_SELF_SIGNED_CERT: bool = Field(
        default=False,
        description="Allow self-signed ECDSA certificate in development mode",
    )

    # Upload & Transfer Limits
    MAX_UPLOAD_MB: int = Field(
        default=250,
        ge=1,
        le=2048,
        description="Maximum allowed upload file size in megabytes",
    )

    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = Field(
        default=120,
        ge=1,
        description="General API rate limit per IP per minute",
    )
    UPLOAD_RATE_LIMIT_PER_MINUTE: int = Field(
        default=10,
        ge=1,
        description="Upload endpoint rate limit per IP per minute",
    )
    AUTH_FAILURE_LIMIT_PER_MINUTE: int = Field(
        default=5,
        ge=1,
        description="Consecutive auth failures before temporary IP block",
    )
    AUTH_BLOCK_DURATION_MINUTES: int = Field(
        default=10,
        ge=1,
        description="Duration in minutes of temporary IP block after auth failure threshold",
    )
    SCANNER_BLOCK_ENABLED: bool = Field(
        default=True,
        description="Enable automatic IP blocking for vulnerability scanners and probe activity",
    )
    SCANNER_BLOCK_DURATION_MINUTES: int = Field(
        default=60,
        ge=1,
        description="Duration in minutes to ban IPs flagged for scanning/probing",
    )
    SCANNER_FAILURE_THRESHOLD: int = Field(
        default=5,
        ge=1,
        description="Number of consecutive probe/404/405/400 failures within window before IP ban",
    )
    SCANNER_FAILURE_WINDOW_SECONDS: float = Field(
        default=60.0,
        ge=1.0,
        description="Sliding window in seconds for tracking probe failures",
    )

    # Web Dashboard Configuration
    WEB_ENABLED: bool = Field(
        default=True,
        description="Enable or disable the /web administration and monitoring interface",
    )
    WEB_ALLOWED_IPS: str = Field(
        default="127.0.0.1,::1",
        description="Comma-separated list of allowed IPs for /web (0.0.0.0 for public access)",
    )
    WEB_USERNAME: str = Field(
        default="admin",
        description="HTTP Basic Auth username for /web dashboard",
    )
    WEB_PASSWORD: str = Field(
        default="change-me-secure-web-password",
        description="HTTP Basic Auth password for /web dashboard",
    )

    @field_validator("STORAGE_DIR", "DB_DIR", "SSL_CERT", "SSL_KEY", mode="after")
    @classmethod
    def resolve_paths(cls, value: Path) -> Path:
        """Resolve paths to absolute path representations."""
        return value.expanduser().resolve()

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"

    @property
    def is_development(self) -> bool:
        return self.ENVIRONMENT == "development"

    @property
    def is_test(self) -> bool:
        return self.ENVIRONMENT == "test"

    @property
    def max_upload_bytes(self) -> int:
        return self.MAX_UPLOAD_MB * 1024 * 1024

    @property
    def database_path(self) -> Path:
        return self.DB_DIR / "recordings.db"

    @property
    def database_url(self) -> str:
        return f"sqlite:///{self.database_path}"

    def ensure_directories(self) -> None:
        """Create necessary directories if they do not exist."""
        self.STORAGE_DIR.mkdir(parents=True, exist_ok=True)
        self.DB_DIR.mkdir(parents=True, exist_ok=True)

    @model_validator(mode="after")
    def validate_production_security(self) -> "Settings":
        """Enforce strict production credential and security requirements."""
        if self.is_production:
            # Check for placeholder secrets
            for key_name, key_val in [
                ("UPLOAD_KEY", self.UPLOAD_KEY),
                ("PULL_KEY", self.PULL_KEY),
                ("ADMIN_KEY", self.ADMIN_KEY),
            ]:
                if key_val is None:
                    continue
                lowered = key_val.lower()
                if any(substr in lowered for substr in INSECURE_KEY_SUBSTRINGS):
                    raise ValueError(
                        f"Insecure production credential detected for {key_name}. "
                        "Must generate a strong random secret."
                    )
                if len(key_val) < 32:
                    raise ValueError(
                        f"Production {key_name} is too short (minimum 32 chars required)."
                    )
                if len(set(key_val)) < 8:
                    raise ValueError(f"Production {key_name} has insufficient entropy/diversity.")

            # Ensure keys are distinct
            if self.UPLOAD_KEY == self.PULL_KEY:
                raise ValueError("UPLOAD_KEY and PULL_KEY must not be identical.")

            if self.ADMIN_KEY and self.ADMIN_KEY in (self.UPLOAD_KEY, self.PULL_KEY):
                raise ValueError("ADMIN_KEY must not be identical to UPLOAD_KEY or PULL_KEY.")

            # Validate web dashboard credentials if enabled
            if self.WEB_ENABLED:
                lowered_web_pass = self.WEB_PASSWORD.lower()
                if any(substr in lowered_web_pass for substr in INSECURE_KEY_SUBSTRINGS):
                    raise ValueError(
                        "Insecure production credential detected for WEB_PASSWORD. "
                        "Must generate a strong random password in .env."
                    )
                if len(self.WEB_PASSWORD) < 16:
                    raise ValueError(
                        "Production WEB_PASSWORD is too short (minimum 16 chars required)."
                    )

        return self


# Global singleton instance (lazily initialized or overridden during tests)
_settings: Settings | None = None


def get_settings() -> Settings:
    """Retrieve global settings instance."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def set_settings(new_settings: Settings) -> None:
    """Override settings instance (useful in test harnesses)."""
    global _settings
    _settings = new_settings
