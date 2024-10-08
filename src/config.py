from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    DATABASE_URL: str
    SECRET_KEY: str
    JWT_EXPIRY: int
    PROJECT_NAME: str
    DOMAIN: str = "localhost:8000"
    BACKEND_CORS_ORIGINS: list[str] = [
        "http://localhost:8000",
        "http://localhost:3000",
        "http://localhost:8080",
    ]
    BACKEND_CORS_ORIGINS: list[str]
    EMAILS_ENABLED: bool = False
    EMAILS_FROM_NAME: str
    EMAILS_FROM_EMAIL: str
    EMAIL_RESET_TOKEN_EXPIRE_HOURS: int = 48
    SMTP_USER: str | None = None
    SMTP_PASSWORD: str | None = None
    SMTP_HOST: str | None = None
    SMTP_PORT: int | None = None
    SMTP_SSL: bool | None = None
    SMTP_TLS: bool | None = None
    REDIS_URL: str = "redis://localhost:6379/0"
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()