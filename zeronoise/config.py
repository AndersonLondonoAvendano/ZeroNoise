from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    # Dependency-Track
    dt_base_url: str = "http://localhost:8080"
    dt_api_key: str

    # MCP Server
    mcp_server_name: str = "zeronoise"
    mcp_transport: str = "stdio"  # "stdio" | "sse"

    # Stage 3 gate — minimum confidence required to allow contextual LLM analysis
    stage3_confidence_threshold: float = 0.70


settings = Settings()
