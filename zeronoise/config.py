from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    # Dependency-Track
    dt_base_url: str = "http://localhost:8080"
    dt_api_key: str

    # MCP Server
    mcp_server_name: str = "zeronoise"
    mcp_transport: str = "stdio"  # "stdio" | "sse"


settings = Settings()
