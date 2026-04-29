from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Dependency-Track
    dt_base_url: str = "http://localhost:8080"
    dt_api_key: str

    # MCP Server
    mcp_server_name: str = "zeronoise"
    mcp_transport: str = "stdio"  # "stdio" | "sse"
    mcp_host: str = "127.0.0.1"  # binding host — relevant when mcp_transport == "sse"

    # Stage 3 gate — minimum confidence required to allow contextual LLM analysis
    stage3_confidence_threshold: float = 0.70

    # Security — defensive pagination for Stage 1 responses
    max_findings_per_response: int = 50

    # Security — rate limits per MCP server session (resets on restart)
    stage3_rate_limit_fetch: int = 200     # fetch_code_snippet
    stage3_rate_limit_function: int = 100  # get_function_context
    stage3_rate_limit_call: int = 100      # get_call_context
    stage3_rate_limit_symbol: int = 50     # find_symbol_usages

    # OWASP Dependency-Check fast-gate — minimum CVSS to treat as gate blocker
    gate_cvss_threshold: float = 7.0


settings = Settings()


def get_settings() -> Settings:
    return settings
