from zeronoise.config import settings
from zeronoise.server import mcp


def main():
    mcp.run(transport=settings.mcp_transport)


if __name__ == "__main__":
    main()
