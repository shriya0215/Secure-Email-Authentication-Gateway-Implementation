#!/usr/bin/env python3
"""
Secure Email Authentication Gateway - Web Server Launcher.
Starts the local web gateway dashboard on http://127.0.0.1:5000.
"""

import os
import sys

# Ensure local imports work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from web.app import app


def main():
    print("""
========================================================================
    SECURE EMAIL AUTHENTICATION GATEWAY (SPF | DKIM | DMARC)
========================================================================
Starting Email Authentication Gateway Web Server...
Available at: http://127.0.0.1:5000
Press Ctrl+C to stop the server.
========================================================================
    """)
    app.run(host="127.0.0.1", port=5000, debug=False)


if __name__ == "__main__":
    main()
