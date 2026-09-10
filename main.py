"""
AES-256-GCM Enterprise Cryptographic Suite - Main Entry Point.
NIST SP 800-38D Compliant Authenticated Encryption System.
"""
import sys
import os

# Add root project path to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gui.app import ModernAESApp


def main():
    """Launches the modern graphical interface."""
    app = ModernAESApp()
    app.mainloop()


if __name__ == "__main__":
    main()