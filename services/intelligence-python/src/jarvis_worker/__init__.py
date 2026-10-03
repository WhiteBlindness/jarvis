"""Intelligence worker for the JARVIS Core.

The worker is a separate process. It speaks the line-delimited JSON protocol described in
``docs/protocol.md`` over its own stdin and stdout and asks the Core to perform every action.
"""

__version__ = "0.1.0"
