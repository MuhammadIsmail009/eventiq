"""EventIQ: a streaming detection engine for network security logs.

The detection engine reads only raw observable fields. It never reads the
``event_type`` or ``severity`` columns; those are held out and used solely to
score detections (see ``eventiq.validate``).
"""

__version__ = "0.1.0"
