"""spektralia.sessions — agent session stream producers and consumers.

This package is the substrate for the Airlock (#114). The writer module
appends normalized JSONL turn events to SPEKTRALIA_SESSION_STREAMS_DIR
(default /work/session-streams), which the Airlock ingester will tail.
"""
