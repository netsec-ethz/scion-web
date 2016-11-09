"""
:mod:`defines` --- Constants
============================
Contains constant definitions used for SCION web.
"""

# Values related to the suggested default values
DEFAULT_BANDWIDTH = 1000
SCION_SUGGESTED_PORT = 31000

# Values related to the SCION coordination service API
COORD_SERVICE_URI = "http://127.0.0.1:8080"
UPLOAD_JOIN_REQUEST_SVC = "/api/as/uploadJoinRequest/"
UPLOAD_JOIN_REPLY_SVC = "/api/as/uploadJoinReply/"
POLL_JOIN_REPLY_SVC = "/api/as/pollJoinReply/"
UPLOAD_CONN_REQUESTS_SVC = "/api/as/uploadConnRequests/"
UPLOAD_CONN_REPLIES_SVC = "/api/as/uploadConnReplies/"
POLL_CONN_REPLIES_SVC = "/api/as/pollConnReplies/"
POLL_EVENTS_SVC = "/api/as/pollEvents/"

INITIAL_CERT_VERSION = 0
