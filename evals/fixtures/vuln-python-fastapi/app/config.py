"""Application configuration.

FIXTURE NOTE: every credential below is FAKE and exists only to be found by scanners.
"""
HOST = "127.0.0.1"
PORT = 3103
INTERNAL_PORT = 3193
ANALYTICS_PORT = 3163
ANALYTICS_URL = f"http://127.0.0.1:{ANALYTICS_PORT}/collect"

# payment + cloud credentials (planted, FAKE)
STRIPE_SECRET_KEY = "sk_test_51FAKEfixtureKeyNotRealXq7Lm2Pz9Rt4Vw8Yb3"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
