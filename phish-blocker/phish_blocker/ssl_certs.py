import os

import certifi


def ensure() -> None:
    bundle = certifi.where()
    os.environ.setdefault("SSL_CERT_FILE", bundle)
    os.environ.setdefault("REQUESTS_CA_BUNDLE", bundle)
