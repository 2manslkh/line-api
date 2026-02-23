"""LINE client configuration — endpoints, versions, and app identity."""


class LineConfig:
    # ── Hosts ──
    HOST = "https://ga2.line.naver.jp"
    GW_HOST = "https://gwz.line.naver.jp"  # Direct (encType=0)
    GF_HOST = "https://gf.line.naver.jp"   # Encrypted (encType=1)
    LEGY_HOST = "https://legy-jp.line.naver.jp"
    OBS_HOST = "https://obs.line-apps.com"

    # ── Endpoints ──
    TALK_ENDPOINT = "/S4"  # TCompact
    TALK_BINARY_ENDPOINT = "/S3"  # TBinary
    TALK_MORE_COMPACT_ENDPOINT = "/S5"  # TMoreCompact
    AUTH_ENDPOINT = "/api/v3p/rs"
    RSA_KEY_ENDPOINT = "/api/v3/TalkService.do"
    SQR_ENDPOINT = "/acct/lgn/sq/v1"
    SQR_POLL_ENDPOINT = "/acct/lp/lgn/sq/v1"
    SECONDARY_LOGIN_VERIFY_E2EE = "/LF1"
    SECONDARY_LOGIN_VERIFY = "/Q"
    COMPACT_MESSAGE_ENDPOINT = "/C5"
    ENCRYPTION_ENDPOINT = "/enc"

    # ── App Identity ──
    # Pretend to be LINE Chrome OS extension
    DEVICE_TYPE = "CHROMEOS"
    APP_VERSION = "3.0.3"
    SYSTEM_NAME = "Chrome_OS"
    SYSTEM_VERSION = "1"

    LANGUAGE = "th"
    REGION = "TH"

    @property
    def app_name(self) -> str:
        return f"{self.DEVICE_TYPE}\t{self.APP_VERSION}\t{self.SYSTEM_NAME}\t{self.SYSTEM_VERSION}"

    @property
    def user_agent(self) -> str:
        return f"Line/{self.APP_VERSION}"
