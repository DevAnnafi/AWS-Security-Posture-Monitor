from dataclasses import dataclass, field, asdict
from enum import IntEnum, Enum
from typing import Any
from datetime import datetime, timezone
import hashlib
import json
from botocore.exceptions import ClientError

class Severity(IntEnum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1

class CollectionStatus(Enum):
    OK = "ok"
    ACCESS_DENIED = "access_denied"
    PARSE_ERROR = "parse_error"

def collect_policy(s3_client, bucket_name):
    try:
        response = s3_client.get_bucket_policy(Bucket=bucket_name)
        document = json.loads(response["Policy"])
        return {"status": CollectionStatus.OK.value, "document": document}

    except ClientError as e:
        error_code = e.response["Error"]["Code"]

        if error_code == "NoSuchBucketPolicy":
            return {"status": CollectionStatus.OK.value, "document": None}

        if error_code == "AccessDenied":
            return {"status": CollectionStatus.ACCESS_DENIED.value, "document": None}

        raise

    except json.JSONDecodeError:
        return {"status": CollectionStatus.PARSE_ERROR.value, "document": None}


@dataclass
class Finding:
    control_id: str
    title: str
    severity: Severity
    resource_id: str
    resource_sub_id: str | None
    region: str | None
    remediable: bool
    evidence: dict[str, Any]
    account_id: str
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finding_id: str = field(init=False)

    def __post_init__(self):
        joined = "|".join([self.account_id, self.region or "", self.control_id, self.resource_id, self.resource_sub_id or ""])
        encode = joined.encode()
        self.finding_id = hashlib.sha256(encode).hexdigest()

    def to_dict(self):
        finding_dict = asdict(self)
        finding_dict["detected_at"] = self.detected_at.isoformat()
        finding_dict["severity"] = self.severity.name
        return finding_dict

    @classmethod
    def from_dict(cls, finding_dict):
        finding_dict["detected_at"] = datetime.fromisoformat(finding_dict["detected_at"])
        finding_dict["severity"] = Severity[finding_dict["severity"]]

        finding_dict.pop("finding_id")

        return cls(**finding_dict)













