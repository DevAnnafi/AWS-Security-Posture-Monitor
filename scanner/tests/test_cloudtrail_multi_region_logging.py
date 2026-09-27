from scanner.checks.cloudtrail_multi_region import (
    CloudTrailMultiRegionLoggingCheck,
)
from scanner.fixtures import (
    CLOUDTRAIL_FIXTURE,
    CLOUDTRAIL_COMPLIANT_FIXTURE,
)
from scanner.models import Severity
from scanner.registry import CheckStatus


def test_cloudtrail_multi_region_logging_fails():
    result = CloudTrailMultiRegionLoggingCheck().evaluate(
        CLOUDTRAIL_FIXTURE
    )

    assert result.status == CheckStatus.VIOLATIONS
    assert len(result.findings) == 1

    finding = result.findings[0]

    assert finding.control_id == "4.1"
    assert finding.severity == Severity.HIGH
    assert finding.resource_id == "157182991517"
    assert finding.resource_sub_id is None
    assert finding.region is None
    assert finding.account_id == "157182991517"


def test_cloudtrail_multi_region_logging_passes():
    result = CloudTrailMultiRegionLoggingCheck().evaluate(
        CLOUDTRAIL_COMPLIANT_FIXTURE
    )

    assert result.status == CheckStatus.EVALUATED
    assert result.findings == []

def test_cloudtrail_multi_region_trail_not_logging_fails():
    fixture = {
        **CLOUDTRAIL_COMPLIANT_FIXTURE,
        "cloudtrail_trails": {
            **CLOUDTRAIL_COMPLIANT_FIXTURE["cloudtrail_trails"],
            "document": [
                {
                    "region": "us-east-1",
                    "status": "ok",
                    "document": [
                        {
                            "name": "multi-region-trail",
                            "trail_arn": (
                                "arn:aws:cloudtrail:us-east-1:"
                                "157182991517:trail/multi-region-trail"
                            ),
                            "home_region": "us-east-1",
                            "s3_bucket_name": "cloudtrail-bucket",
                            "is_multi_region_trail": True,
                            "include_global_service_events": True,
                            "log_file_validation_enabled": True,
                            "is_logging": {
                                "status": "ok",
                                "document": {
                                    "IsLogging": False,
                                },
                            },
                        }
                    ],
                }
            ],
        },
    }

    result = CloudTrailMultiRegionLoggingCheck().evaluate(fixture)

    assert result.status == CheckStatus.VIOLATIONS
    assert len(result.findings) == 1