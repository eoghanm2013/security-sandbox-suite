#!/usr/bin/env python3
"""
Cloud SIEM Event Generator

Produces synthetic log events in the native format of real integrations
(AWS CloudTrail, Okta) so that Datadog's built-in log pipelines parse them
and OOTB Cloud SIEM detection rules generate Security Signals automatically.

Each integration writes to its own log file.  The Datadog Agent collects
them with the correct `source` tag, which activates the matching pipeline.

Targeted OOTB rules (10 total):
  CloudTrail (6):
    - AWS CloudTrail configuration modified              (StopLogging)
    - AWS GuardDuty detector deleted                     (DeleteDetector)
    - AWS IAM AdministratorAccess policy applied to user (AttachUserPolicy)
    - AWS EBS Snapshot Made Public                       (ModifySnapshotAttribute)
    - AWS KMS key deleted or scheduled for deletion      (ScheduleKeyDeletion)
    - AWS CloudWatch log group deleted                   (DeleteLogGroup)
  Okta (4):
    - Okta API Token Created or Enabled                  (system.api_token.create)
    - Okta administrator role assigned to user           (user.account.privilege.grant)
    - Okta MFA reset for user                            (user.mfa.factor.reset_all)
    - Okta policy rule deleted                           (policy.rule.delete)

Usage:
    python event-generator.py                          # Run all scenarios once
    python event-generator.py --loop --interval 60     # Run continuously
    python event-generator.py --scenario cloudtrail    # CloudTrail only
    python event-generator.py --scenario okta          # Okta only
    python event-generator.py --output-dir /var/log/sandbox
"""

import argparse
import json
import os
import random
import string
import sys
import time
from datetime import datetime, timezone

DEFAULT_OUTPUT_DIR = "/var/log/sandbox"

ATTACKER_IPS = ["198.51.100.42", "203.0.113.99", "45.33.32.156"]
AWS_REGIONS = ["us-east-1", "us-west-2", "eu-west-1"]


def _ts():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _aws_ts():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _rand_id(prefix="", length=12):
    chars = string.ascii_lowercase + string.digits
    return prefix + "".join(random.choices(chars, k=length))


def _emit(entry, filepath):
    line = json.dumps(entry, separators=(",", ":"))
    if filepath:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "a") as f:
            f.write(line + "\n")
    else:
        print(line, flush=True)


def _log_path(output_dir, filename):
    if output_dir:
        return os.path.join(output_dir, filename)
    return None


# ---------------------------------------------------------------------------
# CloudTrail event builder
# ---------------------------------------------------------------------------

def _cloudtrail_base(event_name, event_source, request_params=None,
                     response_elements=None, error_code=None):
    ip = random.choice(ATTACKER_IPS)
    region = random.choice(AWS_REGIONS)
    account = "123456789012"
    user = "suspicious-user"
    event = {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDAEXAMPLE123456",
            "arn": f"arn:aws:iam::{account}:user/{user}",
            "accountId": account,
            "userName": user,
            "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
        },
        "eventTime": _aws_ts(),
        "eventSource": event_source,
        "eventName": event_name,
        "awsRegion": region,
        "sourceIPAddress": ip,
        "userAgent": "aws-cli/2.15.0 Python/3.11.6 Linux/5.15.0",
        "requestParameters": request_params or {},
        "responseElements": response_elements,
        "requestID": _rand_id(length=36),
        "eventID": _rand_id(length=36),
        "readOnly": False,
        "eventType": "AwsApiCall",
        "managementEvent": True,
        "recipientAccountId": account,
    }
    if error_code:
        event["errorCode"] = error_code
    return event


def cloudtrail_scenarios(output_dir=None):
    """Generate 6 CloudTrail events that each trigger a different OOTB rule."""
    print("[SIEM] Generating: CloudTrail events (6 OOTB rules)", file=sys.stderr)
    fp = _log_path(output_dir, "cloudtrail.log")

    # 1. StopLogging  ->  "AWS CloudTrail configuration modified"
    _emit(_cloudtrail_base(
        event_name="StopLogging",
        event_source="cloudtrail.amazonaws.com",
        request_params={"name": "management-trail"},
    ), fp)
    time.sleep(0.3)

    # 2. DeleteDetector  ->  "AWS GuardDuty detector deleted"
    _emit(_cloudtrail_base(
        event_name="DeleteDetector",
        event_source="guardduty.amazonaws.com",
        request_params={"detectorId": _rand_id(length=32)},
    ), fp)
    time.sleep(0.3)

    # 3. AttachUserPolicy + AdministratorAccess  ->  "AWS IAM AdministratorAccess policy applied to user"
    _emit(_cloudtrail_base(
        event_name="AttachUserPolicy",
        event_source="iam.amazonaws.com",
        request_params={
            "userName": "backdoor-user",
            "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
        },
    ), fp)
    time.sleep(0.3)

    # 4. ModifySnapshotAttribute public  ->  "AWS EBS Snapshot Made Public"
    _emit(_cloudtrail_base(
        event_name="ModifySnapshotAttribute",
        event_source="ec2.amazonaws.com",
        request_params={
            "snapshotId": "snap-0123456789abcdef0",
            "createVolumePermission": {
                "add": {"items": [{"group": "all"}]},
            },
            "attributeType": "CREATE_VOLUME_PERMISSION",
        },
    ), fp)
    time.sleep(0.3)

    # 5. ScheduleKeyDeletion  ->  "AWS KMS key deleted or scheduled for deletion"
    _emit(_cloudtrail_base(
        event_name="ScheduleKeyDeletion",
        event_source="kms.amazonaws.com",
        request_params={
            "keyId": _rand_id(prefix="mrk-", length=32),
            "pendingWindowInDays": 7,
        },
    ), fp)
    time.sleep(0.3)

    # 6. DeleteLogGroup  ->  "AWS CloudWatch log group deleted"
    _emit(_cloudtrail_base(
        event_name="DeleteLogGroup",
        event_source="logs.amazonaws.com",
        request_params={"logGroupName": "/aws/lambda/production-api"},
    ), fp)

    print("[SIEM]   Wrote 6 CloudTrail events to cloudtrail.log", file=sys.stderr)


# ---------------------------------------------------------------------------
# Okta event builder
# ---------------------------------------------------------------------------

def _okta_base(event_type, outcome="SUCCESS", targets=None,
               debug_data=None, display_message=""):
    ip = random.choice(ATTACKER_IPS)
    event = {
        "uuid": _rand_id(length=20),
        "published": _ts(),
        "eventType": event_type,
        "version": "0",
        "severity": "WARN" if outcome == "FAILURE" else "INFO",
        "legacyEventType": event_type.replace(".", "_"),
        "displayMessage": {"value": display_message, "args": None},
        "actor": {
            "id": "00u" + _rand_id(length=17),
            "type": "User",
            "alternateId": "attacker@sandbox-corp.com",
            "displayName": "Attacker User",
            "detailEntry": None,
        },
        "client": {
            "userAgent": {
                "rawUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
                "os": "Mac OS X",
                "browser": "CHROME",
            },
            "zone": "null",
            "device": "Computer",
            "id": None,
            "ipAddress": ip,
            "geographicalContext": {
                "city": "San Francisco",
                "state": "California",
                "country": "United States",
                "postalCode": "94107",
                "geolocation": {"lat": 37.7749, "lon": -122.4194},
            },
        },
        "outcome": {"result": outcome, "reason": None},
        "target": targets or [],
        "transaction": {"type": "WEB", "id": _rand_id(length=16)},
        "debugContext": {"debugData": debug_data or {}},
        "authenticationContext": {
            "authenticationStep": 0,
            "externalSessionId": _rand_id(length=20),
        },
        "securityContext": {
            "asNumber": 0, "asOrg": "", "isp": "", "domain": "", "isProxy": False,
        },
        "request": {
            "ipChain": [{"ip": ip, "version": "V4", "source": None}],
        },
    }
    return event


def okta_scenarios(output_dir=None):
    """Generate 4 Okta events that each trigger a different OOTB rule."""
    print("[SIEM] Generating: Okta events (4 OOTB rules)", file=sys.stderr)
    fp = _log_path(output_dir, "okta.log")

    # 1. system.api_token.create  ->  "Okta API Token Created or Enabled"
    _emit(_okta_base(
        event_type="system.api_token.create",
        outcome="SUCCESS",
        targets=[{
            "id": "00t" + _rand_id(length=17),
            "type": "Token",
            "alternateId": "unknown",
            "displayName": "Sandbox Exfil Token",
            "detailEntry": None,
        }],
        display_message="Create API token",
        debug_data={"requestUri": "/api/v1/tokens"},
    ), fp)
    time.sleep(0.3)

    # 2. user.account.privilege.grant  ->  "Okta administrator role assigned to user"
    _emit(_okta_base(
        event_type="user.account.privilege.grant",
        outcome="SUCCESS",
        targets=[
            {
                "id": "00u" + _rand_id(length=17),
                "type": "User",
                "alternateId": "backdoor@sandbox-corp.com",
                "displayName": "Backdoor User",
                "detailEntry": None,
            },
            {
                "id": "00r" + _rand_id(length=17),
                "type": "ROLE_ASSIGNED",
                "alternateId": "unknown",
                "displayName": "Super Administrator",
                "detailEntry": None,
            },
        ],
        display_message="Grant user privilege",
        debug_data={
            "privilegeGranted": "Super admin",
            "requestUri": "/api/v1/users/00uXXX/roles",
        },
    ), fp)
    time.sleep(0.3)

    # 3. user.mfa.factor.reset_all  ->  "Okta MFA reset for user"
    _emit(_okta_base(
        event_type="user.mfa.factor.reset_all",
        outcome="SUCCESS",
        targets=[{
            "id": "00u" + _rand_id(length=17),
            "type": "User",
            "alternateId": "victim@sandbox-corp.com",
            "displayName": "Victim User",
            "detailEntry": None,
        }],
        display_message="Reset all MFA factors for user",
        debug_data={"requestUri": "/api/v1/users/00uXXX/lifecycle/reset_factors"},
    ), fp)
    time.sleep(0.3)

    # 4. policy.rule.delete  ->  "Okta policy rule deleted"
    _emit(_okta_base(
        event_type="policy.rule.delete",
        outcome="SUCCESS",
        targets=[{
            "id": "00p" + _rand_id(length=17),
            "type": "PolicyRule",
            "alternateId": "unknown",
            "displayName": "Require MFA for all users",
            "detailEntry": None,
        }],
        display_message="Delete policy rule",
        debug_data={"requestUri": "/api/v1/policies/00pXXX/rules/0prXXX"},
    ), fp)

    print("[SIEM]   Wrote 4 Okta events to okta.log", file=sys.stderr)


# ---------------------------------------------------------------------------
# Scenario registry
# ---------------------------------------------------------------------------

SCENARIOS = {
    "cloudtrail": cloudtrail_scenarios,
    "okta": okta_scenarios,
}


def main():
    parser = argparse.ArgumentParser(description="Cloud SIEM Event Generator")
    parser.add_argument("--scenario", choices=list(SCENARIOS.keys()),
                        help="Run a specific scenario (default: all)")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR,
                        help=f"Directory for log files (default: {DEFAULT_OUTPUT_DIR})")
    parser.add_argument("--stdout", action="store_true",
                        help="Print to stdout instead of writing files")
    parser.add_argument("--loop", action="store_true",
                        help="Run continuously")
    parser.add_argument("--interval", type=int, default=60,
                        help="Seconds between loops (default: 60)")
    args = parser.parse_args()

    output_dir = None if args.stdout else args.output_dir

    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        print(f"[SIEM] Writing logs to {output_dir}/", file=sys.stderr)

    while True:
        if args.scenario:
            SCENARIOS[args.scenario](output_dir)
        else:
            for fn in SCENARIOS.values():
                fn(output_dir)
                time.sleep(1)

        if not args.loop:
            break

        print(f"[SIEM] Sleeping {args.interval}s before next round...",
              file=sys.stderr)
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
