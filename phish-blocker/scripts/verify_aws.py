#!/usr/bin/env python3
"""Smoke-test AWS creds, Bedrock Nova Sonic access, and LiveKit AWS plugin."""

import os
import sys
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")

MODEL_ID = "amazon.nova-2-sonic-v1:0"
REQUIRED = ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_DEFAULT_REGION")


def ok(msg: str) -> None:
    print(f"  OK  {msg}")


def fail(msg: str) -> None:
    print(f"  FAIL {msg}")


def main() -> int:
    print("=== phish-blocker AWS / Nova Sonic verification ===\n")
    errors = 0

    print("1. Environment")
    for key in REQUIRED:
        val = os.getenv(key, "").strip()
        if val:
            ok(f"{key} is set ({len(val)} chars)")
        else:
            fail(f"{key} is missing or empty")
            errors += 1

    region = os.getenv("AWS_DEFAULT_REGION") or os.getenv("AWS_REGION") or "us-east-1"
    print(f"     region in use: {region}\n")

    print("2. AWS identity (STS)")
    try:
        import boto3
        from botocore.exceptions import ClientError, NoCredentialsError

        sts = boto3.client("sts", region_name=region)
        ident = sts.get_caller_identity()
        ok(f"account {ident['Account']}, arn {ident['Arn']}")
    except NoCredentialsError:
        fail("no credentials found by boto3")
        errors += 1
    except ClientError as e:
        fail(f"STS rejected creds: {e.response['Error']['Code']}")
        errors += 1
    except ImportError:
        fail("boto3 not installed")
        errors += 1

    print("\n3. Bedrock model access")
    try:
        bedrock = boto3.client("bedrock", region_name=region)
        resp = bedrock.get_foundation_model(modelIdentifier=MODEL_ID)
        status = resp.get("modelDetails", {}).get("modelLifecycle", {}).get("status", "?")
        ok(f"{MODEL_ID} visible in {region} (lifecycle: {status})")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("AccessDeniedException", "UnauthorizedException"):
            fail(f"no permission to read {MODEL_ID} in {region}")
        elif code == "ResourceNotFoundException":
            fail(f"{MODEL_ID} not available in {region} — try us-east-1")
        else:
            fail(f"Bedrock API error: {code} — {e.response['Error'].get('Message', '')}")
        errors += 1

    print("\n4. Bedrock runtime endpoint")
    try:
        brt = boto3.client("bedrock-runtime", region_name=region)
        ok(f"bedrock-runtime client created for {region}")
    except Exception as e:
        fail(f"bedrock-runtime client failed: {e}")
        errors += 1

    print("\n5. LiveKit AWS plugin (Nova Sonic realtime)")
    try:
        from livekit.plugins import aws

        model = aws.realtime.RealtimeModel.with_nova_sonic_2(
            region=region,
            voice="matthew",
            turn_detection="MEDIUM",
            tool_choice="auto",
        )
        ok(
            f"RealtimeModel created (region={model._opts.region}, "
            f"voice={model._opts.voice}, modalities={model._opts.modalities})"
        )
    except ImportError as e:
        fail(f"import failed — run: pip install 'livekit-plugins-aws[realtime]' — {e}")
        errors += 1
    except Exception as e:
        fail(f"RealtimeModel init failed: {e}")
        errors += 1

    print("\n6. Nova Sonic realtime SDK package")
    try:
        import aws_sdk_bedrock_runtime  # noqa: F401
        import aws_sdk_signers  # noqa: F401

        ok("aws_sdk_bedrock_runtime + aws_sdk_signers installed")
    except ImportError as e:
        fail(f"realtime SDK packages missing — pip install 'livekit-plugins-aws[realtime]' — {e}")
        errors += 1

    print("\n7. Agent module import")
    try:
        sys.path.insert(0, str(ROOT))
        from phish_blocker.agent import server  # noqa: F401

        ok("phish_blocker.agent loads")
    except Exception as e:
        fail(f"agent import failed: {e}")
        errors += 1

    print("\n8. LiveKit credentials (needed for real calls, not AWS)")
    livekit_missing = 0
    for key in ("LIVEKIT_URL", "LIVEKIT_API_KEY", "LIVEKIT_API_SECRET"):
        val = os.getenv(key, "").strip()
        if not val or "YOUR_PROJECT" in val:
            print(f"  WARN {key} not configured yet")
            livekit_missing += 1
        else:
            ok(f"{key} is set")

    print()
    if errors:
        print(f"RESULT: {errors} AWS/plugin check(s) failed")
        return 1
    if livekit_missing:
        print("RESULT: AWS setup OK — configure LiveKit creds before running the agent")
        return 0
    print("RESULT: all checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
