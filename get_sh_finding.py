
import boto3
import json
import uuid
from botocore.exceptions import ClientError
import datetime
import logging
import os
import time
from decimal import Decimal

logger = logging.getLogger()
logger.setLevel(logging.INFO)

S3_BUCKET = os.environ['S3_BUCKET']
SSM_PARAMETER_COUNT = os.environ['SSM_PARAMETER_COUNT']
# Optional: set to "true" to export JSON Lines instead of a single JSON array
EXPORT_JSONL = os.environ.get('EXPORT_JSONL', 'false').lower() == 'true'

sechub = boto3.client('securityhub')
s3 = boto3.resource('s3')
ssm = boto3.client('ssm')

# -------- Date helpers --------
def _parse_iso8601_z(dt_str: str) -> datetime.datetime:
    fmts = [
        '%Y-%m-%dT%H:%M:%SZ',
        '%Y-%m-%dT%H:%M:%S.%fZ',
    ]
    for f in fmts:
        try:
            return datetime.datetime.strptime(dt_str, f)
        except ValueError:
            continue
    raise ValueError(f"Unsupported date format: {dt_str}. Expected ISO-8601 UTC ending with 'Z'.")

def _now_z() -> str:
    return datetime.datetime.utcnow().isoformat(timespec='milliseconds') + 'Z'

# Safe JSON default for any Decimal that might sneak in from providers.
def _json_default(o):
    if isinstance(o, (datetime.date, datetime.datetime)):
        return o.isoformat()
    if isinstance(o, Decimal):
        # You may choose str(o) to avoid float rounding
        return float(o)
    raise TypeError(f"Object of type {type(o)} is not JSON serializable")

# -------- Core logic --------
def create_filter(date_filter: str, day_counter: int = 90) -> dict:
    converted = _parse_iso8601_z(date_filter)
    end = converted.isoformat(timespec='milliseconds') + 'Z'
    start_dt = converted - datetime.timedelta(days=day_counter)
    start = start_dt.isoformat(timespec='milliseconds') + 'Z'
    logger.info("Creating finding filter to get findings from %s to %s...", start, end)
    return {
        'UpdatedAt': [{'Start': start, 'End': end}],
        'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}]
    }

def _derive_region_from_product_arn(product_arn: str) -> str | None:
    # arn:partition:service:region:account-id:resource
    try:
        parts = product_arn.split(':', 5)
        return parts[3] if len(parts) > 3 else None
    except Exception:
        return None

def _resource_fallback_from_product_fields(product_fields: dict) -> dict | None:
    """Try to recover a resource Id/Arn from various vendor ProductFields."""
    if not isinstance(product_fields, dict):
        return None
    # Common-ish keys vendors use
    candidate_keys = [
        'resourceId', 'ResourceId', 'resourceArn', 'ResourceArn', 'assetDetails.resourceArn',
        'assetDetails.resourceId', 'entityArn', 'entityId', 'affectedResource', 'Resource'
    ]
    for k in candidate_keys:
        if k in product_fields and isinstance(product_fields[k], str) and product_fields[k].strip():
            val = product_fields[k].strip()
            rtype = "Other"
            if val.startswith("arn:aws:"):
                rtype = "AwsArn"
            return {
                "Id": val,
                "Type": rtype,
                "Details": None
            }
    return None

def project_finding_for_export(f: dict) -> dict:
    """Project a Security Hub finding to a compact schema that ALWAYS includes resource info if present."""
    resources = f.get('Resources') or []
    product_arn = f.get('ProductArn')
    derived_region = _derive_region_from_product_arn(product_arn) if product_arn else None

    resource_summaries = []
    for r in resources:
        resource_summaries.append({
            "Id": r.get("Id"),
            "Type": r.get("Type"),
            "Region": r.get("Region") or derived_region,
            "Partition": r.get("Partition"),
            "Tags": r.get("Tags"),
            "Details": r.get("Details")
        })

    # If provider didn’t populate Resources, try a soft recovery from ProductFields
    if not resource_summaries:
        fallback = _resource_fallback_from_product_fields(f.get('ProductFields') or {})
        if fallback:
            resource_summaries.append({
                "Id": fallback["Id"],
                "Type": fallback["Type"],
                "Region": derived_region,
                "Partition": f.get('Partition'),
                "Tags": f.get('UserDefinedFields') or None,
                "Details": fallback["Details"]
            })

    projected = {
        "Id": f.get("Id"),
        "ProductArn": product_arn,
        "AwsAccountId": f.get("AwsAccountId"),
        "GeneratorId": f.get("GeneratorId"),
        "Types": f.get("Types"),
        "Title": f.get("Title"),
        "Description": f.get("Description"),
        "Severity": f.get("Severity"),
        "Compliance": f.get("Compliance"),
        "Workflow": f.get("Workflow"),
        "RecordState": f.get("RecordState"),
        "CreatedAt": f.get("CreatedAt"),
        "UpdatedAt": f.get("UpdatedAt"),
        "Resources": resource_summaries
    }
    return projected

def get_findings(sechub_client, finding_filter: dict, next_token):
    """
    Fetch up to 50 pages (100 findings per page). Returns (next_token, results, consolidated_json).
    Now exports a projected payload that always includes a normalized Resources list.
    """
    max_pages = 50
    raw_results = []
    page = 0
    logger.info("Running export for Security Hub findings...")

    while page < max_pages:
        try:
            kwargs = {'Filters': finding_filter, 'MaxResults': 100}
            if isinstance(next_token, str) and next_token.strip():
                kwargs['NextToken'] = next_token

            response = sechub_client.get_findings(**kwargs)
            findings = response.get("Findings", [])
            raw_results.extend(findings)

            next_token = response.get('NextToken', None)
            page += 1

            if not next_token:
                logger.info("NextToken not found. Ending Security Hub finding export paging.")
                break

        except ClientError as e:
            code = e.response.get('Error', {}).get('Code')
            if code in ('TooManyRequestsException', 'ThrottlingException'):
                sleep_s = min(30, 2 ** min(page, 5)) + (0.05 * (page % 5))
                logger.warning("Throttled by Security Hub (%s). Sleeping %.2fs then retrying same page...", code, sleep_s)
                time.sleep(sleep_s)
                continue
            logger.error("ClientError in get_findings: %s", e, exc_info=True)
            raise
        except Exception as ex:
            logger.exception("Unexpected exception in get_findings: %s", ex)
            raise

    logger.info("Consolidating %d findings...", len(raw_results))

    # Project to a compact schema that lifts resource data up predictably
    projected = [project_finding_for_export(f) for f in raw_results]

    if EXPORT_JSONL:
        # JSON Lines – easier to query/append
        consolidated_results = "\n".join(
            json.dumps(item, ensure_ascii=False, separators=(",", ":"), default=_json_default)
            for item in projected
        )
    else:
        consolidated_results = json.dumps(projected, ensure_ascii=False, separators=(",", ":"), default=_json_default)

    return next_token, raw_results, consolidated_results

def sechub_count_value(results_len: int) -> int:
    logger.info("Adding %d Security Hub findings to export count...", results_len)
    current = 0
    try:
        existing = ssm.get_parameter(Name=SSM_PARAMETER_COUNT)
        current = int(existing['Parameter']['Value'])
    except ClientError as e:
        code = e.response.get('Error', {}).get('Code')
        if code != 'ParameterNotFound':
            logger.error("Failed to get SSM parameter: %s", e, exc_info=True)
            raise

    new_value = current + results_len
    try:
        ssm.put_parameter(Name=SSM_PARAMETER_COUNT, Value=str(new_value), Overwrite=True)
        logger.info("Current Security Hub export count is %d.", new_value)
    except ClientError as e:
        logger.error("Failed to put SSM parameter: %s", e, exc_info=True)
        raise
    return new_value

def put_obj_to_s3(results_len: int, consolidated_results: str):
    key = datetime.datetime.utcnow().strftime('%Y/%m/%d/%H') + "/security-hub-finding-export-" + str(uuid.uuid4()) + (".jsonl" if EXPORT_JSONL else ".json")
    try:
        logger.info("Exporting %d findings to s3://%s/%s", results_len, S3_BUCKET, key)
        s3.Bucket(S3_BUCKET).put_object(
            Key=key,
            Body=consolidated_results.encode('utf-8'),
            ContentType='application/json'
        )
        logger.info("Successfully exported %d findings to s3://%s/%s", results_len, S3_BUCKET, key)
    except ClientError as e:
        code = e.response.get('Error', {}).get('Code')
        if code == 'ConnectTimeoutError':
            time.sleep(5)
            logger.warning('Caught Connection Timeout Error... retry once')
            s3.Bucket(S3_BUCKET).put_object(
                Key=key,
                Body=consolidated_results.encode('utf-8'),
                ContentType='application/json'
            )
        else:
            logger.error("S3 put_object failed: %s", e, exc_info=True)
            raise

# -------- Handler helpers --------
def _coerce_start_date(event: dict) -> str:
    if isinstance(event, dict):
        if 'Payload' in event and isinstance(event['Payload'], dict) and 'StartDate' in event['Payload']:
            return event['Payload']['StartDate']
        if 'StartDate' in event:
            return event['StartDate']
        if 'Input' in event and isinstance(event['Input'], dict) and 'StartDate' in event['Input']:
            return event['Input']['StartDate']
    fallback = _now_z()
    logger.warning("StartDate not provided in event; defaulting to current time: %s", fallback)
    return fallback

def lambda_handler(event, context):
    try:
        logger.info("Event: %s", json.dumps(event))
    except Exception:
        logger.info("Event received (non-serializable)")

    next_token = None
    if isinstance(event, dict) and 'Payload' in event and isinstance(event['Payload'], dict):
        next_token = event['Payload'].get('NextToken')
    elif isinstance(event, dict):
        next_token = event.get('NextToken')

    date_filter = _coerce_start_date(event)
    finding_filter = create_filter(date_filter)

    sechub_count = 0

    next_token, raw_results, consolidated_results = get_findings(sechub, finding_filter, next_token)

    if raw_results:
        put_obj_to_s3(len(raw_results), consolidated_results)
        sechub_count = sechub_count_value(len(raw_results))
    else:
        logger.info("No findings returned for this window.")
        sechub_count = sechub_count_value(0)

    # Optionally include a tiny summary of how many resources we exported (avoid returning full payload)
    resource_ids_seen = 0
    try:
        # This is safe because consolidated_results is either JSONL or JSON array of projected objects
        if EXPORT_JSONL:
            resource_ids_seen = sum(
                (json.loads(line).get('Resources') and len(json.loads(line)['Resources'])) or 0
                for line in consolidated_results.splitlines() if line.strip()
            )
        else:
            arr = json.loads(consolidated_results)
            resource_ids_seen = sum(len(item.get('Resources') or []) for item in arr)
    except Exception:
        pass

    return {
        'NextToken': next_token,
        'SecHubCount': sechub_count,
        'StartDate': date_filter,
        'ExportedResourceRefs': resource_ids_seen
    }
