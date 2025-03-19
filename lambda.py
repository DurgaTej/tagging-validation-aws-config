import json
import boto3
import urllib3
import os

# Allowed values for the "mmsystem" tag
ALLOWED_VALUES = {"finance", "hr", "it", "marketing", "sales"}

config_client = boto3.client("config")
http = urllib3.PoolManager()

# Get Slack Webhook URL from environment variable
SLACK_WEBHOOK_URL = os.environ['SLACK_WEBHOOK_URL']

def send_slack_alert(resource_id, resource_type, annotation):
    # Construct the Slack message in table format
    slack_message = {
        "text": f":rotating_light: *AWS Config Alert!* :rotating_light:\n\n"
                f"*Resource ID:* `{resource_id}`\n"
                f"*Resource Type:* `{resource_type}`\n"
                f"*Compliance Status:* `NON_COMPLIANT`\n"
                f"*Reason for Non-Compliance:* {annotation}\n"
                f"Check AWS Config for more details."
    }

    # Send message to Slack
    response = http.request(
        "POST",
        SLACK_WEBHOOK_URL,
        body=json.dumps(slack_message),
        headers={"Content-Type": "application/json"}
    )

    print("Slack Response:", response.status, response.data)

def lambda_handler(event, context):
    print("Received event:", json.dumps(event))

    invoking_event = json.loads(event["invokingEvent"])
    configuration_item = invoking_event["configurationItem"]

    resource_id = configuration_item["resourceId"]
    resource_type = configuration_item["resourceType"]

    compliance_type = "COMPLIANT"

    # Check if the resource has tags
    tags = configuration_item.get("tags", {})

    if "mmsystem" not in tags:
        compliance_type = "NON_COMPLIANT"
        annotation = "Missing required 'mmsystem' tag."
        send_slack_alert(resource_id, resource_type, annotation)
    elif tags["mmsystem"] not in ALLOWED_VALUES:
        compliance_type = "NON_COMPLIANT"
        annotation = f"Invalid 'mmsystem' value: {tags['mmsystem']}. Allowed values: {', '.join(ALLOWED_VALUES)}."
        send_slack_alert(resource_id, resource_type, annotation)
    else:
        annotation = "'mmsystem' tag is present and valid."

    # Report compliance status to AWS Config
    response = config_client.put_evaluations(
        Evaluations=[
            {
                "ComplianceResourceType": resource_type,
                "ComplianceResourceId": resource_id,
                "ComplianceType": compliance_type,
                "Annotation": annotation,
                "OrderingTimestamp": configuration_item["configurationItemCaptureTime"],
            }
        ],
        ResultToken=event["resultToken"],
    )

    return response
