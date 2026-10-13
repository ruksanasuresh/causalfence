import json
import os
import boto3
table = boto3.resource("dynamodb").Table(os.environ["TABLE_NAME"])
def handler(event, context):
    """Toy read-only report: how many (fake) patient records exist."""
    count = table.scan(Select="COUNT")["Count"]
    return {"statusCode": 200, "body": json.dumps({"patients": count})}
