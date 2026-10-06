import json
import os
import uuid

import boto3

table = boto3.resource("dynamodb").Table(os.environ["TABLE_NAME"])


def handler(event, context):
    method = event["requestContext"]["http"]["method"]

    if method == "POST":
        item = {"patient_id": str(uuid.uuid4()), "note": "demo record"}
        table.put_item(Item=item)
        return {"statusCode": 201, "body": json.dumps(item)}

    count = table.scan(Select="COUNT")["Count"]
    return {"statusCode": 200, "body": json.dumps({"patients": count})}