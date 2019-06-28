# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import json
import warnings
import pulumi
import pulumi.runtime
from .. import utilities, tables

class GetDefaultKmsKeyResult:
    """
    A collection of values returned by getDefaultKmsKey.
    """
    def __init__(__self__, key_arn=None, id=None):
        if key_arn and not isinstance(key_arn, str):
            raise TypeError("Expected argument 'key_arn' to be a str")
        __self__.key_arn = key_arn
        """
        Amazon Resource Name (ARN) of the default KMS key uses to encrypt an EBS volume in this region when no key is specified in an API call that creates the volume and encryption by default is enabled.
        """
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        __self__.id = id
        """
        id is the provider-assigned unique ID for this managed resource.
        """

async def get_default_kms_key(opts=None):
    """
    Use this data source to get the default EBS encryption KMS key in the current region.
    """
    __args__ = dict()

    __ret__ = await pulumi.runtime.invoke('aws:ebs/getDefaultKmsKey:getDefaultKmsKey', __args__, opts=opts)

    return GetDefaultKmsKeyResult(
        key_arn=__ret__.get('keyArn'),
        id=__ret__.get('id'))