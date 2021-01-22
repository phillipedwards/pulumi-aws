// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package kinesis

import (
	"fmt"

	"github.com/blang/semver"
	"github.com/pulumi/pulumi-aws/sdk/v3/go/aws"
	"github.com/pulumi/pulumi/sdk/v2/go/pulumi"
)

type module struct {
	version semver.Version
}

func (m *module) Version() semver.Version {
	return m.version
}

func (m *module) Construct(ctx *pulumi.Context, name, typ, urn string) (r pulumi.Resource, err error) {
	switch typ {
	case "aws:kinesis/analyticsApplication:AnalyticsApplication":
		r, err = NewAnalyticsApplication(ctx, name, nil, pulumi.URN_(urn))
	case "aws:kinesis/firehoseDeliveryStream:FirehoseDeliveryStream":
		r, err = NewFirehoseDeliveryStream(ctx, name, nil, pulumi.URN_(urn))
	case "aws:kinesis/stream:Stream":
		r, err = NewStream(ctx, name, nil, pulumi.URN_(urn))
	case "aws:kinesis/videoStream:VideoStream":
		r, err = NewVideoStream(ctx, name, nil, pulumi.URN_(urn))
	default:
		return nil, fmt.Errorf("unknown resource type: %s", typ)
	}

	return
}

func init() {
	version, err := aws.PkgVersion()
	if err != nil {
		fmt.Println("failed to determine package version. defaulting to v1: %v", err)
	}
	pulumi.RegisterResourceModule(
		"aws",
		"kinesis/analyticsApplication",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"aws",
		"kinesis/firehoseDeliveryStream",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"aws",
		"kinesis/stream",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"aws",
		"kinesis/videoStream",
		&module{version},
	)
}