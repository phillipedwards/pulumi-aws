// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package lightsail

import (
	"fmt"

	"github.com/blang/semver"
	"github.com/pulumi/pulumi-aws/sdk/go/aws"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

type module struct {
	version semver.Version
}

func (m *module) Version() semver.Version {
	return m.version
}

func (m *module) Construct(ctx *pulumi.Context, name, typ, urn string) (r pulumi.Resource, err error) {
	switch typ {
	case "aws:lightsail/containerService:ContainerService":
		r = &ContainerService{}
	case "aws:lightsail/containerServiceDeploymentVersion:ContainerServiceDeploymentVersion":
		r = &ContainerServiceDeploymentVersion{}
	case "aws:lightsail/database:Database":
		r = &Database{}
	case "aws:lightsail/domain:Domain":
		r = &Domain{}
	case "aws:lightsail/instance:Instance":
		r = &Instance{}
	case "aws:lightsail/instancePublicPorts:InstancePublicPorts":
		r = &InstancePublicPorts{}
	case "aws:lightsail/keyPair:KeyPair":
		r = &KeyPair{}
	case "aws:lightsail/staticIp:StaticIp":
		r = &StaticIp{}
	case "aws:lightsail/staticIpAttachment:StaticIpAttachment":
		r = &StaticIpAttachment{}
	default:
		return nil, fmt.Errorf("unknown resource type: %s", typ)
	}

	err = ctx.RegisterResource(typ, name, nil, r, pulumi.URN_(urn))
	return
}

func init() {
	version, err := aws.PkgVersion()
	if err != nil {
		version = semver.Version{Major: 1}
	}
	pulumi.RegisterResourceModule(
		"aws",
		"lightsail/containerService",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"aws",
		"lightsail/containerServiceDeploymentVersion",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"aws",
		"lightsail/database",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"aws",
		"lightsail/domain",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"aws",
		"lightsail/instance",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"aws",
		"lightsail/instancePublicPorts",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"aws",
		"lightsail/keyPair",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"aws",
		"lightsail/staticIp",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"aws",
		"lightsail/staticIpAttachment",
		&module{version},
	)
}
