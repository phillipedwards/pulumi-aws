// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package glue

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v2/go/pulumi"
)

// Provides a Glue Data Catalog Encryption Settings resource.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-aws/sdk/v3/go/aws/glue"
// 	"github.com/pulumi/pulumi/sdk/v2/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		_, err := glue.NewDataCatalogEncryptionSettings(ctx, "example", &glue.DataCatalogEncryptionSettingsArgs{
// 			DataCatalogEncryptionSettings: &glue.DataCatalogEncryptionSettingsDataCatalogEncryptionSettingsArgs{
// 				ConnectionPasswordEncryption: &glue.DataCatalogEncryptionSettingsDataCatalogEncryptionSettingsConnectionPasswordEncryptionArgs{
// 					AwsKmsKeyId:                       pulumi.Any(aws_kms_key.Test.Arn),
// 					ReturnConnectionPasswordEncrypted: pulumi.Bool(true),
// 				},
// 				EncryptionAtRest: &glue.DataCatalogEncryptionSettingsDataCatalogEncryptionSettingsEncryptionAtRestArgs{
// 					CatalogEncryptionMode: pulumi.String("SSE-KMS"),
// 					SseAwsKmsKeyId:        pulumi.Any(aws_kms_key.Test.Arn),
// 				},
// 			},
// 		})
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
//
// ## Import
//
// Glue Data Catalog Encryption Settings can be imported using `CATALOG-ID` (AWS account ID if not custom), e.g.
//
// ```sh
//  $ pulumi import aws:glue/dataCatalogEncryptionSettings:DataCatalogEncryptionSettings example 123456789012
// ```
type DataCatalogEncryptionSettings struct {
	pulumi.CustomResourceState

	// The ID of the Data Catalog to set the security configuration for. If none is provided, the AWS account ID is used by default.
	CatalogId pulumi.StringOutput `pulumi:"catalogId"`
	// The security configuration to set. see Data Catalog Encryption Settings.
	DataCatalogEncryptionSettings DataCatalogEncryptionSettingsDataCatalogEncryptionSettingsOutput `pulumi:"dataCatalogEncryptionSettings"`
}

// NewDataCatalogEncryptionSettings registers a new resource with the given unique name, arguments, and options.
func NewDataCatalogEncryptionSettings(ctx *pulumi.Context,
	name string, args *DataCatalogEncryptionSettingsArgs, opts ...pulumi.ResourceOption) (*DataCatalogEncryptionSettings, error) {
	if args == nil || args.DataCatalogEncryptionSettings == nil {
		return nil, errors.New("missing required argument 'DataCatalogEncryptionSettings'")
	}
	if args == nil {
		args = &DataCatalogEncryptionSettingsArgs{}
	}
	var resource DataCatalogEncryptionSettings
	err := ctx.RegisterResource("aws:glue/dataCatalogEncryptionSettings:DataCatalogEncryptionSettings", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetDataCatalogEncryptionSettings gets an existing DataCatalogEncryptionSettings resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetDataCatalogEncryptionSettings(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *DataCatalogEncryptionSettingsState, opts ...pulumi.ResourceOption) (*DataCatalogEncryptionSettings, error) {
	var resource DataCatalogEncryptionSettings
	err := ctx.ReadResource("aws:glue/dataCatalogEncryptionSettings:DataCatalogEncryptionSettings", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering DataCatalogEncryptionSettings resources.
type dataCatalogEncryptionSettingsState struct {
	// The ID of the Data Catalog to set the security configuration for. If none is provided, the AWS account ID is used by default.
	CatalogId *string `pulumi:"catalogId"`
	// The security configuration to set. see Data Catalog Encryption Settings.
	DataCatalogEncryptionSettings *DataCatalogEncryptionSettingsDataCatalogEncryptionSettings `pulumi:"dataCatalogEncryptionSettings"`
}

type DataCatalogEncryptionSettingsState struct {
	// The ID of the Data Catalog to set the security configuration for. If none is provided, the AWS account ID is used by default.
	CatalogId pulumi.StringPtrInput
	// The security configuration to set. see Data Catalog Encryption Settings.
	DataCatalogEncryptionSettings DataCatalogEncryptionSettingsDataCatalogEncryptionSettingsPtrInput
}

func (DataCatalogEncryptionSettingsState) ElementType() reflect.Type {
	return reflect.TypeOf((*dataCatalogEncryptionSettingsState)(nil)).Elem()
}

type dataCatalogEncryptionSettingsArgs struct {
	// The ID of the Data Catalog to set the security configuration for. If none is provided, the AWS account ID is used by default.
	CatalogId *string `pulumi:"catalogId"`
	// The security configuration to set. see Data Catalog Encryption Settings.
	DataCatalogEncryptionSettings DataCatalogEncryptionSettingsDataCatalogEncryptionSettings `pulumi:"dataCatalogEncryptionSettings"`
}

// The set of arguments for constructing a DataCatalogEncryptionSettings resource.
type DataCatalogEncryptionSettingsArgs struct {
	// The ID of the Data Catalog to set the security configuration for. If none is provided, the AWS account ID is used by default.
	CatalogId pulumi.StringPtrInput
	// The security configuration to set. see Data Catalog Encryption Settings.
	DataCatalogEncryptionSettings DataCatalogEncryptionSettingsDataCatalogEncryptionSettingsInput
}

func (DataCatalogEncryptionSettingsArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*dataCatalogEncryptionSettingsArgs)(nil)).Elem()
}

type DataCatalogEncryptionSettingsInput interface {
	pulumi.Input

	ToDataCatalogEncryptionSettingsOutput() DataCatalogEncryptionSettingsOutput
	ToDataCatalogEncryptionSettingsOutputWithContext(ctx context.Context) DataCatalogEncryptionSettingsOutput
}

func (DataCatalogEncryptionSettings) ElementType() reflect.Type {
	return reflect.TypeOf((*DataCatalogEncryptionSettings)(nil)).Elem()
}

func (i DataCatalogEncryptionSettings) ToDataCatalogEncryptionSettingsOutput() DataCatalogEncryptionSettingsOutput {
	return i.ToDataCatalogEncryptionSettingsOutputWithContext(context.Background())
}

func (i DataCatalogEncryptionSettings) ToDataCatalogEncryptionSettingsOutputWithContext(ctx context.Context) DataCatalogEncryptionSettingsOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DataCatalogEncryptionSettingsOutput)
}

type DataCatalogEncryptionSettingsOutput struct {
	*pulumi.OutputState
}

func (DataCatalogEncryptionSettingsOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*DataCatalogEncryptionSettingsOutput)(nil)).Elem()
}

func (o DataCatalogEncryptionSettingsOutput) ToDataCatalogEncryptionSettingsOutput() DataCatalogEncryptionSettingsOutput {
	return o
}

func (o DataCatalogEncryptionSettingsOutput) ToDataCatalogEncryptionSettingsOutputWithContext(ctx context.Context) DataCatalogEncryptionSettingsOutput {
	return o
}

func init() {
	pulumi.RegisterOutputType(DataCatalogEncryptionSettingsOutput{})
}