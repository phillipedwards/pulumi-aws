// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package cloudfront

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// Provides information about a CloudFront Function.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws/cloudfront"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi/config"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		cfg := config.New(ctx, "")
// 		functionName := cfg.Require("functionName")
// 		_, err := cloudfront.LookupFunction(ctx, &cloudfront.LookupFunctionArgs{
// 			Name: functionName,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func LookupFunction(ctx *pulumi.Context, args *LookupFunctionArgs, opts ...pulumi.InvokeOption) (*LookupFunctionResult, error) {
	var rv LookupFunctionResult
	err := ctx.Invoke("aws:cloudfront/getFunction:getFunction", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getFunction.
type LookupFunctionArgs struct {
	// Name of the CloudFront function.
	Name string `pulumi:"name"`
	// The function’s stage, either `DEVELOPMENT` or `LIVE`.
	Stage string `pulumi:"stage"`
}

// A collection of values returned by getFunction.
type LookupFunctionResult struct {
	// Amazon Resource Name (ARN) identifying your CloudFront Function.
	Arn string `pulumi:"arn"`
	// Source code of the function
	Code string `pulumi:"code"`
	// Comment.
	Comment string `pulumi:"comment"`
	// ETag hash of the function
	Etag string `pulumi:"etag"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// When this resource was last modified.
	LastModifiedTime string `pulumi:"lastModifiedTime"`
	Name             string `pulumi:"name"`
	// Identifier of the function's runtime.
	Runtime string `pulumi:"runtime"`
	Stage   string `pulumi:"stage"`
	// Status of the function. Can be `UNPUBLISHED`, `UNASSOCIATED` or `ASSOCIATED`.
	Status string `pulumi:"status"`
}

func LookupFunctionOutput(ctx *pulumi.Context, args LookupFunctionOutputArgs, opts ...pulumi.InvokeOption) LookupFunctionResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (LookupFunctionResult, error) {
			args := v.(LookupFunctionArgs)
			r, err := LookupFunction(ctx, &args, opts...)
			return *r, err
		}).(LookupFunctionResultOutput)
}

// A collection of arguments for invoking getFunction.
type LookupFunctionOutputArgs struct {
	// Name of the CloudFront function.
	Name pulumi.StringInput `pulumi:"name"`
	// The function’s stage, either `DEVELOPMENT` or `LIVE`.
	Stage pulumi.StringInput `pulumi:"stage"`
}

func (LookupFunctionOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupFunctionArgs)(nil)).Elem()
}

// A collection of values returned by getFunction.
type LookupFunctionResultOutput struct{ *pulumi.OutputState }

func (LookupFunctionResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupFunctionResult)(nil)).Elem()
}

func (o LookupFunctionResultOutput) ToLookupFunctionResultOutput() LookupFunctionResultOutput {
	return o
}

func (o LookupFunctionResultOutput) ToLookupFunctionResultOutputWithContext(ctx context.Context) LookupFunctionResultOutput {
	return o
}

// Amazon Resource Name (ARN) identifying your CloudFront Function.
func (o LookupFunctionResultOutput) Arn() pulumi.StringOutput {
	return o.ApplyT(func(v LookupFunctionResult) string { return v.Arn }).(pulumi.StringOutput)
}

// Source code of the function
func (o LookupFunctionResultOutput) Code() pulumi.StringOutput {
	return o.ApplyT(func(v LookupFunctionResult) string { return v.Code }).(pulumi.StringOutput)
}

// Comment.
func (o LookupFunctionResultOutput) Comment() pulumi.StringOutput {
	return o.ApplyT(func(v LookupFunctionResult) string { return v.Comment }).(pulumi.StringOutput)
}

// ETag hash of the function
func (o LookupFunctionResultOutput) Etag() pulumi.StringOutput {
	return o.ApplyT(func(v LookupFunctionResult) string { return v.Etag }).(pulumi.StringOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o LookupFunctionResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupFunctionResult) string { return v.Id }).(pulumi.StringOutput)
}

// When this resource was last modified.
func (o LookupFunctionResultOutput) LastModifiedTime() pulumi.StringOutput {
	return o.ApplyT(func(v LookupFunctionResult) string { return v.LastModifiedTime }).(pulumi.StringOutput)
}

func (o LookupFunctionResultOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v LookupFunctionResult) string { return v.Name }).(pulumi.StringOutput)
}

// Identifier of the function's runtime.
func (o LookupFunctionResultOutput) Runtime() pulumi.StringOutput {
	return o.ApplyT(func(v LookupFunctionResult) string { return v.Runtime }).(pulumi.StringOutput)
}

func (o LookupFunctionResultOutput) Stage() pulumi.StringOutput {
	return o.ApplyT(func(v LookupFunctionResult) string { return v.Stage }).(pulumi.StringOutput)
}

// Status of the function. Can be `UNPUBLISHED`, `UNASSOCIATED` or `ASSOCIATED`.
func (o LookupFunctionResultOutput) Status() pulumi.StringOutput {
	return o.ApplyT(func(v LookupFunctionResult) string { return v.Status }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupFunctionResultOutput{})
}