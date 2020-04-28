// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Aws.S3
{
    /// <summary>
    /// Provides a resource to manage an S3 Access Point.
    /// </summary>
    public partial class AccessPoint : Pulumi.CustomResource
    {
        /// <summary>
        /// The AWS account ID for the owner of the bucket for which you want to create an access point. Defaults to automatically determined account ID of the provider.
        /// </summary>
        [Output("accountId")]
        public Output<string> AccountId { get; private set; } = null!;

        /// <summary>
        /// Amazon Resource Name (ARN) of the S3 Access Point.
        /// </summary>
        [Output("arn")]
        public Output<string> Arn { get; private set; } = null!;

        /// <summary>
        /// The name of the bucket that you want to associate this access point with.
        /// </summary>
        [Output("bucket")]
        public Output<string> Bucket { get; private set; } = null!;

        /// <summary>
        /// The DNS domain name of the S3 Access Point in the format _`name`_-_`account_id`_.s3-accesspoint._region_.amazonaws.com.
        /// Note: S3 access points only support secure access by HTTPS. HTTP isn't supported.
        /// </summary>
        [Output("domainName")]
        public Output<string> DomainName { get; private set; } = null!;

        /// <summary>
        /// Indicates whether this access point currently has a policy that allows public access.
        /// </summary>
        [Output("hasPublicAccessPolicy")]
        public Output<bool> HasPublicAccessPolicy { get; private set; } = null!;

        /// <summary>
        /// The name you want to assign to this access point.
        /// </summary>
        [Output("name")]
        public Output<string> Name { get; private set; } = null!;

        /// <summary>
        /// Indicates whether this access point allows access from the public Internet. Values are `VPC` (the access point doesn't allow access from the public Internet) and `Internet` (the access point allows access from the public Internet, subject to the access point and bucket access policies).
        /// </summary>
        [Output("networkOrigin")]
        public Output<string> NetworkOrigin { get; private set; } = null!;

        /// <summary>
        /// A valid JSON document that specifies the policy that you want to apply to this access point.
        /// </summary>
        [Output("policy")]
        public Output<string?> Policy { get; private set; } = null!;

        /// <summary>
        /// Configuration block to manage the `PublicAccessBlock` configuration that you want to apply to this Amazon S3 bucket. You can enable the configuration options in any combination. Detailed below.
        /// </summary>
        [Output("publicAccessBlockConfiguration")]
        public Output<Outputs.AccessPointPublicAccessBlockConfiguration?> PublicAccessBlockConfiguration { get; private set; } = null!;

        /// <summary>
        /// Configuration block to restrict access to this access point to requests from the specified Virtual Private Cloud (VPC). Detailed below.
        /// </summary>
        [Output("vpcConfiguration")]
        public Output<Outputs.AccessPointVpcConfiguration?> VpcConfiguration { get; private set; } = null!;


        /// <summary>
        /// Create a AccessPoint resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public AccessPoint(string name, AccessPointArgs args, CustomResourceOptions? options = null)
            : base("aws:s3/accessPoint:AccessPoint", name, args ?? new AccessPointArgs(), MakeResourceOptions(options, ""))
        {
        }

        private AccessPoint(string name, Input<string> id, AccessPointState? state = null, CustomResourceOptions? options = null)
            : base("aws:s3/accessPoint:AccessPoint", name, state, MakeResourceOptions(options, id))
        {
        }

        private static CustomResourceOptions MakeResourceOptions(CustomResourceOptions? options, Input<string>? id)
        {
            var defaultOptions = new CustomResourceOptions
            {
                Version = Utilities.Version,
            };
            var merged = CustomResourceOptions.Merge(defaultOptions, options);
            // Override the ID if one was specified for consistency with other language SDKs.
            merged.Id = id ?? merged.Id;
            return merged;
        }
        /// <summary>
        /// Get an existing AccessPoint resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static AccessPoint Get(string name, Input<string> id, AccessPointState? state = null, CustomResourceOptions? options = null)
        {
            return new AccessPoint(name, id, state, options);
        }
    }

    public sealed class AccessPointArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The AWS account ID for the owner of the bucket for which you want to create an access point. Defaults to automatically determined account ID of the provider.
        /// </summary>
        [Input("accountId")]
        public Input<string>? AccountId { get; set; }

        /// <summary>
        /// The name of the bucket that you want to associate this access point with.
        /// </summary>
        [Input("bucket", required: true)]
        public Input<string> Bucket { get; set; } = null!;

        /// <summary>
        /// The name you want to assign to this access point.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// A valid JSON document that specifies the policy that you want to apply to this access point.
        /// </summary>
        [Input("policy")]
        public Input<string>? Policy { get; set; }

        /// <summary>
        /// Configuration block to manage the `PublicAccessBlock` configuration that you want to apply to this Amazon S3 bucket. You can enable the configuration options in any combination. Detailed below.
        /// </summary>
        [Input("publicAccessBlockConfiguration")]
        public Input<Inputs.AccessPointPublicAccessBlockConfigurationArgs>? PublicAccessBlockConfiguration { get; set; }

        /// <summary>
        /// Configuration block to restrict access to this access point to requests from the specified Virtual Private Cloud (VPC). Detailed below.
        /// </summary>
        [Input("vpcConfiguration")]
        public Input<Inputs.AccessPointVpcConfigurationArgs>? VpcConfiguration { get; set; }

        public AccessPointArgs()
        {
        }
    }

    public sealed class AccessPointState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The AWS account ID for the owner of the bucket for which you want to create an access point. Defaults to automatically determined account ID of the provider.
        /// </summary>
        [Input("accountId")]
        public Input<string>? AccountId { get; set; }

        /// <summary>
        /// Amazon Resource Name (ARN) of the S3 Access Point.
        /// </summary>
        [Input("arn")]
        public Input<string>? Arn { get; set; }

        /// <summary>
        /// The name of the bucket that you want to associate this access point with.
        /// </summary>
        [Input("bucket")]
        public Input<string>? Bucket { get; set; }

        /// <summary>
        /// The DNS domain name of the S3 Access Point in the format _`name`_-_`account_id`_.s3-accesspoint._region_.amazonaws.com.
        /// Note: S3 access points only support secure access by HTTPS. HTTP isn't supported.
        /// </summary>
        [Input("domainName")]
        public Input<string>? DomainName { get; set; }

        /// <summary>
        /// Indicates whether this access point currently has a policy that allows public access.
        /// </summary>
        [Input("hasPublicAccessPolicy")]
        public Input<bool>? HasPublicAccessPolicy { get; set; }

        /// <summary>
        /// The name you want to assign to this access point.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// Indicates whether this access point allows access from the public Internet. Values are `VPC` (the access point doesn't allow access from the public Internet) and `Internet` (the access point allows access from the public Internet, subject to the access point and bucket access policies).
        /// </summary>
        [Input("networkOrigin")]
        public Input<string>? NetworkOrigin { get; set; }

        /// <summary>
        /// A valid JSON document that specifies the policy that you want to apply to this access point.
        /// </summary>
        [Input("policy")]
        public Input<string>? Policy { get; set; }

        /// <summary>
        /// Configuration block to manage the `PublicAccessBlock` configuration that you want to apply to this Amazon S3 bucket. You can enable the configuration options in any combination. Detailed below.
        /// </summary>
        [Input("publicAccessBlockConfiguration")]
        public Input<Inputs.AccessPointPublicAccessBlockConfigurationGetArgs>? PublicAccessBlockConfiguration { get; set; }

        /// <summary>
        /// Configuration block to restrict access to this access point to requests from the specified Virtual Private Cloud (VPC). Detailed below.
        /// </summary>
        [Input("vpcConfiguration")]
        public Input<Inputs.AccessPointVpcConfigurationGetArgs>? VpcConfiguration { get; set; }

        public AccessPointState()
        {
        }
    }
}