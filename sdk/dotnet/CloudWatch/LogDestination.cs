// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Aws.CloudWatch
{
    /// <summary>
    /// Provides a CloudWatch Logs destination resource.
    /// </summary>
    public partial class LogDestination : Pulumi.CustomResource
    {
        /// <summary>
        /// The Amazon Resource Name (ARN) specifying the log destination.
        /// </summary>
        [Output("arn")]
        public Output<string> Arn { get; private set; } = null!;

        /// <summary>
        /// A name for the log destination
        /// </summary>
        [Output("name")]
        public Output<string> Name { get; private set; } = null!;

        /// <summary>
        /// The ARN of an IAM role that grants Amazon CloudWatch Logs permissions to put data into the target
        /// </summary>
        [Output("roleArn")]
        public Output<string> RoleArn { get; private set; } = null!;

        /// <summary>
        /// The ARN of the target Amazon Kinesis stream resource for the destination
        /// </summary>
        [Output("targetArn")]
        public Output<string> TargetArn { get; private set; } = null!;


        /// <summary>
        /// Create a LogDestination resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public LogDestination(string name, LogDestinationArgs args, CustomResourceOptions? options = null)
            : base("aws:cloudwatch/logDestination:LogDestination", name, args ?? new LogDestinationArgs(), MakeResourceOptions(options, ""))
        {
        }

        private LogDestination(string name, Input<string> id, LogDestinationState? state = null, CustomResourceOptions? options = null)
            : base("aws:cloudwatch/logDestination:LogDestination", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing LogDestination resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static LogDestination Get(string name, Input<string> id, LogDestinationState? state = null, CustomResourceOptions? options = null)
        {
            return new LogDestination(name, id, state, options);
        }
    }

    public sealed class LogDestinationArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// A name for the log destination
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// The ARN of an IAM role that grants Amazon CloudWatch Logs permissions to put data into the target
        /// </summary>
        [Input("roleArn", required: true)]
        public Input<string> RoleArn { get; set; } = null!;

        /// <summary>
        /// The ARN of the target Amazon Kinesis stream resource for the destination
        /// </summary>
        [Input("targetArn", required: true)]
        public Input<string> TargetArn { get; set; } = null!;

        public LogDestinationArgs()
        {
        }
    }

    public sealed class LogDestinationState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The Amazon Resource Name (ARN) specifying the log destination.
        /// </summary>
        [Input("arn")]
        public Input<string>? Arn { get; set; }

        /// <summary>
        /// A name for the log destination
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// The ARN of an IAM role that grants Amazon CloudWatch Logs permissions to put data into the target
        /// </summary>
        [Input("roleArn")]
        public Input<string>? RoleArn { get; set; }

        /// <summary>
        /// The ARN of the target Amazon Kinesis stream resource for the destination
        /// </summary>
        [Input("targetArn")]
        public Input<string>? TargetArn { get; set; }

        public LogDestinationState()
        {
        }
    }
}