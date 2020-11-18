// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Aws.AppMesh.Inputs
{

    public sealed class RouteSpecGrpcRouteGetArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The action to take if a match is determined.
        /// </summary>
        [Input("action", required: true)]
        public Input<Inputs.RouteSpecGrpcRouteActionGetArgs> Action { get; set; } = null!;

        /// <summary>
        /// The criteria for determining an gRPC request match.
        /// </summary>
        [Input("match", required: true)]
        public Input<Inputs.RouteSpecGrpcRouteMatchGetArgs> Match { get; set; } = null!;

        /// <summary>
        /// The retry policy.
        /// </summary>
        [Input("retryPolicy")]
        public Input<Inputs.RouteSpecGrpcRouteRetryPolicyGetArgs>? RetryPolicy { get; set; }

        /// <summary>
        /// The types of timeouts.
        /// </summary>
        [Input("timeout")]
        public Input<Inputs.RouteSpecGrpcRouteTimeoutGetArgs>? Timeout { get; set; }

        public RouteSpecGrpcRouteGetArgs()
        {
        }
    }
}