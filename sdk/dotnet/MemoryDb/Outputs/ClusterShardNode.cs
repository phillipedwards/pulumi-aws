// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Aws.MemoryDb.Outputs
{

    [OutputType]
    public sealed class ClusterShardNode
    {
        /// <summary>
        /// The Availability Zone in which the node resides.
        /// </summary>
        public readonly string? AvailabilityZone;
        /// <summary>
        /// The date and time when the node was created. Example: `2022-01-01T21:00:00Z`.
        /// </summary>
        public readonly string? CreateTime;
        public readonly ImmutableArray<Outputs.ClusterShardNodeEndpoint> Endpoints;
        /// <summary>
        /// Name of this node.
        /// * `endpoint`
        /// </summary>
        public readonly string? Name;

        [OutputConstructor]
        private ClusterShardNode(
            string? availabilityZone,

            string? createTime,

            ImmutableArray<Outputs.ClusterShardNodeEndpoint> endpoints,

            string? name)
        {
            AvailabilityZone = availabilityZone;
            CreateTime = createTime;
            Endpoints = endpoints;
            Name = name;
        }
    }
}
