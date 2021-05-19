// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Aws.Macie2.Outputs
{

    [OutputType]
    public sealed class ClassificationJobUserPausedDetail
    {
        public readonly string? JobExpiresAt;
        public readonly string? JobImminentExpirationHealthEventArn;
        public readonly string? JobPausedAt;

        [OutputConstructor]
        private ClassificationJobUserPausedDetail(
            string? jobExpiresAt,

            string? jobImminentExpirationHealthEventArn,

            string? jobPausedAt)
        {
            JobExpiresAt = jobExpiresAt;
            JobImminentExpirationHealthEventArn = jobImminentExpirationHealthEventArn;
            JobPausedAt = jobPausedAt;
        }
    }
}