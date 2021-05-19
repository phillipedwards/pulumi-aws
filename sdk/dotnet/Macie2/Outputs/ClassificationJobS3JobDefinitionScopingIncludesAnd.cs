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
    public sealed class ClassificationJobS3JobDefinitionScopingIncludesAnd
    {
        /// <summary>
        /// A property-based condition that defines a property, operator, and one or more values for including or excluding an object from the job.  (documented below)
        /// </summary>
        public readonly Outputs.ClassificationJobS3JobDefinitionScopingIncludesAndSimpleScopeTerm? SimpleScopeTerm;
        /// <summary>
        /// A tag-based condition that defines the operator and tag keys or tag key and value pairs for including or excluding an object from the job.  (documented below)
        /// </summary>
        public readonly Outputs.ClassificationJobS3JobDefinitionScopingIncludesAndTagScopeTerm? TagScopeTerm;

        [OutputConstructor]
        private ClassificationJobS3JobDefinitionScopingIncludesAnd(
            Outputs.ClassificationJobS3JobDefinitionScopingIncludesAndSimpleScopeTerm? simpleScopeTerm,

            Outputs.ClassificationJobS3JobDefinitionScopingIncludesAndTagScopeTerm? tagScopeTerm)
        {
            SimpleScopeTerm = simpleScopeTerm;
            TagScopeTerm = tagScopeTerm;
        }
    }
}