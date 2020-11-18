// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Aws.WafV2.Outputs
{

    [OutputType]
    public sealed class RuleGroupRuleStatementNotStatementStatementNotStatementStatementSqliMatchStatementFieldToMatch
    {
        /// <summary>
        /// Inspect all query arguments.
        /// </summary>
        public readonly Outputs.RuleGroupRuleStatementNotStatementStatementNotStatementStatementSqliMatchStatementFieldToMatchAllQueryArguments? AllQueryArguments;
        /// <summary>
        /// Inspect the request body, which immediately follows the request headers.
        /// </summary>
        public readonly Outputs.RuleGroupRuleStatementNotStatementStatementNotStatementStatementSqliMatchStatementFieldToMatchBody? Body;
        /// <summary>
        /// Inspect the HTTP method. The method indicates the type of operation that the request is asking the origin to perform.
        /// </summary>
        public readonly Outputs.RuleGroupRuleStatementNotStatementStatementNotStatementStatementSqliMatchStatementFieldToMatchMethod? Method;
        /// <summary>
        /// Inspect the query string. This is the part of a URL that appears after a `?` character, if any.
        /// </summary>
        public readonly Outputs.RuleGroupRuleStatementNotStatementStatementNotStatementStatementSqliMatchStatementFieldToMatchQueryString? QueryString;
        /// <summary>
        /// Inspect a single header. See Single Header below for details.
        /// </summary>
        public readonly Outputs.RuleGroupRuleStatementNotStatementStatementNotStatementStatementSqliMatchStatementFieldToMatchSingleHeader? SingleHeader;
        /// <summary>
        /// Inspect a single query argument. See Single Query Argument below for details.
        /// </summary>
        public readonly Outputs.RuleGroupRuleStatementNotStatementStatementNotStatementStatementSqliMatchStatementFieldToMatchSingleQueryArgument? SingleQueryArgument;
        /// <summary>
        /// Inspect the request URI path. This is the part of a web request that identifies a resource, for example, `/images/daily-ad.jpg`.
        /// </summary>
        public readonly Outputs.RuleGroupRuleStatementNotStatementStatementNotStatementStatementSqliMatchStatementFieldToMatchUriPath? UriPath;

        [OutputConstructor]
        private RuleGroupRuleStatementNotStatementStatementNotStatementStatementSqliMatchStatementFieldToMatch(
            Outputs.RuleGroupRuleStatementNotStatementStatementNotStatementStatementSqliMatchStatementFieldToMatchAllQueryArguments? allQueryArguments,

            Outputs.RuleGroupRuleStatementNotStatementStatementNotStatementStatementSqliMatchStatementFieldToMatchBody? body,

            Outputs.RuleGroupRuleStatementNotStatementStatementNotStatementStatementSqliMatchStatementFieldToMatchMethod? method,

            Outputs.RuleGroupRuleStatementNotStatementStatementNotStatementStatementSqliMatchStatementFieldToMatchQueryString? queryString,

            Outputs.RuleGroupRuleStatementNotStatementStatementNotStatementStatementSqliMatchStatementFieldToMatchSingleHeader? singleHeader,

            Outputs.RuleGroupRuleStatementNotStatementStatementNotStatementStatementSqliMatchStatementFieldToMatchSingleQueryArgument? singleQueryArgument,

            Outputs.RuleGroupRuleStatementNotStatementStatementNotStatementStatementSqliMatchStatementFieldToMatchUriPath? uriPath)
        {
            AllQueryArguments = allQueryArguments;
            Body = body;
            Method = method;
            QueryString = queryString;
            SingleHeader = singleHeader;
            SingleQueryArgument = singleQueryArgument;
            UriPath = uriPath;
        }
    }
}