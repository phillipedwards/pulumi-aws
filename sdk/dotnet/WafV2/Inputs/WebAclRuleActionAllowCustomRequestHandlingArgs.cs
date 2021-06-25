// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Aws.WafV2.Inputs
{

    public sealed class WebAclRuleActionAllowCustomRequestHandlingArgs : Pulumi.ResourceArgs
    {
        [Input("insertHeaders", required: true)]
        private InputList<Inputs.WebAclRuleActionAllowCustomRequestHandlingInsertHeaderArgs>? _insertHeaders;

        /// <summary>
        /// The `insert_header` blocks used to define HTTP headers added to the request. See Custom HTTP Header below for details.
        /// </summary>
        public InputList<Inputs.WebAclRuleActionAllowCustomRequestHandlingInsertHeaderArgs> InsertHeaders
        {
            get => _insertHeaders ?? (_insertHeaders = new InputList<Inputs.WebAclRuleActionAllowCustomRequestHandlingInsertHeaderArgs>());
            set => _insertHeaders = value;
        }

        public WebAclRuleActionAllowCustomRequestHandlingArgs()
        {
        }
    }
}