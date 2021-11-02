// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Aws.Sagemaker.Inputs
{

    public sealed class FlowDefinitionHumanLoopActivationConfigGetArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// defines under what conditions SageMaker creates a human loop. See Human Loop Activation Conditions Config details below.
        /// </summary>
        [Input("humanLoopActivationConditionsConfig")]
        public Input<Inputs.FlowDefinitionHumanLoopActivationConfigHumanLoopActivationConditionsConfigGetArgs>? HumanLoopActivationConditionsConfig { get; set; }

        public FlowDefinitionHumanLoopActivationConfigGetArgs()
        {
        }
    }
}