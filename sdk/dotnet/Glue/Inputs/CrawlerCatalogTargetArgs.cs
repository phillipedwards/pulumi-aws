// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Aws.Glue.Inputs
{

    public sealed class CrawlerCatalogTargetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The name of the Glue database to be synchronized.
        /// </summary>
        [Input("databaseName", required: true)]
        public Input<string> DatabaseName { get; set; } = null!;

        [Input("tables", required: true)]
        private InputList<string>? _tables;

        /// <summary>
        /// A list of catalog tables to be synchronized.
        /// </summary>
        public InputList<string> Tables
        {
            get => _tables ?? (_tables = new InputList<string>());
            set => _tables = value;
        }

        public CrawlerCatalogTargetArgs()
        {
        }
        public static new CrawlerCatalogTargetArgs Empty => new CrawlerCatalogTargetArgs();
    }
}
