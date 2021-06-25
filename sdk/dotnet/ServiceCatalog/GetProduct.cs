// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Aws.ServiceCatalog
{
    public static class GetProduct
    {
        /// <summary>
        /// Provides information on a Service Catalog Product.
        /// 
        /// &gt; **Tip:** A "provisioning artifact" is also referred to as a "version." A "distributor" is also referred to as a "vendor."
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// ### Basic Usage
        /// 
        /// ```csharp
        /// using Pulumi;
        /// using Aws = Pulumi.Aws;
        /// 
        /// class MyStack : Stack
        /// {
        ///     public MyStack()
        ///     {
        ///         var example = Output.Create(Aws.ServiceCatalog.GetProduct.InvokeAsync(new Aws.ServiceCatalog.GetProductArgs
        ///         {
        ///             Id = "prod-dnigbtea24ste",
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetProductResult> InvokeAsync(GetProductArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetProductResult>("aws:servicecatalog/getProduct:getProduct", args ?? new GetProductArgs(), options.WithVersion());
    }


    public sealed class GetProductArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// Language code. Valid values: `en` (English), `jp` (Japanese), `zh` (Chinese). Default value is `en`.
        /// </summary>
        [Input("acceptLanguage")]
        public string? AcceptLanguage { get; set; }

        /// <summary>
        /// Product ID.
        /// </summary>
        [Input("id", required: true)]
        public string Id { get; set; } = null!;

        [Input("tags")]
        private Dictionary<string, string>? _tags;

        /// <summary>
        /// Tags to apply to the product.
        /// </summary>
        public Dictionary<string, string> Tags
        {
            get => _tags ?? (_tags = new Dictionary<string, string>());
            set => _tags = value;
        }

        public GetProductArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetProductResult
    {
        public readonly string? AcceptLanguage;
        /// <summary>
        /// ARN of the product.
        /// </summary>
        public readonly string Arn;
        /// <summary>
        /// Time when the product was created.
        /// </summary>
        public readonly string CreatedTime;
        /// <summary>
        /// Description of the product.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// Distributor (i.e., vendor) of the product.
        /// </summary>
        public readonly string Distributor;
        /// <summary>
        /// Whether the product has a default path.
        /// </summary>
        public readonly bool HasDefaultPath;
        public readonly string Id;
        /// <summary>
        /// Name of the product.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// Owner of the product.
        /// </summary>
        public readonly string Owner;
        /// <summary>
        /// Status of the product.
        /// </summary>
        public readonly string Status;
        /// <summary>
        /// Support information about the product.
        /// </summary>
        public readonly string SupportDescription;
        /// <summary>
        /// Contact email for product support.
        /// </summary>
        public readonly string SupportEmail;
        /// <summary>
        /// Contact URL for product support.
        /// </summary>
        public readonly string SupportUrl;
        /// <summary>
        /// Tags to apply to the product.
        /// </summary>
        public readonly ImmutableDictionary<string, string> Tags;
        /// <summary>
        /// Type of product.
        /// </summary>
        public readonly string Type;

        [OutputConstructor]
        private GetProductResult(
            string? acceptLanguage,

            string arn,

            string createdTime,

            string description,

            string distributor,

            bool hasDefaultPath,

            string id,

            string name,

            string owner,

            string status,

            string supportDescription,

            string supportEmail,

            string supportUrl,

            ImmutableDictionary<string, string> tags,

            string type)
        {
            AcceptLanguage = acceptLanguage;
            Arn = arn;
            CreatedTime = createdTime;
            Description = description;
            Distributor = distributor;
            HasDefaultPath = hasDefaultPath;
            Id = id;
            Name = name;
            Owner = owner;
            Status = status;
            SupportDescription = supportDescription;
            SupportEmail = supportEmail;
            SupportUrl = supportUrl;
            Tags = tags;
            Type = type;
        }
    }
}