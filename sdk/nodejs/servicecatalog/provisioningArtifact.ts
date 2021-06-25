// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * Manages a Service Catalog Provisioning Artifact for a specified product.
 *
 * > A "provisioning artifact" is also referred to as a "version."
 *
 * > **NOTE:** You cannot create a provisioning artifact for a product that was shared with you.
 *
 * > **NOTE:** The user or role that use this resource must have the `cloudformation:GetTemplate` IAM policy permission. This policy permission is required when using the `templatePhysicalId` argument.
 *
 * ## Example Usage
 * ### Basic Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as aws from "@pulumi/aws";
 *
 * const example = new aws.servicecatalog.ProvisioningArtifact("example", {
 *     productId: aws_servicecatalog_product.example.id,
 *     type: "CLOUD_FORMATION_TEMPLATE",
 *     templateUrl: `https://${aws_s3_bucket.example.bucket_regional_domain_name}/${aws_s3_bucket_object.example.key}`,
 * });
 * ```
 *
 * ## Import
 *
 * `aws_servicecatalog_provisioning_artifact` can be imported using the provisioning artifact ID and product ID separated by a colon, e.g.
 *
 * ```sh
 *  $ pulumi import aws:servicecatalog/provisioningArtifact:ProvisioningArtifact example pa-ij2b6lusy6dec:prod-el3an0rma3
 * ```
 */
export class ProvisioningArtifact extends pulumi.CustomResource {
    /**
     * Get an existing ProvisioningArtifact resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: ProvisioningArtifactState, opts?: pulumi.CustomResourceOptions): ProvisioningArtifact {
        return new ProvisioningArtifact(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'aws:servicecatalog/provisioningArtifact:ProvisioningArtifact';

    /**
     * Returns true if the given object is an instance of ProvisioningArtifact.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is ProvisioningArtifact {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === ProvisioningArtifact.__pulumiType;
    }

    /**
     * Language code. Valid values: `en` (English), `jp` (Japanese), `zh` (Chinese). The default value is `en`.
     */
    public readonly acceptLanguage!: pulumi.Output<string | undefined>;
    /**
     * Whether the product version is active. Inactive provisioning artifacts are invisible to end users. End users cannot launch or update a provisioned product from an inactive provisioning artifact. Default is `true`.
     */
    public readonly active!: pulumi.Output<boolean | undefined>;
    /**
     * Time when the provisioning artifact was created.
     */
    public /*out*/ readonly createdTime!: pulumi.Output<string>;
    /**
     * Description of the provisioning artifact (i.e., version), including how it differs from the previous provisioning artifact.
     */
    public readonly description!: pulumi.Output<string>;
    /**
     * Whether AWS Service Catalog stops validating the specified provisioning artifact template even if it is invalid.
     */
    public readonly disableTemplateValidation!: pulumi.Output<boolean | undefined>;
    /**
     * Information set by the administrator to provide guidance to end users about which provisioning artifacts to use. Valid values are `DEFAULT` and `DEPRECATED`. The default is `DEFAULT`. Users are able to make updates to a provisioned product of a deprecated version but cannot launch new provisioned products using a deprecated version.
     */
    public readonly guidance!: pulumi.Output<string | undefined>;
    /**
     * Name of the provisioning artifact (for example, `v1`, `v2beta`). No spaces are allowed.
     */
    public readonly name!: pulumi.Output<string>;
    /**
     * Identifier of the product.
     */
    public readonly productId!: pulumi.Output<string>;
    /**
     * Template source as the physical ID of the resource that contains the template. Currently only supports CloudFormation stack ARN. Specify the physical ID as `arn:[partition]:cloudformation:[region]:[account ID]:stack/[stack name]/[resource ID]`.
     */
    public readonly templatePhysicalId!: pulumi.Output<string | undefined>;
    /**
     * Template source as URL of the CloudFormation template in Amazon S3.
     */
    public readonly templateUrl!: pulumi.Output<string | undefined>;
    /**
     * Type of provisioning artifact. Valid values: `CLOUD_FORMATION_TEMPLATE`, `MARKETPLACE_AMI`, `MARKETPLACE_CAR` (Marketplace Clusters and AWS Resources).
     */
    public readonly type!: pulumi.Output<string | undefined>;

    /**
     * Create a ProvisioningArtifact resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: ProvisioningArtifactArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: ProvisioningArtifactArgs | ProvisioningArtifactState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as ProvisioningArtifactState | undefined;
            inputs["acceptLanguage"] = state ? state.acceptLanguage : undefined;
            inputs["active"] = state ? state.active : undefined;
            inputs["createdTime"] = state ? state.createdTime : undefined;
            inputs["description"] = state ? state.description : undefined;
            inputs["disableTemplateValidation"] = state ? state.disableTemplateValidation : undefined;
            inputs["guidance"] = state ? state.guidance : undefined;
            inputs["name"] = state ? state.name : undefined;
            inputs["productId"] = state ? state.productId : undefined;
            inputs["templatePhysicalId"] = state ? state.templatePhysicalId : undefined;
            inputs["templateUrl"] = state ? state.templateUrl : undefined;
            inputs["type"] = state ? state.type : undefined;
        } else {
            const args = argsOrState as ProvisioningArtifactArgs | undefined;
            if ((!args || args.productId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'productId'");
            }
            inputs["acceptLanguage"] = args ? args.acceptLanguage : undefined;
            inputs["active"] = args ? args.active : undefined;
            inputs["description"] = args ? args.description : undefined;
            inputs["disableTemplateValidation"] = args ? args.disableTemplateValidation : undefined;
            inputs["guidance"] = args ? args.guidance : undefined;
            inputs["name"] = args ? args.name : undefined;
            inputs["productId"] = args ? args.productId : undefined;
            inputs["templatePhysicalId"] = args ? args.templatePhysicalId : undefined;
            inputs["templateUrl"] = args ? args.templateUrl : undefined;
            inputs["type"] = args ? args.type : undefined;
            inputs["createdTime"] = undefined /*out*/;
        }
        if (!opts.version) {
            opts = pulumi.mergeOptions(opts, { version: utilities.getVersion()});
        }
        super(ProvisioningArtifact.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering ProvisioningArtifact resources.
 */
export interface ProvisioningArtifactState {
    /**
     * Language code. Valid values: `en` (English), `jp` (Japanese), `zh` (Chinese). The default value is `en`.
     */
    acceptLanguage?: pulumi.Input<string>;
    /**
     * Whether the product version is active. Inactive provisioning artifacts are invisible to end users. End users cannot launch or update a provisioned product from an inactive provisioning artifact. Default is `true`.
     */
    active?: pulumi.Input<boolean>;
    /**
     * Time when the provisioning artifact was created.
     */
    createdTime?: pulumi.Input<string>;
    /**
     * Description of the provisioning artifact (i.e., version), including how it differs from the previous provisioning artifact.
     */
    description?: pulumi.Input<string>;
    /**
     * Whether AWS Service Catalog stops validating the specified provisioning artifact template even if it is invalid.
     */
    disableTemplateValidation?: pulumi.Input<boolean>;
    /**
     * Information set by the administrator to provide guidance to end users about which provisioning artifacts to use. Valid values are `DEFAULT` and `DEPRECATED`. The default is `DEFAULT`. Users are able to make updates to a provisioned product of a deprecated version but cannot launch new provisioned products using a deprecated version.
     */
    guidance?: pulumi.Input<string>;
    /**
     * Name of the provisioning artifact (for example, `v1`, `v2beta`). No spaces are allowed.
     */
    name?: pulumi.Input<string>;
    /**
     * Identifier of the product.
     */
    productId?: pulumi.Input<string>;
    /**
     * Template source as the physical ID of the resource that contains the template. Currently only supports CloudFormation stack ARN. Specify the physical ID as `arn:[partition]:cloudformation:[region]:[account ID]:stack/[stack name]/[resource ID]`.
     */
    templatePhysicalId?: pulumi.Input<string>;
    /**
     * Template source as URL of the CloudFormation template in Amazon S3.
     */
    templateUrl?: pulumi.Input<string>;
    /**
     * Type of provisioning artifact. Valid values: `CLOUD_FORMATION_TEMPLATE`, `MARKETPLACE_AMI`, `MARKETPLACE_CAR` (Marketplace Clusters and AWS Resources).
     */
    type?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a ProvisioningArtifact resource.
 */
export interface ProvisioningArtifactArgs {
    /**
     * Language code. Valid values: `en` (English), `jp` (Japanese), `zh` (Chinese). The default value is `en`.
     */
    acceptLanguage?: pulumi.Input<string>;
    /**
     * Whether the product version is active. Inactive provisioning artifacts are invisible to end users. End users cannot launch or update a provisioned product from an inactive provisioning artifact. Default is `true`.
     */
    active?: pulumi.Input<boolean>;
    /**
     * Description of the provisioning artifact (i.e., version), including how it differs from the previous provisioning artifact.
     */
    description?: pulumi.Input<string>;
    /**
     * Whether AWS Service Catalog stops validating the specified provisioning artifact template even if it is invalid.
     */
    disableTemplateValidation?: pulumi.Input<boolean>;
    /**
     * Information set by the administrator to provide guidance to end users about which provisioning artifacts to use. Valid values are `DEFAULT` and `DEPRECATED`. The default is `DEFAULT`. Users are able to make updates to a provisioned product of a deprecated version but cannot launch new provisioned products using a deprecated version.
     */
    guidance?: pulumi.Input<string>;
    /**
     * Name of the provisioning artifact (for example, `v1`, `v2beta`). No spaces are allowed.
     */
    name?: pulumi.Input<string>;
    /**
     * Identifier of the product.
     */
    productId: pulumi.Input<string>;
    /**
     * Template source as the physical ID of the resource that contains the template. Currently only supports CloudFormation stack ARN. Specify the physical ID as `arn:[partition]:cloudformation:[region]:[account ID]:stack/[stack name]/[resource ID]`.
     */
    templatePhysicalId?: pulumi.Input<string>;
    /**
     * Template source as URL of the CloudFormation template in Amazon S3.
     */
    templateUrl?: pulumi.Input<string>;
    /**
     * Type of provisioning artifact. Valid values: `CLOUD_FORMATION_TEMPLATE`, `MARKETPLACE_AMI`, `MARKETPLACE_CAR` (Marketplace Clusters and AWS Resources).
     */
    type?: pulumi.Input<string>;
}