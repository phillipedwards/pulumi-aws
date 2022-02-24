// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * Provides a subnet CIDR reservation resource.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as aws from "@pulumi/aws";
 *
 * const example = new aws.ec2.SubnetCidrReservation("example", {
 *     cidrBlock: "10.0.0.16/28",
 *     reservationType: "prefix",
 *     subnetId: aws_subnet.example.id,
 * });
 * ```
 *
 * ## Import
 *
 * Existing CIDR reservations can be imported using `SUBNET_ID:RESERVATION_ID`, e.g.,
 *
 * ```sh
 *  $ pulumi import aws:ec2/subnetCidrReservation:SubnetCidrReservation example subnet-01llsxvsxabqiymcz:scr-4mnvz6wb7otksjcs9
 * ```
 */
export class SubnetCidrReservation extends pulumi.CustomResource {
    /**
     * Get an existing SubnetCidrReservation resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: SubnetCidrReservationState, opts?: pulumi.CustomResourceOptions): SubnetCidrReservation {
        return new SubnetCidrReservation(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'aws:ec2/subnetCidrReservation:SubnetCidrReservation';

    /**
     * Returns true if the given object is an instance of SubnetCidrReservation.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is SubnetCidrReservation {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === SubnetCidrReservation.__pulumiType;
    }

    /**
     * The CIDR block for the reservation.
     */
    public readonly cidrBlock!: pulumi.Output<string>;
    /**
     * A brief description of the reservation.
     */
    public readonly description!: pulumi.Output<string | undefined>;
    /**
     * ID of the AWS account that owns this CIDR reservation.
     */
    public /*out*/ readonly ownerId!: pulumi.Output<string>;
    /**
     * The type of reservation to create. Valid values: `explicit`, `prefix`
     */
    public readonly reservationType!: pulumi.Output<string>;
    /**
     * The ID of the subnet to create the reservation for.
     */
    public readonly subnetId!: pulumi.Output<string>;

    /**
     * Create a SubnetCidrReservation resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: SubnetCidrReservationArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: SubnetCidrReservationArgs | SubnetCidrReservationState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as SubnetCidrReservationState | undefined;
            resourceInputs["cidrBlock"] = state ? state.cidrBlock : undefined;
            resourceInputs["description"] = state ? state.description : undefined;
            resourceInputs["ownerId"] = state ? state.ownerId : undefined;
            resourceInputs["reservationType"] = state ? state.reservationType : undefined;
            resourceInputs["subnetId"] = state ? state.subnetId : undefined;
        } else {
            const args = argsOrState as SubnetCidrReservationArgs | undefined;
            if ((!args || args.cidrBlock === undefined) && !opts.urn) {
                throw new Error("Missing required property 'cidrBlock'");
            }
            if ((!args || args.reservationType === undefined) && !opts.urn) {
                throw new Error("Missing required property 'reservationType'");
            }
            if ((!args || args.subnetId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'subnetId'");
            }
            resourceInputs["cidrBlock"] = args ? args.cidrBlock : undefined;
            resourceInputs["description"] = args ? args.description : undefined;
            resourceInputs["reservationType"] = args ? args.reservationType : undefined;
            resourceInputs["subnetId"] = args ? args.subnetId : undefined;
            resourceInputs["ownerId"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(SubnetCidrReservation.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering SubnetCidrReservation resources.
 */
export interface SubnetCidrReservationState {
    /**
     * The CIDR block for the reservation.
     */
    cidrBlock?: pulumi.Input<string>;
    /**
     * A brief description of the reservation.
     */
    description?: pulumi.Input<string>;
    /**
     * ID of the AWS account that owns this CIDR reservation.
     */
    ownerId?: pulumi.Input<string>;
    /**
     * The type of reservation to create. Valid values: `explicit`, `prefix`
     */
    reservationType?: pulumi.Input<string>;
    /**
     * The ID of the subnet to create the reservation for.
     */
    subnetId?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a SubnetCidrReservation resource.
 */
export interface SubnetCidrReservationArgs {
    /**
     * The CIDR block for the reservation.
     */
    cidrBlock: pulumi.Input<string>;
    /**
     * A brief description of the reservation.
     */
    description?: pulumi.Input<string>;
    /**
     * The type of reservation to create. Valid values: `explicit`, `prefix`
     */
    reservationType: pulumi.Input<string>;
    /**
     * The ID of the subnet to create the reservation for.
     */
    subnetId: pulumi.Input<string>;
}