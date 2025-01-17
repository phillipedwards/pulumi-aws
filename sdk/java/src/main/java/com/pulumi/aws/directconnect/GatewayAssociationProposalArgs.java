// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.aws.directconnect;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GatewayAssociationProposalArgs extends com.pulumi.resources.ResourceArgs {

    public static final GatewayAssociationProposalArgs Empty = new GatewayAssociationProposalArgs();

    /**
     * VPC prefixes (CIDRs) to advertise to the Direct Connect gateway. Defaults to the CIDR block of the VPC associated with the Virtual Gateway. To enable drift detection, must be configured.
     * 
     */
    @Import(name="allowedPrefixes")
    private @Nullable Output<List<String>> allowedPrefixes;

    /**
     * @return VPC prefixes (CIDRs) to advertise to the Direct Connect gateway. Defaults to the CIDR block of the VPC associated with the Virtual Gateway. To enable drift detection, must be configured.
     * 
     */
    public Optional<Output<List<String>>> allowedPrefixes() {
        return Optional.ofNullable(this.allowedPrefixes);
    }

    /**
     * The ID of the VGW or transit gateway with which to associate the Direct Connect gateway.
     * 
     */
    @Import(name="associatedGatewayId", required=true)
    private Output<String> associatedGatewayId;

    /**
     * @return The ID of the VGW or transit gateway with which to associate the Direct Connect gateway.
     * 
     */
    public Output<String> associatedGatewayId() {
        return this.associatedGatewayId;
    }

    /**
     * Direct Connect Gateway identifier.
     * 
     */
    @Import(name="dxGatewayId", required=true)
    private Output<String> dxGatewayId;

    /**
     * @return Direct Connect Gateway identifier.
     * 
     */
    public Output<String> dxGatewayId() {
        return this.dxGatewayId;
    }

    /**
     * AWS Account identifier of the Direct Connect Gateway&#39;s owner.
     * 
     */
    @Import(name="dxGatewayOwnerAccountId", required=true)
    private Output<String> dxGatewayOwnerAccountId;

    /**
     * @return AWS Account identifier of the Direct Connect Gateway&#39;s owner.
     * 
     */
    public Output<String> dxGatewayOwnerAccountId() {
        return this.dxGatewayOwnerAccountId;
    }

    private GatewayAssociationProposalArgs() {}

    private GatewayAssociationProposalArgs(GatewayAssociationProposalArgs $) {
        this.allowedPrefixes = $.allowedPrefixes;
        this.associatedGatewayId = $.associatedGatewayId;
        this.dxGatewayId = $.dxGatewayId;
        this.dxGatewayOwnerAccountId = $.dxGatewayOwnerAccountId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GatewayAssociationProposalArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GatewayAssociationProposalArgs $;

        public Builder() {
            $ = new GatewayAssociationProposalArgs();
        }

        public Builder(GatewayAssociationProposalArgs defaults) {
            $ = new GatewayAssociationProposalArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param allowedPrefixes VPC prefixes (CIDRs) to advertise to the Direct Connect gateway. Defaults to the CIDR block of the VPC associated with the Virtual Gateway. To enable drift detection, must be configured.
         * 
         * @return builder
         * 
         */
        public Builder allowedPrefixes(@Nullable Output<List<String>> allowedPrefixes) {
            $.allowedPrefixes = allowedPrefixes;
            return this;
        }

        /**
         * @param allowedPrefixes VPC prefixes (CIDRs) to advertise to the Direct Connect gateway. Defaults to the CIDR block of the VPC associated with the Virtual Gateway. To enable drift detection, must be configured.
         * 
         * @return builder
         * 
         */
        public Builder allowedPrefixes(List<String> allowedPrefixes) {
            return allowedPrefixes(Output.of(allowedPrefixes));
        }

        /**
         * @param allowedPrefixes VPC prefixes (CIDRs) to advertise to the Direct Connect gateway. Defaults to the CIDR block of the VPC associated with the Virtual Gateway. To enable drift detection, must be configured.
         * 
         * @return builder
         * 
         */
        public Builder allowedPrefixes(String... allowedPrefixes) {
            return allowedPrefixes(List.of(allowedPrefixes));
        }

        /**
         * @param associatedGatewayId The ID of the VGW or transit gateway with which to associate the Direct Connect gateway.
         * 
         * @return builder
         * 
         */
        public Builder associatedGatewayId(Output<String> associatedGatewayId) {
            $.associatedGatewayId = associatedGatewayId;
            return this;
        }

        /**
         * @param associatedGatewayId The ID of the VGW or transit gateway with which to associate the Direct Connect gateway.
         * 
         * @return builder
         * 
         */
        public Builder associatedGatewayId(String associatedGatewayId) {
            return associatedGatewayId(Output.of(associatedGatewayId));
        }

        /**
         * @param dxGatewayId Direct Connect Gateway identifier.
         * 
         * @return builder
         * 
         */
        public Builder dxGatewayId(Output<String> dxGatewayId) {
            $.dxGatewayId = dxGatewayId;
            return this;
        }

        /**
         * @param dxGatewayId Direct Connect Gateway identifier.
         * 
         * @return builder
         * 
         */
        public Builder dxGatewayId(String dxGatewayId) {
            return dxGatewayId(Output.of(dxGatewayId));
        }

        /**
         * @param dxGatewayOwnerAccountId AWS Account identifier of the Direct Connect Gateway&#39;s owner.
         * 
         * @return builder
         * 
         */
        public Builder dxGatewayOwnerAccountId(Output<String> dxGatewayOwnerAccountId) {
            $.dxGatewayOwnerAccountId = dxGatewayOwnerAccountId;
            return this;
        }

        /**
         * @param dxGatewayOwnerAccountId AWS Account identifier of the Direct Connect Gateway&#39;s owner.
         * 
         * @return builder
         * 
         */
        public Builder dxGatewayOwnerAccountId(String dxGatewayOwnerAccountId) {
            return dxGatewayOwnerAccountId(Output.of(dxGatewayOwnerAccountId));
        }

        public GatewayAssociationProposalArgs build() {
            $.associatedGatewayId = Objects.requireNonNull($.associatedGatewayId, "expected parameter 'associatedGatewayId' to be non-null");
            $.dxGatewayId = Objects.requireNonNull($.dxGatewayId, "expected parameter 'dxGatewayId' to be non-null");
            $.dxGatewayOwnerAccountId = Objects.requireNonNull($.dxGatewayOwnerAccountId, "expected parameter 'dxGatewayOwnerAccountId' to be non-null");
            return $;
        }
    }

}
