// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.aws.servicecatalog;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class PortfolioShareArgs extends com.pulumi.resources.ResourceArgs {

    public static final PortfolioShareArgs Empty = new PortfolioShareArgs();

    /**
     * Language code. Valid values: `en` (English), `jp` (Japanese), `zh` (Chinese). Default value is `en`.
     * 
     */
    @Import(name="acceptLanguage")
    private @Nullable Output<String> acceptLanguage;

    /**
     * @return Language code. Valid values: `en` (English), `jp` (Japanese), `zh` (Chinese). Default value is `en`.
     * 
     */
    public Optional<Output<String>> acceptLanguage() {
        return Optional.ofNullable(this.acceptLanguage);
    }

    /**
     * Portfolio identifier.
     * 
     */
    @Import(name="portfolioId", required=true)
    private Output<String> portfolioId;

    /**
     * @return Portfolio identifier.
     * 
     */
    public Output<String> portfolioId() {
        return this.portfolioId;
    }

    /**
     * Identifier of the principal with whom you will share the portfolio. Valid values AWS account IDs and ARNs of AWS Organizations and organizational units.
     * 
     */
    @Import(name="principalId", required=true)
    private Output<String> principalId;

    /**
     * @return Identifier of the principal with whom you will share the portfolio. Valid values AWS account IDs and ARNs of AWS Organizations and organizational units.
     * 
     */
    public Output<String> principalId() {
        return this.principalId;
    }

    /**
     * Whether to enable sharing of `aws.servicecatalog.TagOption` resources when creating the portfolio share.
     * 
     */
    @Import(name="shareTagOptions")
    private @Nullable Output<Boolean> shareTagOptions;

    /**
     * @return Whether to enable sharing of `aws.servicecatalog.TagOption` resources when creating the portfolio share.
     * 
     */
    public Optional<Output<Boolean>> shareTagOptions() {
        return Optional.ofNullable(this.shareTagOptions);
    }

    /**
     * Type of portfolio share. Valid values are `ACCOUNT` (an external account), `ORGANIZATION` (a share to every account in an organization), `ORGANIZATIONAL_UNIT`, `ORGANIZATION_MEMBER_ACCOUNT` (a share to an account in an organization).
     * 
     */
    @Import(name="type", required=true)
    private Output<String> type;

    /**
     * @return Type of portfolio share. Valid values are `ACCOUNT` (an external account), `ORGANIZATION` (a share to every account in an organization), `ORGANIZATIONAL_UNIT`, `ORGANIZATION_MEMBER_ACCOUNT` (a share to an account in an organization).
     * 
     */
    public Output<String> type() {
        return this.type;
    }

    /**
     * Whether to wait (up to the timeout) for the share to be accepted. Organizational shares are automatically accepted.
     * 
     */
    @Import(name="waitForAcceptance")
    private @Nullable Output<Boolean> waitForAcceptance;

    /**
     * @return Whether to wait (up to the timeout) for the share to be accepted. Organizational shares are automatically accepted.
     * 
     */
    public Optional<Output<Boolean>> waitForAcceptance() {
        return Optional.ofNullable(this.waitForAcceptance);
    }

    private PortfolioShareArgs() {}

    private PortfolioShareArgs(PortfolioShareArgs $) {
        this.acceptLanguage = $.acceptLanguage;
        this.portfolioId = $.portfolioId;
        this.principalId = $.principalId;
        this.shareTagOptions = $.shareTagOptions;
        this.type = $.type;
        this.waitForAcceptance = $.waitForAcceptance;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(PortfolioShareArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private PortfolioShareArgs $;

        public Builder() {
            $ = new PortfolioShareArgs();
        }

        public Builder(PortfolioShareArgs defaults) {
            $ = new PortfolioShareArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param acceptLanguage Language code. Valid values: `en` (English), `jp` (Japanese), `zh` (Chinese). Default value is `en`.
         * 
         * @return builder
         * 
         */
        public Builder acceptLanguage(@Nullable Output<String> acceptLanguage) {
            $.acceptLanguage = acceptLanguage;
            return this;
        }

        /**
         * @param acceptLanguage Language code. Valid values: `en` (English), `jp` (Japanese), `zh` (Chinese). Default value is `en`.
         * 
         * @return builder
         * 
         */
        public Builder acceptLanguage(String acceptLanguage) {
            return acceptLanguage(Output.of(acceptLanguage));
        }

        /**
         * @param portfolioId Portfolio identifier.
         * 
         * @return builder
         * 
         */
        public Builder portfolioId(Output<String> portfolioId) {
            $.portfolioId = portfolioId;
            return this;
        }

        /**
         * @param portfolioId Portfolio identifier.
         * 
         * @return builder
         * 
         */
        public Builder portfolioId(String portfolioId) {
            return portfolioId(Output.of(portfolioId));
        }

        /**
         * @param principalId Identifier of the principal with whom you will share the portfolio. Valid values AWS account IDs and ARNs of AWS Organizations and organizational units.
         * 
         * @return builder
         * 
         */
        public Builder principalId(Output<String> principalId) {
            $.principalId = principalId;
            return this;
        }

        /**
         * @param principalId Identifier of the principal with whom you will share the portfolio. Valid values AWS account IDs and ARNs of AWS Organizations and organizational units.
         * 
         * @return builder
         * 
         */
        public Builder principalId(String principalId) {
            return principalId(Output.of(principalId));
        }

        /**
         * @param shareTagOptions Whether to enable sharing of `aws.servicecatalog.TagOption` resources when creating the portfolio share.
         * 
         * @return builder
         * 
         */
        public Builder shareTagOptions(@Nullable Output<Boolean> shareTagOptions) {
            $.shareTagOptions = shareTagOptions;
            return this;
        }

        /**
         * @param shareTagOptions Whether to enable sharing of `aws.servicecatalog.TagOption` resources when creating the portfolio share.
         * 
         * @return builder
         * 
         */
        public Builder shareTagOptions(Boolean shareTagOptions) {
            return shareTagOptions(Output.of(shareTagOptions));
        }

        /**
         * @param type Type of portfolio share. Valid values are `ACCOUNT` (an external account), `ORGANIZATION` (a share to every account in an organization), `ORGANIZATIONAL_UNIT`, `ORGANIZATION_MEMBER_ACCOUNT` (a share to an account in an organization).
         * 
         * @return builder
         * 
         */
        public Builder type(Output<String> type) {
            $.type = type;
            return this;
        }

        /**
         * @param type Type of portfolio share. Valid values are `ACCOUNT` (an external account), `ORGANIZATION` (a share to every account in an organization), `ORGANIZATIONAL_UNIT`, `ORGANIZATION_MEMBER_ACCOUNT` (a share to an account in an organization).
         * 
         * @return builder
         * 
         */
        public Builder type(String type) {
            return type(Output.of(type));
        }

        /**
         * @param waitForAcceptance Whether to wait (up to the timeout) for the share to be accepted. Organizational shares are automatically accepted.
         * 
         * @return builder
         * 
         */
        public Builder waitForAcceptance(@Nullable Output<Boolean> waitForAcceptance) {
            $.waitForAcceptance = waitForAcceptance;
            return this;
        }

        /**
         * @param waitForAcceptance Whether to wait (up to the timeout) for the share to be accepted. Organizational shares are automatically accepted.
         * 
         * @return builder
         * 
         */
        public Builder waitForAcceptance(Boolean waitForAcceptance) {
            return waitForAcceptance(Output.of(waitForAcceptance));
        }

        public PortfolioShareArgs build() {
            $.portfolioId = Objects.requireNonNull($.portfolioId, "expected parameter 'portfolioId' to be non-null");
            $.principalId = Objects.requireNonNull($.principalId, "expected parameter 'principalId' to be non-null");
            $.type = Objects.requireNonNull($.type, "expected parameter 'type' to be non-null");
            return $;
        }
    }

}
