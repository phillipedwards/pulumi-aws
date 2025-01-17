// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.aws.ses.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ConfgurationSetTrackingOptionsArgs extends com.pulumi.resources.ResourceArgs {

    public static final ConfgurationSetTrackingOptionsArgs Empty = new ConfgurationSetTrackingOptionsArgs();

    /**
     * Custom subdomain that is used to redirect email recipients to the Amazon SES event tracking domain.
     * 
     */
    @Import(name="customRedirectDomain")
    private @Nullable Output<String> customRedirectDomain;

    /**
     * @return Custom subdomain that is used to redirect email recipients to the Amazon SES event tracking domain.
     * 
     */
    public Optional<Output<String>> customRedirectDomain() {
        return Optional.ofNullable(this.customRedirectDomain);
    }

    private ConfgurationSetTrackingOptionsArgs() {}

    private ConfgurationSetTrackingOptionsArgs(ConfgurationSetTrackingOptionsArgs $) {
        this.customRedirectDomain = $.customRedirectDomain;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ConfgurationSetTrackingOptionsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ConfgurationSetTrackingOptionsArgs $;

        public Builder() {
            $ = new ConfgurationSetTrackingOptionsArgs();
        }

        public Builder(ConfgurationSetTrackingOptionsArgs defaults) {
            $ = new ConfgurationSetTrackingOptionsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param customRedirectDomain Custom subdomain that is used to redirect email recipients to the Amazon SES event tracking domain.
         * 
         * @return builder
         * 
         */
        public Builder customRedirectDomain(@Nullable Output<String> customRedirectDomain) {
            $.customRedirectDomain = customRedirectDomain;
            return this;
        }

        /**
         * @param customRedirectDomain Custom subdomain that is used to redirect email recipients to the Amazon SES event tracking domain.
         * 
         * @return builder
         * 
         */
        public Builder customRedirectDomain(String customRedirectDomain) {
            return customRedirectDomain(Output.of(customRedirectDomain));
        }

        public ConfgurationSetTrackingOptionsArgs build() {
            return $;
        }
    }

}
