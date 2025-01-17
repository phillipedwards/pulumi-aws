// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.aws.s3.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class BucketLoggingV2TargetGrantGranteeArgs extends com.pulumi.resources.ResourceArgs {

    public static final BucketLoggingV2TargetGrantGranteeArgs Empty = new BucketLoggingV2TargetGrantGranteeArgs();

    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * Email address of the grantee. See [Regions and Endpoints](https://docs.aws.amazon.com/general/latest/gr/rande.html#s3_region) for supported AWS regions where this argument can be specified.
     * 
     */
    @Import(name="emailAddress")
    private @Nullable Output<String> emailAddress;

    /**
     * @return Email address of the grantee. See [Regions and Endpoints](https://docs.aws.amazon.com/general/latest/gr/rande.html#s3_region) for supported AWS regions where this argument can be specified.
     * 
     */
    public Optional<Output<String>> emailAddress() {
        return Optional.ofNullable(this.emailAddress);
    }

    /**
     * The canonical user ID of the grantee.
     * 
     */
    @Import(name="id")
    private @Nullable Output<String> id;

    /**
     * @return The canonical user ID of the grantee.
     * 
     */
    public Optional<Output<String>> id() {
        return Optional.ofNullable(this.id);
    }

    /**
     * Type of grantee. Valid values: `CanonicalUser`, `AmazonCustomerByEmail`, `Group`.
     * 
     */
    @Import(name="type", required=true)
    private Output<String> type;

    /**
     * @return Type of grantee. Valid values: `CanonicalUser`, `AmazonCustomerByEmail`, `Group`.
     * 
     */
    public Output<String> type() {
        return this.type;
    }

    /**
     * URI of the grantee group.
     * 
     */
    @Import(name="uri")
    private @Nullable Output<String> uri;

    /**
     * @return URI of the grantee group.
     * 
     */
    public Optional<Output<String>> uri() {
        return Optional.ofNullable(this.uri);
    }

    private BucketLoggingV2TargetGrantGranteeArgs() {}

    private BucketLoggingV2TargetGrantGranteeArgs(BucketLoggingV2TargetGrantGranteeArgs $) {
        this.displayName = $.displayName;
        this.emailAddress = $.emailAddress;
        this.id = $.id;
        this.type = $.type;
        this.uri = $.uri;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(BucketLoggingV2TargetGrantGranteeArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private BucketLoggingV2TargetGrantGranteeArgs $;

        public Builder() {
            $ = new BucketLoggingV2TargetGrantGranteeArgs();
        }

        public Builder(BucketLoggingV2TargetGrantGranteeArgs defaults) {
            $ = new BucketLoggingV2TargetGrantGranteeArgs(Objects.requireNonNull(defaults));
        }

        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param emailAddress Email address of the grantee. See [Regions and Endpoints](https://docs.aws.amazon.com/general/latest/gr/rande.html#s3_region) for supported AWS regions where this argument can be specified.
         * 
         * @return builder
         * 
         */
        public Builder emailAddress(@Nullable Output<String> emailAddress) {
            $.emailAddress = emailAddress;
            return this;
        }

        /**
         * @param emailAddress Email address of the grantee. See [Regions and Endpoints](https://docs.aws.amazon.com/general/latest/gr/rande.html#s3_region) for supported AWS regions where this argument can be specified.
         * 
         * @return builder
         * 
         */
        public Builder emailAddress(String emailAddress) {
            return emailAddress(Output.of(emailAddress));
        }

        /**
         * @param id The canonical user ID of the grantee.
         * 
         * @return builder
         * 
         */
        public Builder id(@Nullable Output<String> id) {
            $.id = id;
            return this;
        }

        /**
         * @param id The canonical user ID of the grantee.
         * 
         * @return builder
         * 
         */
        public Builder id(String id) {
            return id(Output.of(id));
        }

        /**
         * @param type Type of grantee. Valid values: `CanonicalUser`, `AmazonCustomerByEmail`, `Group`.
         * 
         * @return builder
         * 
         */
        public Builder type(Output<String> type) {
            $.type = type;
            return this;
        }

        /**
         * @param type Type of grantee. Valid values: `CanonicalUser`, `AmazonCustomerByEmail`, `Group`.
         * 
         * @return builder
         * 
         */
        public Builder type(String type) {
            return type(Output.of(type));
        }

        /**
         * @param uri URI of the grantee group.
         * 
         * @return builder
         * 
         */
        public Builder uri(@Nullable Output<String> uri) {
            $.uri = uri;
            return this;
        }

        /**
         * @param uri URI of the grantee group.
         * 
         * @return builder
         * 
         */
        public Builder uri(String uri) {
            return uri(Output.of(uri));
        }

        public BucketLoggingV2TargetGrantGranteeArgs build() {
            $.type = Objects.requireNonNull($.type, "expected parameter 'type' to be non-null");
            return $;
        }
    }

}
