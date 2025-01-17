// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.aws.identitystore.inputs;

import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetGroupFilter extends com.pulumi.resources.InvokeArgs {

    public static final GetGroupFilter Empty = new GetGroupFilter();

    /**
     * Attribute path that is used to specify which attribute name to search. Currently, `DisplayName` is the only valid attribute path.
     * 
     */
    @Import(name="attributePath", required=true)
    private String attributePath;

    /**
     * @return Attribute path that is used to specify which attribute name to search. Currently, `DisplayName` is the only valid attribute path.
     * 
     */
    public String attributePath() {
        return this.attributePath;
    }

    /**
     * Value for an attribute.
     * 
     */
    @Import(name="attributeValue", required=true)
    private String attributeValue;

    /**
     * @return Value for an attribute.
     * 
     */
    public String attributeValue() {
        return this.attributeValue;
    }

    private GetGroupFilter() {}

    private GetGroupFilter(GetGroupFilter $) {
        this.attributePath = $.attributePath;
        this.attributeValue = $.attributeValue;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetGroupFilter defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetGroupFilter $;

        public Builder() {
            $ = new GetGroupFilter();
        }

        public Builder(GetGroupFilter defaults) {
            $ = new GetGroupFilter(Objects.requireNonNull(defaults));
        }

        /**
         * @param attributePath Attribute path that is used to specify which attribute name to search. Currently, `DisplayName` is the only valid attribute path.
         * 
         * @return builder
         * 
         */
        public Builder attributePath(String attributePath) {
            $.attributePath = attributePath;
            return this;
        }

        /**
         * @param attributeValue Value for an attribute.
         * 
         * @return builder
         * 
         */
        public Builder attributeValue(String attributeValue) {
            $.attributeValue = attributeValue;
            return this;
        }

        public GetGroupFilter build() {
            $.attributePath = Objects.requireNonNull($.attributePath, "expected parameter 'attributePath' to be non-null");
            $.attributeValue = Objects.requireNonNull($.attributeValue, "expected parameter 'attributeValue' to be non-null");
            return $;
        }
    }

}
