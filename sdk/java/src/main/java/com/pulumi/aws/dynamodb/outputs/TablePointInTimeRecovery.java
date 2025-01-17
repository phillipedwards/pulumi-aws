// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.aws.dynamodb.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.util.Objects;

@CustomType
public final class TablePointInTimeRecovery {
    /**
     * @return Whether TTL is enabled.
     * 
     */
    private Boolean enabled;

    private TablePointInTimeRecovery() {}
    /**
     * @return Whether TTL is enabled.
     * 
     */
    public Boolean enabled() {
        return this.enabled;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(TablePointInTimeRecovery defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Boolean enabled;
        public Builder() {}
        public Builder(TablePointInTimeRecovery defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.enabled = defaults.enabled;
        }

        @CustomType.Setter
        public Builder enabled(Boolean enabled) {
            this.enabled = Objects.requireNonNull(enabled);
            return this;
        }
        public TablePointInTimeRecovery build() {
            final var o = new TablePointInTimeRecovery();
            o.enabled = enabled;
            return o;
        }
    }
}
