// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.aws.wafv2.outputs;

import com.pulumi.aws.wafv2.outputs.WebAclRuleStatementManagedRuleGroupStatementScopeDownStatementNotStatementStatementNotStatementStatementByteMatchStatementFieldToMatchJsonBodyMatchPatternAll;
import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class WebAclRuleStatementManagedRuleGroupStatementScopeDownStatementNotStatementStatementNotStatementStatementByteMatchStatementFieldToMatchJsonBodyMatchPattern {
    private @Nullable WebAclRuleStatementManagedRuleGroupStatementScopeDownStatementNotStatementStatementNotStatementStatementByteMatchStatementFieldToMatchJsonBodyMatchPatternAll all;
    private @Nullable List<String> includedPaths;

    private WebAclRuleStatementManagedRuleGroupStatementScopeDownStatementNotStatementStatementNotStatementStatementByteMatchStatementFieldToMatchJsonBodyMatchPattern() {}
    public Optional<WebAclRuleStatementManagedRuleGroupStatementScopeDownStatementNotStatementStatementNotStatementStatementByteMatchStatementFieldToMatchJsonBodyMatchPatternAll> all() {
        return Optional.ofNullable(this.all);
    }
    public List<String> includedPaths() {
        return this.includedPaths == null ? List.of() : this.includedPaths;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(WebAclRuleStatementManagedRuleGroupStatementScopeDownStatementNotStatementStatementNotStatementStatementByteMatchStatementFieldToMatchJsonBodyMatchPattern defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable WebAclRuleStatementManagedRuleGroupStatementScopeDownStatementNotStatementStatementNotStatementStatementByteMatchStatementFieldToMatchJsonBodyMatchPatternAll all;
        private @Nullable List<String> includedPaths;
        public Builder() {}
        public Builder(WebAclRuleStatementManagedRuleGroupStatementScopeDownStatementNotStatementStatementNotStatementStatementByteMatchStatementFieldToMatchJsonBodyMatchPattern defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.all = defaults.all;
    	      this.includedPaths = defaults.includedPaths;
        }

        @CustomType.Setter
        public Builder all(@Nullable WebAclRuleStatementManagedRuleGroupStatementScopeDownStatementNotStatementStatementNotStatementStatementByteMatchStatementFieldToMatchJsonBodyMatchPatternAll all) {
            this.all = all;
            return this;
        }
        @CustomType.Setter
        public Builder includedPaths(@Nullable List<String> includedPaths) {
            this.includedPaths = includedPaths;
            return this;
        }
        public Builder includedPaths(String... includedPaths) {
            return includedPaths(List.of(includedPaths));
        }
        public WebAclRuleStatementManagedRuleGroupStatementScopeDownStatementNotStatementStatementNotStatementStatementByteMatchStatementFieldToMatchJsonBodyMatchPattern build() {
            final var o = new WebAclRuleStatementManagedRuleGroupStatementScopeDownStatementNotStatementStatementNotStatementStatementByteMatchStatementFieldToMatchJsonBodyMatchPattern();
            o.all = all;
            o.includedPaths = includedPaths;
            return o;
        }
    }
}
