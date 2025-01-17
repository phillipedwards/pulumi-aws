// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.aws.wafv2.outputs;

import com.pulumi.aws.wafv2.outputs.WebAclRuleStatementOrStatementStatementNotStatementStatementAndStatement;
import com.pulumi.aws.wafv2.outputs.WebAclRuleStatementOrStatementStatementNotStatementStatementByteMatchStatement;
import com.pulumi.aws.wafv2.outputs.WebAclRuleStatementOrStatementStatementNotStatementStatementGeoMatchStatement;
import com.pulumi.aws.wafv2.outputs.WebAclRuleStatementOrStatementStatementNotStatementStatementIpSetReferenceStatement;
import com.pulumi.aws.wafv2.outputs.WebAclRuleStatementOrStatementStatementNotStatementStatementLabelMatchStatement;
import com.pulumi.aws.wafv2.outputs.WebAclRuleStatementOrStatementStatementNotStatementStatementNotStatement;
import com.pulumi.aws.wafv2.outputs.WebAclRuleStatementOrStatementStatementNotStatementStatementOrStatement;
import com.pulumi.aws.wafv2.outputs.WebAclRuleStatementOrStatementStatementNotStatementStatementRegexPatternSetReferenceStatement;
import com.pulumi.aws.wafv2.outputs.WebAclRuleStatementOrStatementStatementNotStatementStatementSizeConstraintStatement;
import com.pulumi.aws.wafv2.outputs.WebAclRuleStatementOrStatementStatementNotStatementStatementSqliMatchStatement;
import com.pulumi.aws.wafv2.outputs.WebAclRuleStatementOrStatementStatementNotStatementStatementXssMatchStatement;
import com.pulumi.core.annotations.CustomType;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class WebAclRuleStatementOrStatementStatementNotStatementStatement {
    /**
     * @return Logical rule statement used to combine other rule statements with AND logic. See AND Statement below for details.
     * 
     */
    private @Nullable WebAclRuleStatementOrStatementStatementNotStatementStatementAndStatement andStatement;
    /**
     * @return Rule statement that defines a string match search for AWS WAF to apply to web requests. See Byte Match Statement below for details.
     * 
     */
    private @Nullable WebAclRuleStatementOrStatementStatementNotStatementStatementByteMatchStatement byteMatchStatement;
    /**
     * @return Rule statement used to identify web requests based on country of origin. See GEO Match Statement below for details.
     * 
     */
    private @Nullable WebAclRuleStatementOrStatementStatementNotStatementStatementGeoMatchStatement geoMatchStatement;
    /**
     * @return Rule statement used to detect web requests coming from particular IP addresses or address ranges. See IP Set Reference Statement below for details.
     * 
     */
    private @Nullable WebAclRuleStatementOrStatementStatementNotStatementStatementIpSetReferenceStatement ipSetReferenceStatement;
    /**
     * @return Rule statement that defines a string match search against labels that have been added to the web request by rules that have already run in the web ACL. See Label Match Statement below for details.
     * 
     */
    private @Nullable WebAclRuleStatementOrStatementStatementNotStatementStatementLabelMatchStatement labelMatchStatement;
    /**
     * @return Logical rule statement used to negate the results of another rule statement. See NOT Statement below for details.
     * 
     */
    private @Nullable WebAclRuleStatementOrStatementStatementNotStatementStatementNotStatement notStatement;
    /**
     * @return Logical rule statement used to combine other rule statements with OR logic. See OR Statement below for details.
     * 
     */
    private @Nullable WebAclRuleStatementOrStatementStatementNotStatementStatementOrStatement orStatement;
    /**
     * @return Rule statement used to search web request components for matches with regular expressions. See Regex Pattern Set Reference Statement below for details.
     * 
     */
    private @Nullable WebAclRuleStatementOrStatementStatementNotStatementStatementRegexPatternSetReferenceStatement regexPatternSetReferenceStatement;
    /**
     * @return Rule statement that compares a number of bytes against the size of a request component, using a comparison operator, such as greater than (&gt;) or less than (&lt;). See Size Constraint Statement below for more details.
     * 
     */
    private @Nullable WebAclRuleStatementOrStatementStatementNotStatementStatementSizeConstraintStatement sizeConstraintStatement;
    /**
     * @return An SQL injection match condition identifies the part of web requests, such as the URI or the query string, that you want AWS WAF to inspect. See SQL Injection Match Statement below for details.
     * 
     */
    private @Nullable WebAclRuleStatementOrStatementStatementNotStatementStatementSqliMatchStatement sqliMatchStatement;
    /**
     * @return Rule statement that defines a cross-site scripting (XSS) match search for AWS WAF to apply to web requests. See XSS Match Statement below for details.
     * 
     */
    private @Nullable WebAclRuleStatementOrStatementStatementNotStatementStatementXssMatchStatement xssMatchStatement;

    private WebAclRuleStatementOrStatementStatementNotStatementStatement() {}
    /**
     * @return Logical rule statement used to combine other rule statements with AND logic. See AND Statement below for details.
     * 
     */
    public Optional<WebAclRuleStatementOrStatementStatementNotStatementStatementAndStatement> andStatement() {
        return Optional.ofNullable(this.andStatement);
    }
    /**
     * @return Rule statement that defines a string match search for AWS WAF to apply to web requests. See Byte Match Statement below for details.
     * 
     */
    public Optional<WebAclRuleStatementOrStatementStatementNotStatementStatementByteMatchStatement> byteMatchStatement() {
        return Optional.ofNullable(this.byteMatchStatement);
    }
    /**
     * @return Rule statement used to identify web requests based on country of origin. See GEO Match Statement below for details.
     * 
     */
    public Optional<WebAclRuleStatementOrStatementStatementNotStatementStatementGeoMatchStatement> geoMatchStatement() {
        return Optional.ofNullable(this.geoMatchStatement);
    }
    /**
     * @return Rule statement used to detect web requests coming from particular IP addresses or address ranges. See IP Set Reference Statement below for details.
     * 
     */
    public Optional<WebAclRuleStatementOrStatementStatementNotStatementStatementIpSetReferenceStatement> ipSetReferenceStatement() {
        return Optional.ofNullable(this.ipSetReferenceStatement);
    }
    /**
     * @return Rule statement that defines a string match search against labels that have been added to the web request by rules that have already run in the web ACL. See Label Match Statement below for details.
     * 
     */
    public Optional<WebAclRuleStatementOrStatementStatementNotStatementStatementLabelMatchStatement> labelMatchStatement() {
        return Optional.ofNullable(this.labelMatchStatement);
    }
    /**
     * @return Logical rule statement used to negate the results of another rule statement. See NOT Statement below for details.
     * 
     */
    public Optional<WebAclRuleStatementOrStatementStatementNotStatementStatementNotStatement> notStatement() {
        return Optional.ofNullable(this.notStatement);
    }
    /**
     * @return Logical rule statement used to combine other rule statements with OR logic. See OR Statement below for details.
     * 
     */
    public Optional<WebAclRuleStatementOrStatementStatementNotStatementStatementOrStatement> orStatement() {
        return Optional.ofNullable(this.orStatement);
    }
    /**
     * @return Rule statement used to search web request components for matches with regular expressions. See Regex Pattern Set Reference Statement below for details.
     * 
     */
    public Optional<WebAclRuleStatementOrStatementStatementNotStatementStatementRegexPatternSetReferenceStatement> regexPatternSetReferenceStatement() {
        return Optional.ofNullable(this.regexPatternSetReferenceStatement);
    }
    /**
     * @return Rule statement that compares a number of bytes against the size of a request component, using a comparison operator, such as greater than (&gt;) or less than (&lt;). See Size Constraint Statement below for more details.
     * 
     */
    public Optional<WebAclRuleStatementOrStatementStatementNotStatementStatementSizeConstraintStatement> sizeConstraintStatement() {
        return Optional.ofNullable(this.sizeConstraintStatement);
    }
    /**
     * @return An SQL injection match condition identifies the part of web requests, such as the URI or the query string, that you want AWS WAF to inspect. See SQL Injection Match Statement below for details.
     * 
     */
    public Optional<WebAclRuleStatementOrStatementStatementNotStatementStatementSqliMatchStatement> sqliMatchStatement() {
        return Optional.ofNullable(this.sqliMatchStatement);
    }
    /**
     * @return Rule statement that defines a cross-site scripting (XSS) match search for AWS WAF to apply to web requests. See XSS Match Statement below for details.
     * 
     */
    public Optional<WebAclRuleStatementOrStatementStatementNotStatementStatementXssMatchStatement> xssMatchStatement() {
        return Optional.ofNullable(this.xssMatchStatement);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(WebAclRuleStatementOrStatementStatementNotStatementStatement defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable WebAclRuleStatementOrStatementStatementNotStatementStatementAndStatement andStatement;
        private @Nullable WebAclRuleStatementOrStatementStatementNotStatementStatementByteMatchStatement byteMatchStatement;
        private @Nullable WebAclRuleStatementOrStatementStatementNotStatementStatementGeoMatchStatement geoMatchStatement;
        private @Nullable WebAclRuleStatementOrStatementStatementNotStatementStatementIpSetReferenceStatement ipSetReferenceStatement;
        private @Nullable WebAclRuleStatementOrStatementStatementNotStatementStatementLabelMatchStatement labelMatchStatement;
        private @Nullable WebAclRuleStatementOrStatementStatementNotStatementStatementNotStatement notStatement;
        private @Nullable WebAclRuleStatementOrStatementStatementNotStatementStatementOrStatement orStatement;
        private @Nullable WebAclRuleStatementOrStatementStatementNotStatementStatementRegexPatternSetReferenceStatement regexPatternSetReferenceStatement;
        private @Nullable WebAclRuleStatementOrStatementStatementNotStatementStatementSizeConstraintStatement sizeConstraintStatement;
        private @Nullable WebAclRuleStatementOrStatementStatementNotStatementStatementSqliMatchStatement sqliMatchStatement;
        private @Nullable WebAclRuleStatementOrStatementStatementNotStatementStatementXssMatchStatement xssMatchStatement;
        public Builder() {}
        public Builder(WebAclRuleStatementOrStatementStatementNotStatementStatement defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.andStatement = defaults.andStatement;
    	      this.byteMatchStatement = defaults.byteMatchStatement;
    	      this.geoMatchStatement = defaults.geoMatchStatement;
    	      this.ipSetReferenceStatement = defaults.ipSetReferenceStatement;
    	      this.labelMatchStatement = defaults.labelMatchStatement;
    	      this.notStatement = defaults.notStatement;
    	      this.orStatement = defaults.orStatement;
    	      this.regexPatternSetReferenceStatement = defaults.regexPatternSetReferenceStatement;
    	      this.sizeConstraintStatement = defaults.sizeConstraintStatement;
    	      this.sqliMatchStatement = defaults.sqliMatchStatement;
    	      this.xssMatchStatement = defaults.xssMatchStatement;
        }

        @CustomType.Setter
        public Builder andStatement(@Nullable WebAclRuleStatementOrStatementStatementNotStatementStatementAndStatement andStatement) {
            this.andStatement = andStatement;
            return this;
        }
        @CustomType.Setter
        public Builder byteMatchStatement(@Nullable WebAclRuleStatementOrStatementStatementNotStatementStatementByteMatchStatement byteMatchStatement) {
            this.byteMatchStatement = byteMatchStatement;
            return this;
        }
        @CustomType.Setter
        public Builder geoMatchStatement(@Nullable WebAclRuleStatementOrStatementStatementNotStatementStatementGeoMatchStatement geoMatchStatement) {
            this.geoMatchStatement = geoMatchStatement;
            return this;
        }
        @CustomType.Setter
        public Builder ipSetReferenceStatement(@Nullable WebAclRuleStatementOrStatementStatementNotStatementStatementIpSetReferenceStatement ipSetReferenceStatement) {
            this.ipSetReferenceStatement = ipSetReferenceStatement;
            return this;
        }
        @CustomType.Setter
        public Builder labelMatchStatement(@Nullable WebAclRuleStatementOrStatementStatementNotStatementStatementLabelMatchStatement labelMatchStatement) {
            this.labelMatchStatement = labelMatchStatement;
            return this;
        }
        @CustomType.Setter
        public Builder notStatement(@Nullable WebAclRuleStatementOrStatementStatementNotStatementStatementNotStatement notStatement) {
            this.notStatement = notStatement;
            return this;
        }
        @CustomType.Setter
        public Builder orStatement(@Nullable WebAclRuleStatementOrStatementStatementNotStatementStatementOrStatement orStatement) {
            this.orStatement = orStatement;
            return this;
        }
        @CustomType.Setter
        public Builder regexPatternSetReferenceStatement(@Nullable WebAclRuleStatementOrStatementStatementNotStatementStatementRegexPatternSetReferenceStatement regexPatternSetReferenceStatement) {
            this.regexPatternSetReferenceStatement = regexPatternSetReferenceStatement;
            return this;
        }
        @CustomType.Setter
        public Builder sizeConstraintStatement(@Nullable WebAclRuleStatementOrStatementStatementNotStatementStatementSizeConstraintStatement sizeConstraintStatement) {
            this.sizeConstraintStatement = sizeConstraintStatement;
            return this;
        }
        @CustomType.Setter
        public Builder sqliMatchStatement(@Nullable WebAclRuleStatementOrStatementStatementNotStatementStatementSqliMatchStatement sqliMatchStatement) {
            this.sqliMatchStatement = sqliMatchStatement;
            return this;
        }
        @CustomType.Setter
        public Builder xssMatchStatement(@Nullable WebAclRuleStatementOrStatementStatementNotStatementStatementXssMatchStatement xssMatchStatement) {
            this.xssMatchStatement = xssMatchStatement;
            return this;
        }
        public WebAclRuleStatementOrStatementStatementNotStatementStatement build() {
            final var o = new WebAclRuleStatementOrStatementStatementNotStatementStatement();
            o.andStatement = andStatement;
            o.byteMatchStatement = byteMatchStatement;
            o.geoMatchStatement = geoMatchStatement;
            o.ipSetReferenceStatement = ipSetReferenceStatement;
            o.labelMatchStatement = labelMatchStatement;
            o.notStatement = notStatement;
            o.orStatement = orStatement;
            o.regexPatternSetReferenceStatement = regexPatternSetReferenceStatement;
            o.sizeConstraintStatement = sizeConstraintStatement;
            o.sqliMatchStatement = sqliMatchStatement;
            o.xssMatchStatement = xssMatchStatement;
            return o;
        }
    }
}
