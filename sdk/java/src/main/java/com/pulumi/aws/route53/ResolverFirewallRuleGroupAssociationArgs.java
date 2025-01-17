// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.aws.route53;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Integer;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ResolverFirewallRuleGroupAssociationArgs extends com.pulumi.resources.ResourceArgs {

    public static final ResolverFirewallRuleGroupAssociationArgs Empty = new ResolverFirewallRuleGroupAssociationArgs();

    /**
     * The unique identifier of the firewall rule group.
     * 
     */
    @Import(name="firewallRuleGroupId", required=true)
    private Output<String> firewallRuleGroupId;

    /**
     * @return The unique identifier of the firewall rule group.
     * 
     */
    public Output<String> firewallRuleGroupId() {
        return this.firewallRuleGroupId;
    }

    /**
     * If enabled, this setting disallows modification or removal of the association, to help prevent against accidentally altering DNS firewall protections. Valid values: `ENABLED`, `DISABLED`.
     * 
     */
    @Import(name="mutationProtection")
    private @Nullable Output<String> mutationProtection;

    /**
     * @return If enabled, this setting disallows modification or removal of the association, to help prevent against accidentally altering DNS firewall protections. Valid values: `ENABLED`, `DISABLED`.
     * 
     */
    public Optional<Output<String>> mutationProtection() {
        return Optional.ofNullable(this.mutationProtection);
    }

    /**
     * A name that lets you identify the rule group association, to manage and use it.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return A name that lets you identify the rule group association, to manage and use it.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * The setting that determines the processing order of the rule group among the rule groups that you associate with the specified VPC. DNS Firewall filters VPC traffic starting from the rule group with the lowest numeric priority setting.
     * 
     */
    @Import(name="priority", required=true)
    private Output<Integer> priority;

    /**
     * @return The setting that determines the processing order of the rule group among the rule groups that you associate with the specified VPC. DNS Firewall filters VPC traffic starting from the rule group with the lowest numeric priority setting.
     * 
     */
    public Output<Integer> priority() {
        return this.priority;
    }

    /**
     * Key-value map of resource tags. .If configured with a provider `default_tags` configuration block present, tags with matching keys will overwrite those defined at the provider-level.
     * 
     */
    @Import(name="tags")
    private @Nullable Output<Map<String,String>> tags;

    /**
     * @return Key-value map of resource tags. .If configured with a provider `default_tags` configuration block present, tags with matching keys will overwrite those defined at the provider-level.
     * 
     */
    public Optional<Output<Map<String,String>>> tags() {
        return Optional.ofNullable(this.tags);
    }

    /**
     * The unique identifier of the VPC that you want to associate with the rule group.
     * 
     */
    @Import(name="vpcId", required=true)
    private Output<String> vpcId;

    /**
     * @return The unique identifier of the VPC that you want to associate with the rule group.
     * 
     */
    public Output<String> vpcId() {
        return this.vpcId;
    }

    private ResolverFirewallRuleGroupAssociationArgs() {}

    private ResolverFirewallRuleGroupAssociationArgs(ResolverFirewallRuleGroupAssociationArgs $) {
        this.firewallRuleGroupId = $.firewallRuleGroupId;
        this.mutationProtection = $.mutationProtection;
        this.name = $.name;
        this.priority = $.priority;
        this.tags = $.tags;
        this.vpcId = $.vpcId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ResolverFirewallRuleGroupAssociationArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ResolverFirewallRuleGroupAssociationArgs $;

        public Builder() {
            $ = new ResolverFirewallRuleGroupAssociationArgs();
        }

        public Builder(ResolverFirewallRuleGroupAssociationArgs defaults) {
            $ = new ResolverFirewallRuleGroupAssociationArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param firewallRuleGroupId The unique identifier of the firewall rule group.
         * 
         * @return builder
         * 
         */
        public Builder firewallRuleGroupId(Output<String> firewallRuleGroupId) {
            $.firewallRuleGroupId = firewallRuleGroupId;
            return this;
        }

        /**
         * @param firewallRuleGroupId The unique identifier of the firewall rule group.
         * 
         * @return builder
         * 
         */
        public Builder firewallRuleGroupId(String firewallRuleGroupId) {
            return firewallRuleGroupId(Output.of(firewallRuleGroupId));
        }

        /**
         * @param mutationProtection If enabled, this setting disallows modification or removal of the association, to help prevent against accidentally altering DNS firewall protections. Valid values: `ENABLED`, `DISABLED`.
         * 
         * @return builder
         * 
         */
        public Builder mutationProtection(@Nullable Output<String> mutationProtection) {
            $.mutationProtection = mutationProtection;
            return this;
        }

        /**
         * @param mutationProtection If enabled, this setting disallows modification or removal of the association, to help prevent against accidentally altering DNS firewall protections. Valid values: `ENABLED`, `DISABLED`.
         * 
         * @return builder
         * 
         */
        public Builder mutationProtection(String mutationProtection) {
            return mutationProtection(Output.of(mutationProtection));
        }

        /**
         * @param name A name that lets you identify the rule group association, to manage and use it.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name A name that lets you identify the rule group association, to manage and use it.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param priority The setting that determines the processing order of the rule group among the rule groups that you associate with the specified VPC. DNS Firewall filters VPC traffic starting from the rule group with the lowest numeric priority setting.
         * 
         * @return builder
         * 
         */
        public Builder priority(Output<Integer> priority) {
            $.priority = priority;
            return this;
        }

        /**
         * @param priority The setting that determines the processing order of the rule group among the rule groups that you associate with the specified VPC. DNS Firewall filters VPC traffic starting from the rule group with the lowest numeric priority setting.
         * 
         * @return builder
         * 
         */
        public Builder priority(Integer priority) {
            return priority(Output.of(priority));
        }

        /**
         * @param tags Key-value map of resource tags. .If configured with a provider `default_tags` configuration block present, tags with matching keys will overwrite those defined at the provider-level.
         * 
         * @return builder
         * 
         */
        public Builder tags(@Nullable Output<Map<String,String>> tags) {
            $.tags = tags;
            return this;
        }

        /**
         * @param tags Key-value map of resource tags. .If configured with a provider `default_tags` configuration block present, tags with matching keys will overwrite those defined at the provider-level.
         * 
         * @return builder
         * 
         */
        public Builder tags(Map<String,String> tags) {
            return tags(Output.of(tags));
        }

        /**
         * @param vpcId The unique identifier of the VPC that you want to associate with the rule group.
         * 
         * @return builder
         * 
         */
        public Builder vpcId(Output<String> vpcId) {
            $.vpcId = vpcId;
            return this;
        }

        /**
         * @param vpcId The unique identifier of the VPC that you want to associate with the rule group.
         * 
         * @return builder
         * 
         */
        public Builder vpcId(String vpcId) {
            return vpcId(Output.of(vpcId));
        }

        public ResolverFirewallRuleGroupAssociationArgs build() {
            $.firewallRuleGroupId = Objects.requireNonNull($.firewallRuleGroupId, "expected parameter 'firewallRuleGroupId' to be non-null");
            $.priority = Objects.requireNonNull($.priority, "expected parameter 'priority' to be non-null");
            $.vpcId = Objects.requireNonNull($.vpcId, "expected parameter 'vpcId' to be non-null");
            return $;
        }
    }

}
