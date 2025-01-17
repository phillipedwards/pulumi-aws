// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.aws.memorydb.inputs;

import com.pulumi.aws.memorydb.inputs.ClusterShardNodeEndpointArgs;
import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ClusterShardNodeArgs extends com.pulumi.resources.ResourceArgs {

    public static final ClusterShardNodeArgs Empty = new ClusterShardNodeArgs();

    /**
     * The Availability Zone in which the node resides.
     * 
     */
    @Import(name="availabilityZone")
    private @Nullable Output<String> availabilityZone;

    /**
     * @return The Availability Zone in which the node resides.
     * 
     */
    public Optional<Output<String>> availabilityZone() {
        return Optional.ofNullable(this.availabilityZone);
    }

    /**
     * The date and time when the node was created. Example: `2022-01-01T21:00:00Z`.
     * 
     */
    @Import(name="createTime")
    private @Nullable Output<String> createTime;

    /**
     * @return The date and time when the node was created. Example: `2022-01-01T21:00:00Z`.
     * 
     */
    public Optional<Output<String>> createTime() {
        return Optional.ofNullable(this.createTime);
    }

    @Import(name="endpoints")
    private @Nullable Output<List<ClusterShardNodeEndpointArgs>> endpoints;

    public Optional<Output<List<ClusterShardNodeEndpointArgs>>> endpoints() {
        return Optional.ofNullable(this.endpoints);
    }

    /**
     * Name of this node.
     * * `endpoint`
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return Name of this node.
     * * `endpoint`
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    private ClusterShardNodeArgs() {}

    private ClusterShardNodeArgs(ClusterShardNodeArgs $) {
        this.availabilityZone = $.availabilityZone;
        this.createTime = $.createTime;
        this.endpoints = $.endpoints;
        this.name = $.name;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ClusterShardNodeArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ClusterShardNodeArgs $;

        public Builder() {
            $ = new ClusterShardNodeArgs();
        }

        public Builder(ClusterShardNodeArgs defaults) {
            $ = new ClusterShardNodeArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param availabilityZone The Availability Zone in which the node resides.
         * 
         * @return builder
         * 
         */
        public Builder availabilityZone(@Nullable Output<String> availabilityZone) {
            $.availabilityZone = availabilityZone;
            return this;
        }

        /**
         * @param availabilityZone The Availability Zone in which the node resides.
         * 
         * @return builder
         * 
         */
        public Builder availabilityZone(String availabilityZone) {
            return availabilityZone(Output.of(availabilityZone));
        }

        /**
         * @param createTime The date and time when the node was created. Example: `2022-01-01T21:00:00Z`.
         * 
         * @return builder
         * 
         */
        public Builder createTime(@Nullable Output<String> createTime) {
            $.createTime = createTime;
            return this;
        }

        /**
         * @param createTime The date and time when the node was created. Example: `2022-01-01T21:00:00Z`.
         * 
         * @return builder
         * 
         */
        public Builder createTime(String createTime) {
            return createTime(Output.of(createTime));
        }

        public Builder endpoints(@Nullable Output<List<ClusterShardNodeEndpointArgs>> endpoints) {
            $.endpoints = endpoints;
            return this;
        }

        public Builder endpoints(List<ClusterShardNodeEndpointArgs> endpoints) {
            return endpoints(Output.of(endpoints));
        }

        public Builder endpoints(ClusterShardNodeEndpointArgs... endpoints) {
            return endpoints(List.of(endpoints));
        }

        /**
         * @param name Name of this node.
         * * `endpoint`
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name Name of this node.
         * * `endpoint`
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        public ClusterShardNodeArgs build() {
            return $;
        }
    }

}
