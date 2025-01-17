// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.aws.location;

import com.pulumi.aws.location.inputs.PlaceIndexDataSourceConfigurationArgs;
import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class PlaceIndexArgs extends com.pulumi.resources.ResourceArgs {

    public static final PlaceIndexArgs Empty = new PlaceIndexArgs();

    /**
     * Specifies the geospatial data provider for the new place index.
     * 
     */
    @Import(name="dataSource", required=true)
    private Output<String> dataSource;

    /**
     * @return Specifies the geospatial data provider for the new place index.
     * 
     */
    public Output<String> dataSource() {
        return this.dataSource;
    }

    /**
     * Configuration block with the data storage option chosen for requesting Places. Detailed below.
     * 
     */
    @Import(name="dataSourceConfiguration")
    private @Nullable Output<PlaceIndexDataSourceConfigurationArgs> dataSourceConfiguration;

    /**
     * @return Configuration block with the data storage option chosen for requesting Places. Detailed below.
     * 
     */
    public Optional<Output<PlaceIndexDataSourceConfigurationArgs>> dataSourceConfiguration() {
        return Optional.ofNullable(this.dataSourceConfiguration);
    }

    /**
     * The optional description for the place index resource.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return The optional description for the place index resource.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * The name of the place index resource.
     * 
     */
    @Import(name="indexName", required=true)
    private Output<String> indexName;

    /**
     * @return The name of the place index resource.
     * 
     */
    public Output<String> indexName() {
        return this.indexName;
    }

    @Import(name="tags")
    private @Nullable Output<Map<String,String>> tags;

    public Optional<Output<Map<String,String>>> tags() {
        return Optional.ofNullable(this.tags);
    }

    private PlaceIndexArgs() {}

    private PlaceIndexArgs(PlaceIndexArgs $) {
        this.dataSource = $.dataSource;
        this.dataSourceConfiguration = $.dataSourceConfiguration;
        this.description = $.description;
        this.indexName = $.indexName;
        this.tags = $.tags;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(PlaceIndexArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private PlaceIndexArgs $;

        public Builder() {
            $ = new PlaceIndexArgs();
        }

        public Builder(PlaceIndexArgs defaults) {
            $ = new PlaceIndexArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param dataSource Specifies the geospatial data provider for the new place index.
         * 
         * @return builder
         * 
         */
        public Builder dataSource(Output<String> dataSource) {
            $.dataSource = dataSource;
            return this;
        }

        /**
         * @param dataSource Specifies the geospatial data provider for the new place index.
         * 
         * @return builder
         * 
         */
        public Builder dataSource(String dataSource) {
            return dataSource(Output.of(dataSource));
        }

        /**
         * @param dataSourceConfiguration Configuration block with the data storage option chosen for requesting Places. Detailed below.
         * 
         * @return builder
         * 
         */
        public Builder dataSourceConfiguration(@Nullable Output<PlaceIndexDataSourceConfigurationArgs> dataSourceConfiguration) {
            $.dataSourceConfiguration = dataSourceConfiguration;
            return this;
        }

        /**
         * @param dataSourceConfiguration Configuration block with the data storage option chosen for requesting Places. Detailed below.
         * 
         * @return builder
         * 
         */
        public Builder dataSourceConfiguration(PlaceIndexDataSourceConfigurationArgs dataSourceConfiguration) {
            return dataSourceConfiguration(Output.of(dataSourceConfiguration));
        }

        /**
         * @param description The optional description for the place index resource.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description The optional description for the place index resource.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param indexName The name of the place index resource.
         * 
         * @return builder
         * 
         */
        public Builder indexName(Output<String> indexName) {
            $.indexName = indexName;
            return this;
        }

        /**
         * @param indexName The name of the place index resource.
         * 
         * @return builder
         * 
         */
        public Builder indexName(String indexName) {
            return indexName(Output.of(indexName));
        }

        public Builder tags(@Nullable Output<Map<String,String>> tags) {
            $.tags = tags;
            return this;
        }

        public Builder tags(Map<String,String> tags) {
            return tags(Output.of(tags));
        }

        public PlaceIndexArgs build() {
            $.dataSource = Objects.requireNonNull($.dataSource, "expected parameter 'dataSource' to be non-null");
            $.indexName = Objects.requireNonNull($.indexName, "expected parameter 'indexName' to be non-null");
            return $;
        }
    }

}
