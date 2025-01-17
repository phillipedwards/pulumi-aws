// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.aws.kinesis.inputs;

import com.pulumi.aws.kinesis.inputs.FirehoseDeliveryStreamExtendedS3ConfigurationDataFormatConversionConfigurationInputFormatConfigurationDeserializerHiveJsonSerDeArgs;
import com.pulumi.aws.kinesis.inputs.FirehoseDeliveryStreamExtendedS3ConfigurationDataFormatConversionConfigurationInputFormatConfigurationDeserializerOpenXJsonSerDeArgs;
import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class FirehoseDeliveryStreamExtendedS3ConfigurationDataFormatConversionConfigurationInputFormatConfigurationDeserializerArgs extends com.pulumi.resources.ResourceArgs {

    public static final FirehoseDeliveryStreamExtendedS3ConfigurationDataFormatConversionConfigurationInputFormatConfigurationDeserializerArgs Empty = new FirehoseDeliveryStreamExtendedS3ConfigurationDataFormatConversionConfigurationInputFormatConfigurationDeserializerArgs();

    /**
     * Nested argument that specifies the native Hive / HCatalog JsonSerDe. More details below.
     * 
     */
    @Import(name="hiveJsonSerDe")
    private @Nullable Output<FirehoseDeliveryStreamExtendedS3ConfigurationDataFormatConversionConfigurationInputFormatConfigurationDeserializerHiveJsonSerDeArgs> hiveJsonSerDe;

    /**
     * @return Nested argument that specifies the native Hive / HCatalog JsonSerDe. More details below.
     * 
     */
    public Optional<Output<FirehoseDeliveryStreamExtendedS3ConfigurationDataFormatConversionConfigurationInputFormatConfigurationDeserializerHiveJsonSerDeArgs>> hiveJsonSerDe() {
        return Optional.ofNullable(this.hiveJsonSerDe);
    }

    /**
     * Nested argument that specifies the OpenX SerDe. More details below.
     * 
     */
    @Import(name="openXJsonSerDe")
    private @Nullable Output<FirehoseDeliveryStreamExtendedS3ConfigurationDataFormatConversionConfigurationInputFormatConfigurationDeserializerOpenXJsonSerDeArgs> openXJsonSerDe;

    /**
     * @return Nested argument that specifies the OpenX SerDe. More details below.
     * 
     */
    public Optional<Output<FirehoseDeliveryStreamExtendedS3ConfigurationDataFormatConversionConfigurationInputFormatConfigurationDeserializerOpenXJsonSerDeArgs>> openXJsonSerDe() {
        return Optional.ofNullable(this.openXJsonSerDe);
    }

    private FirehoseDeliveryStreamExtendedS3ConfigurationDataFormatConversionConfigurationInputFormatConfigurationDeserializerArgs() {}

    private FirehoseDeliveryStreamExtendedS3ConfigurationDataFormatConversionConfigurationInputFormatConfigurationDeserializerArgs(FirehoseDeliveryStreamExtendedS3ConfigurationDataFormatConversionConfigurationInputFormatConfigurationDeserializerArgs $) {
        this.hiveJsonSerDe = $.hiveJsonSerDe;
        this.openXJsonSerDe = $.openXJsonSerDe;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(FirehoseDeliveryStreamExtendedS3ConfigurationDataFormatConversionConfigurationInputFormatConfigurationDeserializerArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private FirehoseDeliveryStreamExtendedS3ConfigurationDataFormatConversionConfigurationInputFormatConfigurationDeserializerArgs $;

        public Builder() {
            $ = new FirehoseDeliveryStreamExtendedS3ConfigurationDataFormatConversionConfigurationInputFormatConfigurationDeserializerArgs();
        }

        public Builder(FirehoseDeliveryStreamExtendedS3ConfigurationDataFormatConversionConfigurationInputFormatConfigurationDeserializerArgs defaults) {
            $ = new FirehoseDeliveryStreamExtendedS3ConfigurationDataFormatConversionConfigurationInputFormatConfigurationDeserializerArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param hiveJsonSerDe Nested argument that specifies the native Hive / HCatalog JsonSerDe. More details below.
         * 
         * @return builder
         * 
         */
        public Builder hiveJsonSerDe(@Nullable Output<FirehoseDeliveryStreamExtendedS3ConfigurationDataFormatConversionConfigurationInputFormatConfigurationDeserializerHiveJsonSerDeArgs> hiveJsonSerDe) {
            $.hiveJsonSerDe = hiveJsonSerDe;
            return this;
        }

        /**
         * @param hiveJsonSerDe Nested argument that specifies the native Hive / HCatalog JsonSerDe. More details below.
         * 
         * @return builder
         * 
         */
        public Builder hiveJsonSerDe(FirehoseDeliveryStreamExtendedS3ConfigurationDataFormatConversionConfigurationInputFormatConfigurationDeserializerHiveJsonSerDeArgs hiveJsonSerDe) {
            return hiveJsonSerDe(Output.of(hiveJsonSerDe));
        }

        /**
         * @param openXJsonSerDe Nested argument that specifies the OpenX SerDe. More details below.
         * 
         * @return builder
         * 
         */
        public Builder openXJsonSerDe(@Nullable Output<FirehoseDeliveryStreamExtendedS3ConfigurationDataFormatConversionConfigurationInputFormatConfigurationDeserializerOpenXJsonSerDeArgs> openXJsonSerDe) {
            $.openXJsonSerDe = openXJsonSerDe;
            return this;
        }

        /**
         * @param openXJsonSerDe Nested argument that specifies the OpenX SerDe. More details below.
         * 
         * @return builder
         * 
         */
        public Builder openXJsonSerDe(FirehoseDeliveryStreamExtendedS3ConfigurationDataFormatConversionConfigurationInputFormatConfigurationDeserializerOpenXJsonSerDeArgs openXJsonSerDe) {
            return openXJsonSerDe(Output.of(openXJsonSerDe));
        }

        public FirehoseDeliveryStreamExtendedS3ConfigurationDataFormatConversionConfigurationInputFormatConfigurationDeserializerArgs build() {
            return $;
        }
    }

}
