// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.aws.connect.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class QuickConnectQuickConnectConfigQueueConfigArgs extends com.pulumi.resources.ResourceArgs {

    public static final QuickConnectQuickConnectConfigQueueConfigArgs Empty = new QuickConnectQuickConnectConfigQueueConfigArgs();

    /**
     * Specifies the identifier of the contact flow.
     * 
     */
    @Import(name="contactFlowId", required=true)
    private Output<String> contactFlowId;

    /**
     * @return Specifies the identifier of the contact flow.
     * 
     */
    public Output<String> contactFlowId() {
        return this.contactFlowId;
    }

    /**
     * Specifies the identifier for the queue.
     * 
     */
    @Import(name="queueId", required=true)
    private Output<String> queueId;

    /**
     * @return Specifies the identifier for the queue.
     * 
     */
    public Output<String> queueId() {
        return this.queueId;
    }

    private QuickConnectQuickConnectConfigQueueConfigArgs() {}

    private QuickConnectQuickConnectConfigQueueConfigArgs(QuickConnectQuickConnectConfigQueueConfigArgs $) {
        this.contactFlowId = $.contactFlowId;
        this.queueId = $.queueId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(QuickConnectQuickConnectConfigQueueConfigArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private QuickConnectQuickConnectConfigQueueConfigArgs $;

        public Builder() {
            $ = new QuickConnectQuickConnectConfigQueueConfigArgs();
        }

        public Builder(QuickConnectQuickConnectConfigQueueConfigArgs defaults) {
            $ = new QuickConnectQuickConnectConfigQueueConfigArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param contactFlowId Specifies the identifier of the contact flow.
         * 
         * @return builder
         * 
         */
        public Builder contactFlowId(Output<String> contactFlowId) {
            $.contactFlowId = contactFlowId;
            return this;
        }

        /**
         * @param contactFlowId Specifies the identifier of the contact flow.
         * 
         * @return builder
         * 
         */
        public Builder contactFlowId(String contactFlowId) {
            return contactFlowId(Output.of(contactFlowId));
        }

        /**
         * @param queueId Specifies the identifier for the queue.
         * 
         * @return builder
         * 
         */
        public Builder queueId(Output<String> queueId) {
            $.queueId = queueId;
            return this;
        }

        /**
         * @param queueId Specifies the identifier for the queue.
         * 
         * @return builder
         * 
         */
        public Builder queueId(String queueId) {
            return queueId(Output.of(queueId));
        }

        public QuickConnectQuickConnectConfigQueueConfigArgs build() {
            $.contactFlowId = Objects.requireNonNull($.contactFlowId, "expected parameter 'contactFlowId' to be non-null");
            $.queueId = Objects.requireNonNull($.queueId, "expected parameter 'queueId' to be non-null");
            return $;
        }
    }

}
