// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.aws.sqs;

import com.pulumi.aws.Utilities;
import com.pulumi.aws.sqs.inputs.GetQueueArgs;
import com.pulumi.aws.sqs.inputs.GetQueuePlainArgs;
import com.pulumi.aws.sqs.outputs.GetQueueResult;
import com.pulumi.core.Output;
import com.pulumi.core.TypeShape;
import com.pulumi.deployment.Deployment;
import com.pulumi.deployment.InvokeOptions;
import java.util.concurrent.CompletableFuture;

public final class SqsFunctions {
    /**
     * Use this data source to get the ARN and URL of queue in AWS Simple Queue Service (SQS).
     * By using this data source, you can reference SQS queues without having to hardcode
     * the ARNs as input.
     * 
     * ## Example Usage
     * ```java
     * package generated_program;
     * 
     * import com.pulumi.Context;
     * import com.pulumi.Pulumi;
     * import com.pulumi.core.Output;
     * import com.pulumi.aws.sqs.SqsFunctions;
     * import com.pulumi.aws.connect.inputs.GetQueueArgs;
     * import java.util.List;
     * import java.util.ArrayList;
     * import java.util.Map;
     * import java.io.File;
     * import java.nio.file.Files;
     * import java.nio.file.Paths;
     * 
     * public class App {
     *     public static void main(String[] args) {
     *         Pulumi.run(App::stack);
     *     }
     * 
     *     public static void stack(Context ctx) {
     *         final var example = SqsFunctions.getQueue(GetQueueArgs.builder()
     *             .name(&#34;queue&#34;)
     *             .build());
     * 
     *     }
     * }
     * ```
     * 
     */
    public static Output<GetQueueResult> getQueue(GetQueueArgs args) {
        return getQueue(args, InvokeOptions.Empty);
    }
    /**
     * Use this data source to get the ARN and URL of queue in AWS Simple Queue Service (SQS).
     * By using this data source, you can reference SQS queues without having to hardcode
     * the ARNs as input.
     * 
     * ## Example Usage
     * ```java
     * package generated_program;
     * 
     * import com.pulumi.Context;
     * import com.pulumi.Pulumi;
     * import com.pulumi.core.Output;
     * import com.pulumi.aws.sqs.SqsFunctions;
     * import com.pulumi.aws.connect.inputs.GetQueueArgs;
     * import java.util.List;
     * import java.util.ArrayList;
     * import java.util.Map;
     * import java.io.File;
     * import java.nio.file.Files;
     * import java.nio.file.Paths;
     * 
     * public class App {
     *     public static void main(String[] args) {
     *         Pulumi.run(App::stack);
     *     }
     * 
     *     public static void stack(Context ctx) {
     *         final var example = SqsFunctions.getQueue(GetQueueArgs.builder()
     *             .name(&#34;queue&#34;)
     *             .build());
     * 
     *     }
     * }
     * ```
     * 
     */
    public static CompletableFuture<GetQueueResult> getQueuePlain(GetQueuePlainArgs args) {
        return getQueuePlain(args, InvokeOptions.Empty);
    }
    /**
     * Use this data source to get the ARN and URL of queue in AWS Simple Queue Service (SQS).
     * By using this data source, you can reference SQS queues without having to hardcode
     * the ARNs as input.
     * 
     * ## Example Usage
     * ```java
     * package generated_program;
     * 
     * import com.pulumi.Context;
     * import com.pulumi.Pulumi;
     * import com.pulumi.core.Output;
     * import com.pulumi.aws.sqs.SqsFunctions;
     * import com.pulumi.aws.connect.inputs.GetQueueArgs;
     * import java.util.List;
     * import java.util.ArrayList;
     * import java.util.Map;
     * import java.io.File;
     * import java.nio.file.Files;
     * import java.nio.file.Paths;
     * 
     * public class App {
     *     public static void main(String[] args) {
     *         Pulumi.run(App::stack);
     *     }
     * 
     *     public static void stack(Context ctx) {
     *         final var example = SqsFunctions.getQueue(GetQueueArgs.builder()
     *             .name(&#34;queue&#34;)
     *             .build());
     * 
     *     }
     * }
     * ```
     * 
     */
    public static Output<GetQueueResult> getQueue(GetQueueArgs args, InvokeOptions options) {
        return Deployment.getInstance().invoke("aws:sqs/getQueue:getQueue", TypeShape.of(GetQueueResult.class), args, Utilities.withVersion(options));
    }
    /**
     * Use this data source to get the ARN and URL of queue in AWS Simple Queue Service (SQS).
     * By using this data source, you can reference SQS queues without having to hardcode
     * the ARNs as input.
     * 
     * ## Example Usage
     * ```java
     * package generated_program;
     * 
     * import com.pulumi.Context;
     * import com.pulumi.Pulumi;
     * import com.pulumi.core.Output;
     * import com.pulumi.aws.sqs.SqsFunctions;
     * import com.pulumi.aws.connect.inputs.GetQueueArgs;
     * import java.util.List;
     * import java.util.ArrayList;
     * import java.util.Map;
     * import java.io.File;
     * import java.nio.file.Files;
     * import java.nio.file.Paths;
     * 
     * public class App {
     *     public static void main(String[] args) {
     *         Pulumi.run(App::stack);
     *     }
     * 
     *     public static void stack(Context ctx) {
     *         final var example = SqsFunctions.getQueue(GetQueueArgs.builder()
     *             .name(&#34;queue&#34;)
     *             .build());
     * 
     *     }
     * }
     * ```
     * 
     */
    public static CompletableFuture<GetQueueResult> getQueuePlain(GetQueuePlainArgs args, InvokeOptions options) {
        return Deployment.getInstance().invokeAsync("aws:sqs/getQueue:getQueue", TypeShape.of(GetQueueResult.class), args, Utilities.withVersion(options));
    }
}
