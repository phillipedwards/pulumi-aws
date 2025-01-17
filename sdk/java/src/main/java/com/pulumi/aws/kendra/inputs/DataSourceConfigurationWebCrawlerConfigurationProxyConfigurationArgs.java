// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.aws.kendra.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DataSourceConfigurationWebCrawlerConfigurationProxyConfigurationArgs extends com.pulumi.resources.ResourceArgs {

    public static final DataSourceConfigurationWebCrawlerConfigurationProxyConfigurationArgs Empty = new DataSourceConfigurationWebCrawlerConfigurationProxyConfigurationArgs();

    /**
     * Your secret ARN, which you can create in AWS Secrets Manager. The credentials are optional. You use a secret if web proxy credentials are required to connect to a website host. Amazon Kendra currently support basic authentication to connect to a web proxy server. The secret stores your credentials.
     * 
     */
    @Import(name="credentials")
    private @Nullable Output<String> credentials;

    /**
     * @return Your secret ARN, which you can create in AWS Secrets Manager. The credentials are optional. You use a secret if web proxy credentials are required to connect to a website host. Amazon Kendra currently support basic authentication to connect to a web proxy server. The secret stores your credentials.
     * 
     */
    public Optional<Output<String>> credentials() {
        return Optional.ofNullable(this.credentials);
    }

    /**
     * The name of the website host you want to connect to via a web proxy server. For example, the host name of `https://a.example.com/page1.html` is `&#34;a.example.com&#34;`.
     * 
     */
    @Import(name="host", required=true)
    private Output<String> host;

    /**
     * @return The name of the website host you want to connect to via a web proxy server. For example, the host name of `https://a.example.com/page1.html` is `&#34;a.example.com&#34;`.
     * 
     */
    public Output<String> host() {
        return this.host;
    }

    /**
     * The port number of the website host you want to connect to via a web proxy server. For example, the port for `https://a.example.com/page1.html` is `443`, the standard port for HTTPS.
     * 
     */
    @Import(name="port", required=true)
    private Output<Integer> port;

    /**
     * @return The port number of the website host you want to connect to via a web proxy server. For example, the port for `https://a.example.com/page1.html` is `443`, the standard port for HTTPS.
     * 
     */
    public Output<Integer> port() {
        return this.port;
    }

    private DataSourceConfigurationWebCrawlerConfigurationProxyConfigurationArgs() {}

    private DataSourceConfigurationWebCrawlerConfigurationProxyConfigurationArgs(DataSourceConfigurationWebCrawlerConfigurationProxyConfigurationArgs $) {
        this.credentials = $.credentials;
        this.host = $.host;
        this.port = $.port;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DataSourceConfigurationWebCrawlerConfigurationProxyConfigurationArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DataSourceConfigurationWebCrawlerConfigurationProxyConfigurationArgs $;

        public Builder() {
            $ = new DataSourceConfigurationWebCrawlerConfigurationProxyConfigurationArgs();
        }

        public Builder(DataSourceConfigurationWebCrawlerConfigurationProxyConfigurationArgs defaults) {
            $ = new DataSourceConfigurationWebCrawlerConfigurationProxyConfigurationArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param credentials Your secret ARN, which you can create in AWS Secrets Manager. The credentials are optional. You use a secret if web proxy credentials are required to connect to a website host. Amazon Kendra currently support basic authentication to connect to a web proxy server. The secret stores your credentials.
         * 
         * @return builder
         * 
         */
        public Builder credentials(@Nullable Output<String> credentials) {
            $.credentials = credentials;
            return this;
        }

        /**
         * @param credentials Your secret ARN, which you can create in AWS Secrets Manager. The credentials are optional. You use a secret if web proxy credentials are required to connect to a website host. Amazon Kendra currently support basic authentication to connect to a web proxy server. The secret stores your credentials.
         * 
         * @return builder
         * 
         */
        public Builder credentials(String credentials) {
            return credentials(Output.of(credentials));
        }

        /**
         * @param host The name of the website host you want to connect to via a web proxy server. For example, the host name of `https://a.example.com/page1.html` is `&#34;a.example.com&#34;`.
         * 
         * @return builder
         * 
         */
        public Builder host(Output<String> host) {
            $.host = host;
            return this;
        }

        /**
         * @param host The name of the website host you want to connect to via a web proxy server. For example, the host name of `https://a.example.com/page1.html` is `&#34;a.example.com&#34;`.
         * 
         * @return builder
         * 
         */
        public Builder host(String host) {
            return host(Output.of(host));
        }

        /**
         * @param port The port number of the website host you want to connect to via a web proxy server. For example, the port for `https://a.example.com/page1.html` is `443`, the standard port for HTTPS.
         * 
         * @return builder
         * 
         */
        public Builder port(Output<Integer> port) {
            $.port = port;
            return this;
        }

        /**
         * @param port The port number of the website host you want to connect to via a web proxy server. For example, the port for `https://a.example.com/page1.html` is `443`, the standard port for HTTPS.
         * 
         * @return builder
         * 
         */
        public Builder port(Integer port) {
            return port(Output.of(port));
        }

        public DataSourceConfigurationWebCrawlerConfigurationProxyConfigurationArgs build() {
            $.host = Objects.requireNonNull($.host, "expected parameter 'host' to be non-null");
            $.port = Objects.requireNonNull($.port, "expected parameter 'port' to be non-null");
            return $;
        }
    }

}
