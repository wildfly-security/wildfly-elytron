package org.wildfly.security.credential.source;

import static org.wildfly.common.Assert.checkNotNullParam;
import static org.wildfly.security._private.ElytronMessages.log;

import javax.json.Json;
import javax.json.JsonObject;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.security.AccessController;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;

import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.AuthenticationContextConfigurationClient;
import org.wildfly.security.credential.BearerTokenCredential;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.util.ByteStringBuilder;

/**
 * A {@link CredentialSource} capable of authenticating against a OAuth2 compliant authorization server and obtaining
 * access tokens in form of a {@link BearerTokenCredential}.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class OAuth2CredentialSource implements CredentialSource {

    /**
     * Creates a new {@link Builder} instance in order to configure and build a {@link OAuth2CredentialSource}.
     *
     * @param tokenEndpointUrl the token endpoint that will be used to obtain OAuth2 access tokens
     * @return a new builder instance
     */
    public static Builder builder(URL tokenEndpointUrl) {
        return new Builder(tokenEndpointUrl);
    }

    private final String grantType;
    private final URL tokenEndpointUri;
    private final Consumer<Map<String, String>> consumer;
    private String scopes;
    private final Supplier<SSLContext> sslContextSupplier;
    private final Supplier<HostnameVerifier> hostnameVerifierSupplier;

    /**
     * Creates a new instance.
     *
     * @param grantType the OAuth2 grant type as defined by the specification
     * @param tokenEndpointUri the OAuth2 Token Endpoint {@link URI}
     * @param scopes a string with the scope of the access request
     * @param sslContextSupplier a supplier from where the {@link SSLContext} is obtained in case the token endpoint is using TLS/HTTPS
     * @param hostnameVerifierSupplier a supplier from where the {@link HostnameVerifier} is obtained in case the token endpoint is using TLS/HTTPS
     */
    private OAuth2CredentialSource(String grantType, URL tokenEndpointUri, String scopes, Supplier<SSLContext> sslContextSupplier, Supplier<HostnameVerifier> hostnameVerifierSupplier) {
        this(grantType, tokenEndpointUri, stringStringMap -> {}, scopes, sslContextSupplier, hostnameVerifierSupplier);
    }

    /**
     * Creates a new instance.
     *
     * @param grantType the OAuth2 grant type as defined by the specification
     * @param tokenEndpointUrl the OAuth2 Token Endpoint {@link URL}
     * @param consumer a callback that can be used to push addition parameters to requests sent to the authorization server
     * @param scopes a string with the scope of the access request
     * @param sslContextSupplier a supplier from where the {@link SSLContext} is obtained in case the token endpoint is using TLS/HTTPS
     * @param hostnameVerifierSupplier a supplier from where the {@link HostnameVerifier} is obtained in case the token endpoint is using TLS/HTTPS
     */
    private OAuth2CredentialSource(String grantType, URL tokenEndpointUrl, Consumer<Map<String, String>> consumer, String scopes, Supplier<SSLContext> sslContextSupplier, Supplier<HostnameVerifier> hostnameVerifierSupplier) {
        this.grantType = checkNotNullParam("grantType", grantType);
        this.tokenEndpointUri = checkNotNullParam("tokenEndpointUri", tokenEndpointUrl);

        if (isHttps(tokenEndpointUrl)) {
            checkNotNullParam("sslContextSupplier", sslContextSupplier);
        }

        this.consumer = consumer;
        this.scopes = scopes;
        this.sslContextSupplier = sslContextSupplier;
        this.hostnameVerifierSupplier = hostnameVerifierSupplier;
    }

    @Override
    public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName, AlgorithmParameterSpec parameterSpec) throws IOException {
        return getCredential(credentialType, algorithmName, parameterSpec) != null ? SupportLevel.SUPPORTED : SupportLevel.UNSUPPORTED;
    }

    @Override
    public <C extends Credential> C getCredential(Class<C> credentialType, String algorithmName, AlgorithmParameterSpec parameterSpec) throws IOException {
        if (credentialType.isAssignableFrom(credentialType)) {
            try {
                HttpURLConnection connection = null;

                try {
                    connection = openConnection();
                    connection.setDoOutput(true);
                    connection.setRequestMethod("POST");
                    connection.setInstanceFollowRedirects(false);

                    connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

                    HashMap<String, String> parameters = new HashMap<>();

                    parameters.put("grant_type", grantType);
                    consumer.accept(parameters);

                    if (scopes != null) {
                        parameters.put("scope", scopes);
                    }

                    byte[] paramBytes = buildParameters(parameters);

                    try (OutputStream outputStream = connection.getOutputStream()) {
                        outputStream.write(paramBytes);
                    }

                    try (InputStream inputStream = new BufferedInputStream(connection.getInputStream())) {
                        JsonObject jsonObject = Json.createReader(inputStream).readObject();
                        String accessToken = jsonObject.getString("access_token");
                        return credentialType.cast(new BearerTokenCredential(accessToken));
                    }
                } catch (IOException ioe) {
                    InputStream errorStream = null;

                    if (connection != null && connection.getErrorStream() != null) {
                        errorStream = connection.getErrorStream();

                        try (BufferedReader reader = new BufferedReader(new InputStreamReader(errorStream))) {
                            StringBuffer response = reader.lines().reduce(new StringBuffer(), StringBuffer::append, (buffer1, buffer2) -> buffer1);
                            log.errorf(ioe, "Unexpected response from server [%s]. Response: [%s]", tokenEndpointUri, response);
                        } catch (IOException ignore) {
                        }
                    }

                    throw log.mechUnableToHandleResponseFromServer("OAuth2CredentialSource", ioe);
                }
            } catch (Exception cause) {
                throw log.mechCallbackHandlerFailedForUnknownReason("OAuth2CredentialSource", cause);
            }
        }

        return null;
    }

    private SSLContext resolveSSLContext() {
        if (!isHttps(tokenEndpointUri)) {
            return null;
        }
        return sslContextSupplier == null ? null : sslContextSupplier.get();
    }

    private HttpURLConnection openConnection() throws IOException {
        log.debugf("Opening connection to [%s]", tokenEndpointUri);
        HttpURLConnection connection = (HttpURLConnection) tokenEndpointUri.openConnection();

        if (isHttps(tokenEndpointUri)) {
            HttpsURLConnection https = (HttpsURLConnection) connection;

            https.setSSLSocketFactory(resolveSSLContext().getSocketFactory());
            if (hostnameVerifierSupplier != null) {
                https.setHostnameVerifier(checkNotNullParam("hostnameVerifier", hostnameVerifierSupplier.get()));
            }
        }

        return connection;
    }

    private byte[] buildParameters(Map<String, String> parameters) {
        ByteStringBuilder params = new ByteStringBuilder();

        parameters.entrySet().stream().forEach(entry -> {
            if (params.length() > 0) {
                params.append('&');
            }
            params.append(entry.getKey()).append('=').append(entry.getValue());
        });

        return params.toArray();
    }

    private boolean isHttps(URL tokenEndpointUrl) {
        return "https".equals(tokenEndpointUrl.getProtocol());
    }

    public static class Builder {

        private final URL tokenEndpointUrl;
        private Function<Builder, OAuth2CredentialSource> grantType;
        private String scopes;
        private Supplier<SSLContext> sslContextSupplier = new Supplier<SSLContext>() {
            @Override
            public SSLContext get()  {
                AuthenticationContextConfigurationClient contextConfigurationClient = AccessController.doPrivileged(AuthenticationContextConfigurationClient.ACTION);
                try {
                    return contextConfigurationClient.getSSLContext(tokenEndpointUrl.toURI(), AuthenticationContext.captureCurrent());
                } catch (Exception cause) {
                    throw log.failedToObtainSSLContext(cause);
                }
            }
        };
        private Supplier<HostnameVerifier> hostnameVerifierSupplier;

        private Builder(URL tokenEndpointUrl) {
            this.tokenEndpointUrl = checkNotNullParam("tokenEndpointUrl", tokenEndpointUrl);
            this.grantType = builder -> new OAuth2CredentialSource("client_credentials", tokenEndpointUrl, builder.scopes, builder.sslContextSupplier, builder.hostnameVerifierSupplier);
        }

        /**
         * The scopes to grant access.
         *
         * @param scopes the scopes to grant access.
         * @return this instance
         */
        public Builder grantScopes(String scopes) {
            this.scopes = checkNotNullParam("scopes", scopes);
            return this;
        }

        /**
         * <p>Configure OAuth2 Resource Owner Password Grant Type as defined by the OAuth2 specification.
         *
         * @param userName the resource owner's user name
         * @param password the resource owner's password
         * @return this instance.
         */
        public Builder useResourceOwnerPassword(String userName, String password) {
            grantType = builder -> new OAuth2CredentialSource("password", tokenEndpointUrl, parameters -> {
                parameters.put("username", userName);
                parameters.put("password", password);
            }, builder.scopes, builder.sslContextSupplier, builder.hostnameVerifierSupplier);
            return this;
        }

        /**
         * TThe {@link SSLContext} to be used in case connections to remote server require TLS/HTTPS.
         *
         * @param sslContext the SSLContext
         * @return this instance
         */
        public Builder useSslContext(SSLContext sslContext) {
            checkNotNullParam("sslContext", sslContext);
            sslContextSupplier = () -> sslContext;
            return this;
        }

        /**
         * TThe {@link HostnameVerifier} to be used in case connections to remote server require TLS/HTTPS.
         *
         * @param hostnameVerifier the HostnameVerifier
         * @return this instance
         */
        public Builder useSslHostnameVerifier(HostnameVerifier hostnameVerifier) {
            checkNotNullParam("hostnameVerifier", hostnameVerifier);
            this.hostnameVerifierSupplier = () -> hostnameVerifier;
            return this;
        }

        /**
         * Creates a new {@link OAuth2CredentialSource} instance.
         *
         * @return a OAuth2 credential source
         */
        public OAuth2CredentialSource build() {
            return grantType.apply(this);
        }
    }
}