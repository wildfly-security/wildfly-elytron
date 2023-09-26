/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2020 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wildfly.security.http.oidc;

import static org.wildfly.security.http.oidc.ElytronMessages.log;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Map;
import java.util.StringTokenizer;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpRequestBase;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.wildfly.security.jose.util.JsonSerialization;

/**
 * Constants and utility methods related to the OpenID Connect HTTP mechanism.
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class Oidc {

    public static final String ACCEPT = "Accept";
    public static final String OIDC_NAME = "OIDC";
    public static final String JSON_CONTENT_TYPE = "application/json";
    public static final String HTML_CONTENT_TYPE = "text/html";
    public static final String WILDCARD_CONTENT_TYPE = "*/*";
    public static final String TEXT_CONTENT_TYPE = "text/*";
    public static final String DISCOVERY_PATH = ".well-known/openid-configuration";
    public static final String KEYCLOAK_REALMS_PATH = "realms/";
    public static final String KEYSTORE_PASS = "password";
    public static final String JKS_KEYSTORE_TYPE = "JKS";
    public static final String JSON_CONFIG_CONTEXT_PARAM = "org.wildfly.security.http.oidc.json.config";
    static final String ACCOUNT_PATH = "account";
    public static final String CLIENTS_MANAGEMENT_REGISTER_NODE_PATH = "clients-managements/register-node";
    public static final String CLIENTS_MANAGEMENT_UNREGISTER_NODE_PATH = "clients-managements/unregister-node";
    public static final String ADMIN_CONSOLE_PATH = "admin/master/console/#";
    public static final String REALM_SETTING_KEYS_PATH = "realm-settings/keys";
    public static final String SLASH = "/";
    public static final String OIDC_CLIENT_CONTEXT_KEY = OidcClientContext.class.getName();
    public static final String CLIENT_ID = "client_id";
    public static final String CODE = "code";
    public static final String ERROR = "error";
    public static final String ERROR_DESCRIPTION = "error_description";
    public static final String FACES_REQUEST = "Faces-Request";
    public static final String GRANT_TYPE = "grant_type";
    public static final String INVALID_TOKEN = "invalid_token";
    public static final String LOGIN_HINT = "login_hint";
    public static final String DOMAIN_HINT = "domain_hint";
    public static final String MAX_AGE = "max_age";
    public static final String NO_TOKEN = "no_token";
    public static final String OPTIONS = "OPTIONS";
    public static final String PARTIAL = "partial/";
    public static final String PASSWORD = "password";
    public static final String PROMPT = "prompt";
    public static final String REQUEST = "request";
    public static final String REQUEST_URI = "request_uri";
    public static final String SCOPE = "scope";
    public static final String UI_LOCALES = "ui_locales";
    public static final String USERNAME = "username";
    public static final String OIDC_SCOPE = "openid";
    public static final String REDIRECT_URI = "redirect_uri";
    public static final String REFRESH_TOKEN = "refresh_token";
    public static final String REQUEST_TYPE_OAUTH2 = "oauth2";
    public static final String REQUEST_TYPE_REQUEST = "request";
    public static final String REQUEST_TYPE_REQUEST_URI = "request_uri";
    public static final String RESPONSE_TYPE = "response_type";
    public static final String SESSION_STATE = "session_state";
    public static final String SOAP_ACTION = "SOAPAction";
    public static final String STALE_TOKEN = "Stale token";
    public static final String STATE = "state";
    public static final int INVALID_ISSUED_FOR_CLAIM = -1;
    public static final int INVALID_AT_HASH_CLAIM = -2;
    public static final int INVALID_TYPE_CLAIM = -3;
    static final String OIDC_CLIENT_CONFIG_RESOLVER = "oidc.config.resolver";
    static final String OIDC_CONFIG_FILE_LOCATION = "oidc.config.file";
    static final String OIDC_JSON_FILE = "/WEB-INF/oidc.json";
    static final String AUTHORIZATION = "authorization";
    static final String AUTHORIZATION_CODE = "authorization_code";
    static final String CLIENT_ASSERTION_TYPE = "client_assertion_type";
    static final String CLIENT_ASSERTION = "client_assertion";
    static final String CLIENT_ASSERTION_TYPE_JWT = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    static final String RS256 = "SHA256withRSA";
    static final String RS384 = "SHA384withRSA";
    static final String RS512 = "SHA512withRSA";
    static final String HS256 = "HMACSHA256";
    static final String HS384 = "HMACSHA384";
    static final String HS512 = "HMACSHA512";
    static final String ES256 = "SHA256withECDSA";
    static final String ES384 = "SHA384withECDSA";
    static final String ES512 = "SHA512withECDSA";
    public static final String SHA256 = "SHA-256";
    public static final String SHA384 = "SHA-384";
    public static final String SHA512 = "SHA-512";
    static final String PROTOCOL_CLASSPATH = "classpath:";
    static final String OIDC_STATE_COOKIE = "OIDC_STATE";
    static final String KEYCLOAK_CLIENT_CLUSTER_HOST = "client_cluster_host";
    static final String KEYCLOAK_QUERY_BEARER_TOKEN = "k_query_bearer_token";
    static final String DEFAULT_TOKEN_SIGNATURE_ALGORITHM = "RS256";
    public static final String DISABLE_TYP_CLAIM_VALIDATION_PROPERTY_NAME = "wildfly.elytron.oidc.disable.typ.claim.validation";
    public static final String X_REQUESTED_WITH = "X-Requested-With";
    public static final String XML_HTTP_REQUEST = "XMLHttpRequest";

    /* Accepted Request Object Signing Algorithms for KeyCloak*/
    public static final String NONE = "none";
    public static final String RS_256 = "RS256";
    public static final String HS_256 = "HS256";
    public static final String HS_384 = "HS384";
    public static final String HS_512 = "HS512";
    public static final String ES_256 = "ES256";
    public static final String ES_384 = "ES384";
    public static final String ES_512 = "ES512";
    public static final String ES_256K = "ES256K";
    public static final String RS_384 = "RS384";
    public static final String RS_512 = "RS512";
    public static final String PS_256 = "PS256";
    public static final String PS_384 = "PS384";
    public static final String PS_512 = "PS512";

    /* Accepted Request Object Encrypting Algorithms for KeyCloak*/
    public static final String RSA_OAEP = "RSA-OAEP";
    public static final String RSA_OAEP_256 = "RSA-OAEP-256";
    public static final String RSA1_5 = "RSA1_5";

    /* Accepted Request Object Encryption Methods for KeyCloak*/
    public static final String A256GCM = "A256GCM";
    public static final String A192GCM = "A192GCM";
    public static final String A128GCM = "A128GCM";
    public static final String A128CBC_HS256 = "A128CBC-HS256";
    public static final String A192CBC_HS384 = "A192CBC-HS384";
    public static final String A256CBC_HS512 = "A256CBC-HS512";

    /**
     * Bearer token pattern.
     * The Bearer token authorization header is of the form "Bearer", followed by optional whitespace, followed by
     * the token itself, followed by optional whitespace. The token itself must be one or more characters and must
     * not contain any whitespace.
     */
    public static final Pattern BEARER_TOKEN_PATTERN = Pattern.compile("^Bearer *([^ ]+) *$", Pattern.CASE_INSENSITIVE);


    // keycloak-specific request parameter used to specify the identifier of the identity provider that should be used to authenticate a user
    public static final String KC_IDP_HINT = "kc_idp_hint";

   static <T> T sendJsonHttpRequest(OidcClientConfiguration oidcClientConfiguration, HttpRequestBase httpRequest, Class<T> clazz) throws OidcException {
        try {
            HttpResponse response = oidcClientConfiguration.getClient().execute(httpRequest);
            int status = response.getStatusLine().getStatusCode();
            if (status != 200) {
                close(response);
                throw log.unexpectedResponseCodeFromOidcProvider(status);
            }
            HttpEntity entity = response.getEntity();
            if (entity == null) {
                throw log.noEntityInResponse();
            }
            InputStream is = entity.getContent();
            try {
                return JsonSerialization.readValue(is, clazz);
            } finally {
                try {
                    is.close();
                } catch (IOException ignored) {

                }
            }
        } catch (IOException e) {
            throw log.unexpectedErrorSendingRequestToOidcProvider(e);
        }
    }

    private static void close(HttpResponse response) {
        if (response.getEntity() != null) {
            try {
                response.getEntity().getContent().close();
            } catch (IOException e) {

            }
        }
    }

    public enum SSLRequired {

        ALL,
        EXTERNAL,
        NONE;

        public boolean isRequired(String address) {
            switch (this) {
                case ALL:
                    return true;
                case NONE:
                    return false;
                case EXTERNAL:
                    return !isLocal(address);
                default:
                    return true;
            }
        }

        private boolean isLocal(String remoteAddress) {
            try {
                InetAddress inetAddress = InetAddress.getByName(remoteAddress);
                return inetAddress.isAnyLocalAddress() || inetAddress.isLoopbackAddress() || inetAddress.isSiteLocalAddress();
            } catch (UnknownHostException e) {
                return false;
            }
        }
    }

    public enum TokenStore {
        SESSION,
        COOKIE
    }

    public enum ClientCredentialsProviderType {
        SECRET("secret"),
        JWT("jwt"),
        SECRET_JWT("secret-jwt")
        ;

        private final String value;

        private ClientCredentialsProviderType(final String value) {
            this.value = value;
        }

        /**
         * Get the string value for this referral mode.
         *
         * @return the string value for this referral mode
         */
        public String getValue() {
            return value;
        }

    }

    /**
     * Replaces any ${} strings with their corresponding system property.
     *
     * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
     * @version $Revision: 1 $
     */
    public static final class EnvUtil {
        private static final Pattern p = Pattern.compile("[$][{]([^}]+)[}]");

        private EnvUtil() {

        }

        /**
         * Replaces any ${} strings with their corresponding system property.
         *
         * @param val
         * @return
         */
        public static String replace(String val) {
            Matcher matcher = p.matcher(val);
            StringBuffer buf = new StringBuffer();
            while (matcher.find()) {
                String envVar = matcher.group(1);
                String envVal = System.getProperty(envVar);
                if (envVal == null) envVal = "NOT-SPECIFIED";
                matcher.appendReplacement(buf, envVal.replace("\\", "\\\\"));
            }
            matcher.appendTail(buf);
            return buf.toString();
        }
    }


    public static String getJavaAlgorithm(String algorithm) {
        switch (algorithm) {
            case AlgorithmIdentifiers.RSA_USING_SHA256:
                return RS256;
            case AlgorithmIdentifiers.RSA_USING_SHA384:
                return RS384;
            case AlgorithmIdentifiers.RSA_USING_SHA512:
                return RS512;
            case AlgorithmIdentifiers.HMAC_SHA256:
                return HS256;
            case AlgorithmIdentifiers.HMAC_SHA384:
                return HS384;
            case AlgorithmIdentifiers.HMAC_SHA512:
                return HS512;
            case AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256:
                return ES256;
            case AlgorithmIdentifiers.ECDSA_USING_P384_CURVE_AND_SHA384:
                return ES384;
            case AlgorithmIdentifiers.ECDSA_USING_P521_CURVE_AND_SHA512:
                return ES512;
            case AlgorithmIdentifiers.NONE:
                return NONE;
            default:
                throw log.unknownAlgorithm(algorithm);
        }
    }

    public static String getJavaAlgorithmForHash(String algorithm) {
        switch (algorithm) {
            case AlgorithmIdentifiers.RSA_USING_SHA256:
                return SHA256;
            case AlgorithmIdentifiers.RSA_USING_SHA384:
                return SHA384;
            case AlgorithmIdentifiers.RSA_USING_SHA512:
                return SHA512;
            case AlgorithmIdentifiers.HMAC_SHA256:
                return SHA256;
            case AlgorithmIdentifiers.HMAC_SHA384:
                return SHA384;
            case AlgorithmIdentifiers.HMAC_SHA512:
                return SHA512;
            case AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256:
                return SHA256;
            case AlgorithmIdentifiers.ECDSA_USING_P384_CURVE_AND_SHA384:
                return SHA384;
            case AlgorithmIdentifiers.ECDSA_USING_P521_CURVE_AND_SHA512:
                return SHA512;
            default:
                throw log.unknownAlgorithm(algorithm);
        }
    }

    public enum AuthOutcome {
        NOT_ATTEMPTED, FAILED, AUTHENTICATED, NOT_AUTHENTICATED, LOGGED_OUT
    }

    public static String generateId() {
        return UUID.randomUUID().toString();
    }

    static int getCurrentTimeInSeconds() {
        return ((int) (System.currentTimeMillis() / 1000));
    }

    static Integer asInt(Map<String, Object> cfg, String cfgKey, int defaultValue) {
        Object cfgObj = cfg.get(cfgKey);
        if (cfgObj == null) {
            return defaultValue;
        }
        if (cfgObj instanceof String) {
            return Integer.parseInt(cfgObj.toString());
        } else if (cfgObj instanceof Number) {
            return ((Number) cfgObj).intValue();
        } else {
            throw log.unableToParseKeyWithValue(cfgKey, cfgObj);
        }
    }

    public static String getQueryParamValue(OidcHttpFacade facade, String paramName) {
        return facade.getRequest().getQueryParamValue(paramName);
    }

    protected static String stripQueryParam(String url, String paramName){
        return url.replaceFirst("[\\?&]" + paramName + "=[^&]*$|" + paramName + "=[^&]*&", "");
    }

    public static boolean isOpaqueToken(String token) {
        return new StringTokenizer(token, ".").countTokens() != 3;
    }

    public static void logToken(String name, String token) {
        if (token == null || isOpaqueToken(token)) {
            log.tracef("\t%s: %s", name, token);
        } else {
            log.tracef("\t%s: %s", name, token.substring(0, token.lastIndexOf(".")) + ".signature");
        }
    }

}
