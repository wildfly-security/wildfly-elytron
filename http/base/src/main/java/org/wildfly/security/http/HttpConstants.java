/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wildfly.security.http;

import org.ietf.jgss.GSSManager;

/**
 * Constants used within HTTP based authentication.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class HttpConstants {


    private HttpConstants() {
    }

    /*
     * Negotiated Properties
     */

    /**
     * The property which holds the negotiated security identity after a successful HTTP server-side authentication.
     */
    public static final String SECURITY_IDENTITY = "wildfly.http.security-identity";

    /*
     * Mechanism Configuration Properties
     */

    private static final String CONFIG_BASE = HttpConstants.class.getPackage().getName();
    public static final String CONFIG_CONTEXT_PATH = CONFIG_BASE + ".context-path";
    public static final String CONFIG_REALM = CONFIG_BASE + ".realm";

    public static final String CONFIG_VALIDATE_DIGEST_URI = CONFIG_BASE + ".validate-digest-uri";
    public static final String CONFIG_SKIP_CERTIFICATE_VERIFICATION = CONFIG_BASE + ".skip-certificate-verification";

    /**
     * The context relative path of the login page.
     */
    public static final String CONFIG_LOGIN_PAGE = CONFIG_BASE + ".login-page";

    /**
     * The context relative path of the error page.
     */
    public static final String CONFIG_ERROR_PAGE = CONFIG_BASE + ".error-page";

    /**
     * This defines the location used by mechanisms dependent on the response to the challenge being sent in using 'POST'.
     */
    public static final String CONFIG_POST_LOCATION = CONFIG_BASE + ".post-location";

    /**
     * This allows a {@link GSSManager} instance to be passed into the authentication mechanisms.
     */
    public static final String CONFIG_GSS_MANAGER = CONFIG_BASE + ".gss-manager";

    /**
     * This enables workaround for native GSS, where createName() needs to be called for correct GSSContext initialization.
     * Set to "true" to call createName() as part of GSSContext initialization.
     * This is workaround of JDK-8194073.
     */
    public static final String CONFIG_CREATE_NAME_GSS_INIT = CONFIG_BASE + ".create-name-gss-init";

    /**
     * In clustered environment Security Identity is restored during failover, load balancer change node (not sticky behavior) and session passivation/activation.
     * Set to "true" to disable this behavior.
     */
    public static final String CONFIG_DISABLE_RESTORE_SECURITY_IDENTITY = CONFIG_BASE + ".disable-restore-security-identity";

    /**
     * A comma separated list of scopes in preferred order the mechanism should attempt to use to persist state including the
     * caching of any previously authenticated identity.
     *
     * Accepted values are: -
     * <p><ul>
     * <li>CONNECTION
     * <li>SESSION
     * <li>SSL_SESSION
     * <li>NONE
     * </ul></p>
     *
     * Presently only supported by the SPNEGO mechanism.
     */
    public static final String CONFIG_STATE_SCOPES = CONFIG_BASE + ".state-scopes";

    /*
     * Header Fields
     */
    public static final String ALGORITHM = "algorithm";
    public static final String AUTH = "auth";
    public static final String AUTH_PARAM = "auth-param";
    public static final String CHARSET = "charset";
    public static final String CNONCE = "cnonce";
    public static final String DOMAIN = "domain";
    public static final String NC = "nc";
    public static final String NEGOTIATE = "Negotiate";
    public static final String NEXT_NONCE = "nextnonce";
    public static final String NONCE = "nonce";
    public static final String OPAQUE = "opaque";
    public static final String QOP = "qop";
    public static final String REALM = "realm";
    public static final String RSPAUTH = "rspauth";
    public static final String RESPONSE = "response";
    public static final String STALE = "stale";
    public static final String URI = "uri";
    public static final String USERNAME = "username";
    public static final String USERNAME_STAR = "username*";

    /*
     * Header Names
     */

    public static final String AUTHENTICATION_INFO = "Authentication-Info";
    public static final String AUTHORIZATION = "Authorization";
    public static final String HOST = "Host";
    public static final String LOCATION = "Location";
    public static final String WWW_AUTHENTICATE = "WWW-Authenticate";

    /*
     * Mechanism Names
     */

    public static final String BASIC_NAME = "BASIC";
    public static final String CLIENT_CERT_NAME = "CLIENT_CERT";
    public static final String DIGEST_NAME = "DIGEST";
    public static final String DIGEST_SHA256_NAME = "DIGEST-SHA-256";
    public static final String DIGEST_SHA512_256_NAME = "DIGEST-SHA-512-256";
    public static final String EXTERNAL_NAME = "EXTERNAL";
    public static final String FORM_NAME = "FORM";
    public static final String SPNEGO_NAME = "SPNEGO";
    public static final String BEARER_TOKEN = "BEARER_TOKEN";

    /*
     * Response Codes
     */

    public static final int OK = 200;
    public static final int FOUND = 302;
    public static final int SEE_OTHER = 303;
    public static final int TEMPORARY_REDIRECT = 307;
    public static final int BAD_REQUEST = 400;
    public static final int UNAUTHORIZED = 401;
    public static final int FORBIDDEN = 403;

    /*
     * Methods
     */

    public static final String POST = "POST";

    /*
     * Algorithms
     */

    public static final String MD5 = "MD5";
    public static final String SHA256 = "SHA-256";
    public static final String SHA512_256 = "SHA-512-256";

    /*
     * Schemes
     */

    public static final String HTTP = "http";
    public static final String HTTPS = "https";

}
