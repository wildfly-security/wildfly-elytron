/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.sasl;

/**
 * The core WildFly SASL utilities.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class WildFlySasl {

    /**
     * Property name to specify if the GSSAPI mechanism should support credential delegation. The property contains "true" then
     * the credential should be delegated from the client to the server, "false" otherwise. The default value is "false" unless
     * a {@link org.ietf.jgss.GSSCredential} was already passed in using the {@link javax.security.sasl.Sasl#CREDENTIALS} property in which case the default would
     * be "true".
     *
     * Note: This is a client only property and is not used server side.
     */
    public static final String GSSAPI_DELEGATE_CREDENTIAL = "wildfly.sasl.gssapi.client.delegate-credential";

    /**
     * The various specifications for the SASL mechanisms mandate certain behaviour and verification of that behaviour at the
     * opposite side of the connection, unfortunately when interacting with other SASL mechanism implementations some of these
     * requirements have been interpreted loosely. If this property contains "true" then where differences in spec
     * interpretation have been identified the checking can be relaxed. The default value is "false".
     */
    public static final String RELAX_COMPLIANCE = "wildfly.sasl.relax-compliance";

    /**
     * The minimum iteration count to use for SCRAM.  Default is 4096.
     */
    public static final String SCRAM_MIN_ITERATION_COUNT = "wildfly.sasl.scram.min-iteration-count";

    /**
     * The maximum iteration count to use for SCRAM.  Default is 16384.
     */
    public static final String SCRAM_MAX_ITERATION_COUNT = "wildfly.sasl.scram.max-iteration-count";

    /**
     * Property name for the algorithm name of a {@link java.security.SecureRandom} implementation to use.  Using this property can
     * improve security, at the cost of performance.
     */
    public static final String SECURE_RNG = "wildfly.sasl.secure-rng";

    /**
     * A flag indicating that a mechanism which supports channel binding is required.  A value of "true" indicates that
     * channel binding is required; any other value (or lack of this property) indicates that channel binding is not
     * required.
     */
    public static final String CHANNEL_BINDING_REQUIRED = "wildfly.sasl.channel-binding-required";

    /**
     * A flag indicating that all possible supported mechanism names should be returned, regardless of the presence
     * or absence of any other query flags.  This flag is only effective on calls to {@link javax.security.sasl.SaslServerFactory#getMechanismNames(java.util.Map)}
     * or {@link javax.security.sasl.SaslClientFactory#getMechanismNames(java.util.Map)} for Elytron-provided SASL factories.
     */
    public static final String MECHANISM_QUERY_ALL = "wildfly.sasl.mechanism-query-all";

    /**
     * The immutable empty names array.
     */
    public static final String[] NO_NAMES = new String[0];

    /**
     * A property used by some SASL mechanisms (including the {@code DIGEST-MD5} algorithm supplied with most Oracle JDKs)
     * to indicate that information exchange should take place using the UTF-8 character encoding instead of the default
     * Latin-1/ISO-8859-1 encoding.  The default value is "true".
     */
    public static final String USE_UTF8 = "com.sun.security.sasl.digest.utf8";

    /**
     * A property used by some SASL mechanisms (including the {@code DIGEST-MD5} algorithm supplied with most Oracle JDKs)
     * to provide the list of possible server realms to the mechanism.  Each realm name should be separated by a space
     * character (U+0020).
     */
    public static final String REALM_LIST = "com.sun.security.sasl.digest.realm";

    /**
     * A property used to directly limit the set of supported ciphers for SASL mechanisms.  The list items should be
     * separated by a comma character (",").
     */
    public static final String SUPPORTED_CIPHER_NAMES = "org.jboss.security.sasl.digest.ciphers";
}
