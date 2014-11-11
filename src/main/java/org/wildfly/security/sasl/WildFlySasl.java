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

import java.util.Map;

import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslServerFactory;

/**
 * The core WildFly SASL utilities.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class WildFlySasl {

    /*
     These two properties are to prevent checkstyle from raising a false positive for imports used only in JavaDoc.
     The checkstyle problem is fixed upstream.
     TODO: Remove these once checkstyle is updated to 6.1 or later.
     */
    private static final Class<?> ssf = SaslServerFactory.class;
    private static final Class<?> scf = SaslClientFactory.class;
    private static final Class<?> map = Map.class;

    /**
     * Property name to specify if the GSSAPI mechanism should support credential delegation. The property contains "true" then
     * the credential should be delegated from the client to the server, "false" otherwise. The default value is "false" unless
     * a {@link org.ietf.jgss.GSSCredential GSSCredential} was already passed in using the {@link javax.security.sasl.Sasl#CREDENTIALS CREDENTIALS} property in which case the default would
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
     * Property name for the algorithm name of a {@link java.security.SecureRandom SecureRandom} implementation to use.  Using this property can
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
     * or absence of any other query flags.  This flag is only effective on calls to {@link SaslServerFactory#getMechanismNames(Map)}
     * or {@link SaslClientFactory#getMechanismNames(Map)} for Elytron-provided SASL factories.
     */
    public static final String MECHANISM_QUERY_ALL = "wildfly.sasl.mechanism-query-all";

    /**
     * The immutable empty names array.
     */
    public static final String[] NO_NAMES = new String[0];
}
