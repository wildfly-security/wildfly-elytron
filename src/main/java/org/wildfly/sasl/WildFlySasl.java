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

package org.wildfly.sasl;

import java.security.SecureRandom;

import javax.security.sasl.Sasl;

import org.ietf.jgss.GSSCredential;

/**
 * The core WildFly SASL utilities.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class WildFlySasl {

    /**
     * Property name to specify if the GSSAPI mechanism should support credential delegation. The property contains "true" then
     * the credential should be delegated from the client to the server, "false" otherwise. The default value is "false" unless
     * a {@link GSSCredential} was already passed in using the {@link Sasl.CREDENTIALS} property in which case the defailt would
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
     * Property name for the algorithm name of a {@link SecureRandom} implementation to use.  Using this property can
     * improve security, at the cost of performance.
     */
    public static final String SECURE_RNG = "wildfly.sasl.secure-rng";

    /**
     * Property name for indicating a channel binding type to use.  Can also be read as a negotiated property indicating
     * the type of binding which was negotiated, or {@code null} if no channel binding was negotiated.
     */
    public static final String CHANNEL_BINDING_TYPE = "wildfly.sasl.channel-binding.type";

    /**
     * Property name for indicating the channel binding data (specific to a particular channel binding type).
     */
    public static final String CHANNEL_BINDING_DATA = "wildfly.sasl.channel-binding.data";

    /**
     * The channel binding mode to use.  Property value is a {@link String}.  Possible values are:<ul>
     *     <li>{@code required} - Only mechanisms supporting channel binding should be selected, and authentication
     *     should fail of channel binding is not performed.</li>
     *     <li>{@code allowed} - Mechanisms supporting channel binding should be allowed, and channel binding should
     *     be performed whenever possible.  This is the default if channel binding type and data are provided.</li>
     *     <li>{@code forbidden} - Channel binding should not be performed.  If no channel binding type and data are
     *     provided, this mode is always selected regardless of the value of this property.</li>
     * </ul>
     */
    public static final String CHANNEL_BINDING_MODE = "wildfly.sasl.channel-binding.mode";

    /**
     * Channel binding mode of "required".
     */
    public static final String CBM_REQUIRED = "required";
    /**
     * Channel binding mode of "allowed".
     */
    public static final String CBM_ALLOWED = "allowed";
    /**
     * Channel binding mode of "forbidden".
     */
    public static final String CBM_FORBIDDEN = "forbidden";
}
