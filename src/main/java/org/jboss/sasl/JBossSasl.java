/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.jboss.sasl;

import java.security.SecureRandom;

/**
 * The core JBoss SASL utilities.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class JBossSasl {

    /**
     * The minimum iteration count to use for SCRAM.  Default is 4096.
     */
    public static final String SCRAM_MIN_ITERATION_COUNT = "jboss.sasl.scram.min-iteration-count";

    /**
     * The maximum iteration count to use for SCRAM.  Default is 16384.
     */
    public static final String SCRAM_MAX_ITERATION_COUNT = "jboss.sasl.scram.max-iteration-count";

    /**
     * Property name for the algorithm name of a {@link SecureRandom} implementation to use.  Using this property can
     * improve security, at the cost of performance.
     */
    public static final String SECURE_RNG = "jboss.sasl.secure-rng";

    /**
     * Property name for indicating a channel binding type to use.  Can also be read as a negotiated property indicating
     * the type of binding which was negotiated, or {@code null} if no channel binding was negotiated.
     */
    public static final String CHANNEL_BINDING_TYPE = "jboss.sasl.channel-binding.type";

    /**
     * Property name for indicating the channel binding data (specific to a particular channel binding type).
     */
    public static final String CHANNEL_BINDING_DATA = "jboss.sasl.channel-binding.data";

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
    public static final String CHANNEL_BINDING_MODE = "jboss.sasl.channel-binding.mode";

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
