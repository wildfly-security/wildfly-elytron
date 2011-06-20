/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2011, Red Hat, Inc., and individual contributors
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

package org.jboss.sasl.digest;

import javax.security.sasl.SaslException;

/**
  * Interface used for classes implementing integrity checking and privacy
  * for DIGEST-MD5 SASL mechanism implementation.
  *
  * @see <a href="http://www.ietf.org/rfc/rfc2831.txt">RFC 2831</a>
  * - Using Digest Authentication as a SASL Mechanism
  *
  * @author Jonathan Bruce
  */

interface SecurityCtx {

    /**
     * Wrap out-going message and return wrapped message
     *
     * @throws javax.security.sasl.SaslException
     */
    byte[] wrap(byte[] dest, int start, int len)
        throws SaslException;

    /**
     * Unwrap incoming message and return original message
     *
     * @throws javax.security.sasl.SaslException
     */
    byte[] unwrap(byte[] outgoing, int start, int len)
        throws SaslException;
}
