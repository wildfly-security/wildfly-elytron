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

import java.util.Map;
import org.jboss.sasl.util.AbstractSaslFactory;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class DigestMD5ServerFactory extends AbstractSaslFactory implements SaslServerFactory {

    /**
     * The name of this mechanism.
     */
    public static final String DIGEST_MD5 = "DIGEST-MD5";

    /**
     * Construct a new instance.
     */
    public DigestMD5ServerFactory() {
        super(DIGEST_MD5);
    }

    public SaslServer createSaslServer(final String mechanism, final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
        if (DIGEST_MD5.equals(mechanism) == false || matches(props) == false) {
            return null;
        }

        return new DigestMD5Server(protocol, serverName, props, cbh);
    }

    protected boolean isAnonymous() {
        return false;
    }

    protected boolean isPlainText() {
        return false;
    }
}
