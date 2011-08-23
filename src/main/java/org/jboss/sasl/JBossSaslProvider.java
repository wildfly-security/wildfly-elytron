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

package org.jboss.sasl;

import static org.jboss.sasl.anonymous.AbstractAnonymousFactory.ANONYMOUS;
import static org.jboss.sasl.plain.PlainServerFactory.PLAIN;
import static org.jboss.sasl.digest.DigestMD5ServerFactory.DIGEST_MD5;
import static org.jboss.sasl.clienttoken.ClientTokenClientFactory.JBOSS_CLIENTTOKEN;

import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslServerFactory;
import java.security.Provider;

import org.jboss.sasl.anonymous.AnonymousClientFactory;
import org.jboss.sasl.anonymous.AnonymousServerFactory;
import org.jboss.sasl.clienttoken.ClientTokenClientFactory;
import org.jboss.sasl.digest.DigestMD5ServerFactory;
import org.jboss.sasl.plain.PlainServerFactory;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public final class JBossSaslProvider extends Provider {

    private static final long serialVersionUID = 7613128233053194670L;

    private static final String SASL_CLIENT_FACTORY = SaslClientFactory.class.getSimpleName();

    private static final String SASL_SERVER_FACTORY = SaslServerFactory.class.getSimpleName();

    private static final String DOT = ".";

    /**
     * Construct a new instance.
     */
    public JBossSaslProvider() {
        super("jboss-sasl", 1.0, "JBoss SASL Provider");
        put(SASL_CLIENT_FACTORY + DOT + ANONYMOUS, AnonymousClientFactory.class.getName());
        put(SASL_SERVER_FACTORY + DOT + ANONYMOUS, AnonymousServerFactory.class.getName());
        put(SASL_SERVER_FACTORY + DOT + PLAIN, PlainServerFactory.class.getName());
        //put(SASL_SERVER_FACTORY + "." + DIGEST_MD5, DigestMD5ServerFactory.class.getName());
        //put(SASL_CLIENT_FACTORY + "." + JBOSS_CLIENTTOKEN, ClientTokenClientFactory.class.getName());
    }
}
