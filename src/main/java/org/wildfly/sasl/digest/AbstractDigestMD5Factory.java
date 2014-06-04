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

package org.wildfly.sasl.digest;

import org.wildfly.sasl.util.AbstractSaslFactory;

/**
 * The abstract factory for the digest SASL mechanisms.
 * 
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public abstract class AbstractDigestMD5Factory extends AbstractSaslFactory {

    /**
     * The name of this mechanism.
     */
    public static final String DIGEST_MD5 = "DIGEST-MD5";

    /**
     * Construct a new instance.
     */
    public AbstractDigestMD5Factory() {
        super(DIGEST_MD5);
    }

    protected boolean isAnonymous() {
        return false;
    }

    protected boolean isPlainText() {
        return false;
    }

}
