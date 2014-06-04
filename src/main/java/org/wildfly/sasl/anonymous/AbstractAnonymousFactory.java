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

package org.wildfly.sasl.anonymous;

import org.wildfly.sasl.util.AbstractSaslFactory;

/**
 * A base class for the anonymous factories to verify from the properties supplied if anonymous
 * can be used.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public abstract class AbstractAnonymousFactory extends AbstractSaslFactory {

    /**
     * The name of the ANONYMOUS SASL mechanism.
     */
    public static final String ANONYMOUS = "ANONYMOUS";

    /**
     * Construct a new instance.
     */
    protected AbstractAnonymousFactory() {
        super(ANONYMOUS);
    }

    protected boolean isDictionarySusceptible() {
        return false;
    }

    protected boolean isPlainText() {
        return false;
    }
}
