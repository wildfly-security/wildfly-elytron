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

package org.jboss.sasl.localuser;

import org.jboss.sasl.util.AbstractSaslFactory;

/**
 * Base class for the {@code JBOSS-LOCAL-USER} SASL mechanism.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public abstract class LocalUserSaslFactory extends AbstractSaslFactory {

    public static final String JBOSS_LOCAL_USER = "JBOSS-LOCAL-USER";

    LocalUserSaslFactory() {
        super(JBOSS_LOCAL_USER);
    }

    protected boolean isPassCredentials() {
        return false;
    }

    protected boolean isDictionarySusceptible() {
        return false;
    }

    protected boolean isActiveSusceptible() {
        return false;
    }

    protected boolean isForwardSecrecy() {
        return false;
    }

    protected boolean isPlainText() {
        return true;
    }

    protected boolean isAnonymous() {
        return false;
    }
}
