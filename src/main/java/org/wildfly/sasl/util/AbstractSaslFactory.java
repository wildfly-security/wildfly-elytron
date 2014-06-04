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

package org.wildfly.sasl.util;

import java.util.Map;

import javax.security.sasl.Sasl;

/**
 * Abstract SASL factory base class.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public abstract class AbstractSaslFactory {

    static final String[] EMPTY = new String[0];

    private final String[] names;

    /**
     * Construct a new instance.
     *
     * @param name the mechanism name
     */
    protected AbstractSaslFactory(final String name) {
        names = new String[] { name };
    }

    /**
     * Get the mechanism names matching the given properties.
     *
     * @param props the properties
     * @return the mechanism names
     */
    public String[] getMechanismNames(Map<String, ?> props) {
        if (matches(props)) {
            return names;
        } else {
            return EMPTY;
        }
    }

    /**
     * Determine whether the properties match this mechanism.
     *
     * @param props the properties
     *
     * @return {@code true} if there is a match, {@code false} otherwise
     */
    protected boolean matches(final Map<String, ?> props) {
        return  ! (getPropertyValue(Sasl.POLICY_NOPLAINTEXT, props, false) && isPlainText()
                || getPropertyValue(Sasl.POLICY_NOANONYMOUS, props, false) && isAnonymous()
                || getPropertyValue(Sasl.POLICY_FORWARD_SECRECY, props, false) && ! isForwardSecrecy()
                || getPropertyValue(Sasl.POLICY_NOACTIVE, props, false) && isActiveSusceptible()
                || getPropertyValue(Sasl.POLICY_NODICTIONARY, props, false) && isDictionarySusceptible()
                || getPropertyValue(Sasl.POLICY_PASS_CREDENTIALS, props, false) && ! isPassCredentials());
    }

    /**
     * Determine whether the mechanism passes client credentials.
     *
     * @return {@code true} if it does (default is {@code false})
     */
    protected boolean isPassCredentials() {
        return false;
    }

    /**
     * Determine whether the mechanism is susceptible to dictionary (passive) attacks.
     *
     * @return {@code true} if it is (default is {@code true})
     */
    protected boolean isDictionarySusceptible() {
        return true;
    }

    /**
     * Determine whether the mechanism is susceptible to active attack.
     *
     * @return {@code true} if it is (default is {@code true})
     */
    protected boolean isActiveSusceptible() {
        return true;
    }

    /**
     * Determine whether forward secrecy is implemented.
     *
     * @return {@code true} if it is (default is {@code false})
     */
    protected boolean isForwardSecrecy() {
        return false;
    }

    /**
     * Determine whether the algorithm employs plain text.
     *
     * @return {@code true} if it does so (default is {@code true})
     */
    protected boolean isPlainText() {
        return true;
    }

    /**
     * Determine whether the algorithm is anonymous.
     *
     * @return {@code true} if it is (default is {@code true})
     */
    protected boolean isAnonymous() {
        return true;
    }

    /**
     * Get a boolean property value from the properties map.
     *
     * @param property the property name
     * @param props the properties map
     * @param defaultValue the default value
     * @return the value
     */
    protected boolean getPropertyValue(final String property, final Map<String, ?> props, boolean defaultValue) {
        return (props == null || ! props.containsKey(property)) ? defaultValue : Boolean.parseBoolean(props.get(property).toString());
    }

    /**
     * Determine whether our mechanism name is among those given.
     *
     * @param names the names
     * @return {@code true} if the names include our mechanism
     */
    protected boolean isIncluded(final String... names) {
        final String ourName = this.names[0];
        for (String name : names) {
            if (name.equals(ourName)) {
                return true;
            }
        }
        return false;
    }
}
