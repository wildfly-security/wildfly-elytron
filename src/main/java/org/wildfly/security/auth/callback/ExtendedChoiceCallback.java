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

package org.wildfly.security.auth.callback;

import javax.security.auth.callback.ChoiceCallback;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public class ExtendedChoiceCallback extends ChoiceCallback implements ExtendedCallback {

    private static final long serialVersionUID = 2222777746412093737L;

    private final boolean optional;

    /**
     * Construct a new instance.
     *
     * @param prompt the text prompt (must not be {@code null})
     * @param choices the choices (must not be {@code null})
     * @param defaultChoice the default choice as an index into the {@code choices} array
     * @param multipleSelectionsAllowed {@code true} if multiple selections are allowed
     * @param optional {@code true} if the support for the callback is optional
     */
    public ExtendedChoiceCallback(final String prompt, final String[] choices, final int defaultChoice, final boolean multipleSelectionsAllowed, final boolean optional) {
        super(prompt, choices, defaultChoice, multipleSelectionsAllowed);
        this.optional = optional;
    }

    public boolean isOptional() {
        return optional;
    }

    public boolean needsInformation() {
        return true;
    }
}
