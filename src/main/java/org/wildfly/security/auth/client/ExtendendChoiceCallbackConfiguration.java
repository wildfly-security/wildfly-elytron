/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015, Red Hat, Inc., and individual contributors
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
package org.wildfly.security.auth.client;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.wildfly.security.auth.callback.ExtendedChoiceCallback;

/**
 * @author Kabir Khan
 */
class ExtendendChoiceCallbackConfiguration extends AuthenticationConfiguration {
    private final int responseChoice;

    ExtendendChoiceCallbackConfiguration(AuthenticationConfiguration parent, int responseChoice) {
        super(parent);
        this.responseChoice = responseChoice;
    }

    void handleCallback(final Callback[] callbacks, final int index) throws UnsupportedCallbackException, IOException {
        Callback callback = callbacks[index];
        if (callback instanceof ExtendedChoiceCallback) {
            //TODO handle multiple choices etc.
            if (responseChoice >= 0) {
                ((ExtendedChoiceCallback) callback).setSelectedIndex(responseChoice);
            }
        } else {
            super.handleCallback(callbacks, index);
        }
    }

    @Override
    AuthenticationConfiguration reparent(AuthenticationConfiguration newParent) {
        return new ExtendendChoiceCallbackConfiguration(newParent, responseChoice);
    }
}