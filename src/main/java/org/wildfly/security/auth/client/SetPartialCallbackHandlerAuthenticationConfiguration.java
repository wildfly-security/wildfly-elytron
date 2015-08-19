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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

/**
 * An authentication configuration which handles some callbacks, but not everything expected for the client config
 * @author Kabir Khan
 */
class SetPartialCallbackHandlerAuthenticationConfiguration extends AuthenticationConfiguration {

    private final CallbackHandler callbackHandler;
    private final Class<? extends Callback>[] handledCallbacks;

    SetPartialCallbackHandlerAuthenticationConfiguration(final AuthenticationConfiguration parent, final CallbackHandler callbackHandler,
                                                         Class<? extends Callback>[] handledCallbacks) {
        super(parent);
        this.callbackHandler = callbackHandler;
        this.handledCallbacks = Arrays.copyOf(handledCallbacks, handledCallbacks.length);
    }

    void handleCallbacks(final AuthenticationConfiguration config, final Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        //TODO it would have been nice to be able to specify the 'withouts' for the parent, but these classes are
        //package-protected so users will not be able to do that. So, only make the parent handle the callbacks
        //which we are not set up to handle.
        List<Callback> forMe = null;
        List<Callback> forParent = null;
        for (Callback callback : callbacks) {
            if (isHandledCallback(callback)) {
                forMe = addToList(forMe, callback);
            } else {
                forParent = addToList(forParent, callback);
            }
        }
        if (forMe != null) {
            callbackHandler.handle(forMe.toArray(new Callback[forMe.size()]));
        }

        if (forParent != null) {
            super.handleCallbacks(config, forParent.toArray(new Callback[forParent.size()]));
        }
    }

    void handleCallback(final Callback[] callbacks, final int index) throws IOException, UnsupportedCallbackException {
        final Callback callback = callbacks[index];
        if (isHandledCallback(callback)) {
            return;
        }
        super.handleCallback(callbacks, index);
    }

    private boolean isHandledCallback(Callback callback) {
        for (Class<? extends Callback> handledCallback : handledCallbacks) {
            if (handledCallback.isAssignableFrom(callback.getClass())) {
                return true;
            }
        }
        return false;
    }

    private List<Callback> addToList(List<Callback> list, Callback callback) {
        if (list == null) {
            list = new ArrayList<>();
        }
        list.add(callback);
        return list;
    }

    AuthenticationConfiguration reparent(final AuthenticationConfiguration newParent) {
        return new SetPasswordCallbackHandlerAuthenticationConfiguration(newParent, callbackHandler);
    }
}