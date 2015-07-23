/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.auth.client;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.RealmCallback;

/**
 * @author <a href="mailto:kkhan@redhat.com">Kabir Khan</a>
 */
class SetRealmAuthenticationConfiguration extends AuthenticationConfiguration {

    private final String realm;

    SetRealmAuthenticationConfiguration(final AuthenticationConfiguration parent, final String realm) {
        super(parent);
        this.realm = realm;
    }

    void handleCallback(final Callback[] callbacks, final int index) throws IOException, UnsupportedCallbackException {
        Callback callback = callbacks[index];
        if (callback instanceof RealmCallback) {
            RealmCallback realmCallback = (RealmCallback) callback;
            if (realm != null) {
                realmCallback.setText(realm);
            } else {
                realmCallback.setText(realmCallback.getDefaultText());
            }
            return;
        }
        super.handleCallback(callbacks, index);
    }

    AuthenticationConfiguration reparent(final AuthenticationConfiguration newParent) {
        return new SetRealmAuthenticationConfiguration(newParent, realm);
    }
}
