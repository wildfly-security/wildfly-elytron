/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2023 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.http.util;

import static org.wildfly.common.Assert.checkNotNullParam;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.wildfly.security.auth.callback.RequestInformationCallback;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;
import org.wildfly.security.http.HttpServerRequest;

/**
 * A wrapper {@link HttpServerAuthenticationMechanismFactory} that sets the request information using the current authentication request.
 *
 * @author <a href="mailto:dvilkola@redhat.com">Diana Krepinska</a>
 */
public class SetRequestInformationCallbackMechanismFactory implements HttpServerAuthenticationMechanismFactory {

    private final HttpServerAuthenticationMechanismFactory delegate;
    private final HashMap<String, Function<HttpServerRequest, String>> httpServerRequestInformationMap;

    /**
     * Construct a wrapping mechanism factory instance.
     *
     * @param delegate the wrapped mechanism factory
     */
    public SetRequestInformationCallbackMechanismFactory(final HttpServerAuthenticationMechanismFactory delegate, HashMap<String, Function<HttpServerRequest, String>> httpServerRequestInformationMap) {
        this.delegate = checkNotNullParam("delegate", delegate);
        this.httpServerRequestInformationMap = checkNotNullParam("httpServerRequestInformationMap", httpServerRequestInformationMap);
    }

    @Override
    public String[] getMechanismNames(Map<String, ?> properties) {
        return delegate.getMechanismNames(properties);
    }

    @Override
    public HttpServerAuthenticationMechanism createAuthenticationMechanism(final String mechanismName, Map<String, ?> properties,
                                                                           final CallbackHandler callbackHandler) throws HttpAuthenticationException {
        final HttpServerAuthenticationMechanism mechanism = delegate.createAuthenticationMechanism(mechanismName, properties, callbackHandler);
        return mechanism != null ? new HttpServerAuthenticationMechanism() {

            @Override
            public String getMechanismName() {
                return mechanism.getMechanismName();
            }

            @Override
            public void evaluateRequest(HttpServerRequest request) throws HttpAuthenticationException {
                try {
                    HashMap<String, Object> props = new HashMap<>();
                    for (Map.Entry<String, Function<HttpServerRequest, String>> entry : httpServerRequestInformationMap.entrySet()) {
                        props.put(entry.getKey(), entry.getValue().apply(request));
                    }
                    callbackHandler.handle(new Callback[]{new RequestInformationCallback(props)});
                } catch (IOException | UnsupportedCallbackException e) {
                    throw new HttpAuthenticationException(e);
                }

                mechanism.evaluateRequest(request);
            }

            @Override
            public void dispose() {
                mechanism.dispose();
            }

        } : null;
    }
}
