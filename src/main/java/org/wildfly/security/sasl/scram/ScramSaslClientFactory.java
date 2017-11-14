/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.sasl.scram;

import static org.wildfly.security._private.ElytronMessages.saslScram;

import java.io.IOException;
import java.security.Provider;
import java.security.Security;
import java.util.Collections;
import java.util.Map;
import java.util.function.Supplier;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;

import org.kohsuke.MetaInfServices;
import org.wildfly.common.Assert;
import org.wildfly.security.auth.callback.ChannelBindingCallback;
import org.wildfly.security.mechanism.AuthenticationMechanismException;
import org.wildfly.security.mechanism.scram.ScramMechanism;
import org.wildfly.security.sasl.WildFlySasl;
import org.wildfly.security.sasl.util.SaslMechanismInformation;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
@MetaInfServices(value = SaslClientFactory.class)
public final class ScramSaslClientFactory implements SaslClientFactory {

    private final Supplier<Provider[]> providers;

    public ScramSaslClientFactory() {
        super();
        providers = Security::getProviders;
    }

    public ScramSaslClientFactory(final Provider provider) {
        providers = () -> new Provider[] { provider };
    }

    public SaslClient createSaslClient(final String[] mechanisms, final String authorizationId, final String protocol, final String serverName, Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
        Assert.checkNotNullParam("cbh", cbh);
        if (props == null) props = Collections.emptyMap();

        boolean bindingRequired = "true".equals(props.get(WildFlySasl.CHANNEL_BINDING_REQUIRED));
        boolean bindingUnsupported = "true".equals(props.get(WildFlySasl.CHANNEL_BINDING_UNSUPPORTED));

        ChannelBindingCallback callback = null;
        boolean bindingOk = false;
        if (! bindingUnsupported) {
            callback = new ChannelBindingCallback();
            try {
                cbh.handle(new Callback[] { callback });
            } catch (SaslException e) {
                throw e;
            } catch (IOException e) {
                throw saslScram.mechFailedToDetermineChannelBindingStatus(e).toSaslException();
            } catch (UnsupportedCallbackException e) {
                // ignored
            }
            final String bindingType = callback.getBindingType();
            final byte[] bindingData = callback.getBindingData();
            bindingOk = bindingType != null && bindingData != null;
        }

        int minimumIterationCount = ScramUtil.getIntProperty(props, WildFlySasl.SCRAM_MIN_ITERATION_COUNT, 4096);
        int maximumIterationCount = ScramUtil.getIntProperty(props, WildFlySasl.SCRAM_MAX_ITERATION_COUNT, 32768);
        try {
            for (String mechanism : mechanisms) {
                switch (mechanism) {
                    case SaslMechanismInformation.Names.SCRAM_SHA_1_PLUS:
                        if (! bindingOk) break;
                        return new ScramSaslClient(mechanism, protocol, serverName, cbh, authorizationId, ScramMechanism.SCRAM_SHA_1_PLUS.createClient(
                            authorizationId, cbh, ScramUtil.getSecureRandom(props), callback, minimumIterationCount, maximumIterationCount, providers
                        ));
                    case SaslMechanismInformation.Names.SCRAM_SHA_1:
                        if (bindingRequired) break;
                        return new ScramSaslClient(mechanism, protocol, serverName, cbh, authorizationId, ScramMechanism.SCRAM_SHA_1.createClient(
                            authorizationId, cbh, ScramUtil.getSecureRandom(props), callback, minimumIterationCount, maximumIterationCount, providers
                        ));
                    case SaslMechanismInformation.Names.SCRAM_SHA_256_PLUS:
                        if (! bindingOk) break;
                        return new ScramSaslClient(mechanism, protocol, serverName, cbh, authorizationId, ScramMechanism.SCRAM_SHA_256_PLUS.createClient(
                            authorizationId, cbh, ScramUtil.getSecureRandom(props), callback, minimumIterationCount, maximumIterationCount, providers
                        ));
                    case SaslMechanismInformation.Names.SCRAM_SHA_256:
                        if (bindingRequired) break;
                        return new ScramSaslClient(mechanism, protocol, serverName, cbh, authorizationId, ScramMechanism.SCRAM_SHA_256.createClient(
                            authorizationId, cbh, ScramUtil.getSecureRandom(props), callback, minimumIterationCount, maximumIterationCount, providers
                        ));
                    case SaslMechanismInformation.Names.SCRAM_SHA_384_PLUS:
                        if (! bindingOk) break;
                        return new ScramSaslClient(mechanism, protocol, serverName, cbh, authorizationId, ScramMechanism.SCRAM_SHA_384_PLUS.createClient(
                            authorizationId, cbh, ScramUtil.getSecureRandom(props), callback, minimumIterationCount, maximumIterationCount, providers
                        ));
                    case SaslMechanismInformation.Names.SCRAM_SHA_384:
                        if (bindingRequired) break;
                        return new ScramSaslClient(mechanism, protocol, serverName, cbh, authorizationId, ScramMechanism.SCRAM_SHA_384.createClient(
                            authorizationId, cbh, ScramUtil.getSecureRandom(props), callback, minimumIterationCount, maximumIterationCount, providers
                        ));
                    case SaslMechanismInformation.Names.SCRAM_SHA_512_PLUS:
                        if (! bindingOk) break;
                        return new ScramSaslClient(mechanism, protocol, serverName, cbh, authorizationId, ScramMechanism.SCRAM_SHA_512_PLUS.createClient(
                            authorizationId, cbh, ScramUtil.getSecureRandom(props), callback, minimumIterationCount, maximumIterationCount, providers
                        ));
                    case SaslMechanismInformation.Names.SCRAM_SHA_512:
                        if (bindingRequired) break;
                        return new ScramSaslClient(mechanism, protocol, serverName, cbh, authorizationId, ScramMechanism.SCRAM_SHA_512.createClient(
                            authorizationId, cbh, ScramUtil.getSecureRandom(props), callback, minimumIterationCount, maximumIterationCount, providers
                        ));
                }
            }
        } catch (AuthenticationMechanismException e) {
            throw e.toSaslException();
        }
        return null;
    }

    public String[] getMechanismNames(final Map<String, ?> props) {
        if (props != null && !"true".equals(props.get(WildFlySasl.MECHANISM_QUERY_ALL))) {
            if ("true".equals(props.get(WildFlySasl.CHANNEL_BINDING_REQUIRED)) && "true".equals(props.get(WildFlySasl.CHANNEL_BINDING_UNSUPPORTED))) {
                return WildFlySasl.NO_NAMES;
            }
            if ("true".equals(props.get(WildFlySasl.CHANNEL_BINDING_REQUIRED))) {
                return new String[] {
                        SaslMechanismInformation.Names.SCRAM_SHA_512_PLUS,
                        SaslMechanismInformation.Names.SCRAM_SHA_384_PLUS,
                        SaslMechanismInformation.Names.SCRAM_SHA_256_PLUS,
                        SaslMechanismInformation.Names.SCRAM_SHA_1_PLUS
                };
            }
            if ("true".equals(props.get(WildFlySasl.CHANNEL_BINDING_UNSUPPORTED))) {
                return new String[] {
                        SaslMechanismInformation.Names.SCRAM_SHA_512,
                        SaslMechanismInformation.Names.SCRAM_SHA_384,
                        SaslMechanismInformation.Names.SCRAM_SHA_256,
                        SaslMechanismInformation.Names.SCRAM_SHA_1
                };
            }
        }
        return new String[] {
                SaslMechanismInformation.Names.SCRAM_SHA_512_PLUS,
                SaslMechanismInformation.Names.SCRAM_SHA_384_PLUS,
                SaslMechanismInformation.Names.SCRAM_SHA_256_PLUS,
                SaslMechanismInformation.Names.SCRAM_SHA_1_PLUS,
                SaslMechanismInformation.Names.SCRAM_SHA_512,
                SaslMechanismInformation.Names.SCRAM_SHA_384,
                SaslMechanismInformation.Names.SCRAM_SHA_256,
                SaslMechanismInformation.Names.SCRAM_SHA_1
        };
    }
}
