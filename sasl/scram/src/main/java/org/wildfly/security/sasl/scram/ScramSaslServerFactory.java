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

import static org.wildfly.security.mechanism._private.ElytronMessages.saslScram;
import static org.wildfly.security.util.ProviderUtil.INSTALLED_PROVIDERS;

import java.io.IOException;
import java.security.Provider;
import java.util.Collections;
import java.util.Map;
import java.util.function.Supplier;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

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
@MetaInfServices(value = SaslServerFactory.class)
public final class ScramSaslServerFactory implements SaslServerFactory {

    private final Supplier<Provider[]> providers;

    public ScramSaslServerFactory() {
        providers = INSTALLED_PROVIDERS;
    }

    public ScramSaslServerFactory(final Provider provider) {
        providers = () -> new Provider[] { provider };
    }

    public SaslServer createSaslServer(final String mechanism, final String protocol, final String serverName, Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
        Assert.checkNotNullParam("cbh", cbh);
        if (props == null) props = Collections.emptyMap();
        final ChannelBindingCallback callback = new ChannelBindingCallback();
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
        boolean bindingOk = bindingType != null && bindingData != null;
        boolean bindingRequired = "true".equals(props.get(WildFlySasl.CHANNEL_BINDING_REQUIRED));
        int minimumIterationCount = ScramUtil.getIntProperty(props, WildFlySasl.SCRAM_MIN_ITERATION_COUNT, 4096);
        int maximumIterationCount = ScramUtil.getIntProperty(props, WildFlySasl.SCRAM_MAX_ITERATION_COUNT, 32768);
        try {
            switch (mechanism) {
                case SaslMechanismInformation.Names.SCRAM_SHA_1_PLUS:
                    if (! bindingOk) return null;
                    return new ScramSaslServer(mechanism, protocol, serverName, cbh, ScramMechanism.SCRAM_SHA_1_PLUS.createServer(
                        cbh, ScramUtil.getSecureRandom(props), callback, minimumIterationCount, maximumIterationCount, providers
                    ), callback);
                case SaslMechanismInformation.Names.SCRAM_SHA_1:
                    if (bindingRequired) return null;
                    return new ScramSaslServer(mechanism, protocol, serverName, cbh, ScramMechanism.SCRAM_SHA_1.createServer(
                        cbh, ScramUtil.getSecureRandom(props), callback, minimumIterationCount, maximumIterationCount, providers
                    ), callback);
                case SaslMechanismInformation.Names.SCRAM_SHA_256_PLUS:
                    if (! bindingOk) return null;
                    return new ScramSaslServer(mechanism, protocol, serverName, cbh, ScramMechanism.SCRAM_SHA_256_PLUS.createServer(
                        cbh, ScramUtil.getSecureRandom(props), callback, minimumIterationCount, maximumIterationCount, providers
                    ), callback);
                case SaslMechanismInformation.Names.SCRAM_SHA_256:
                    if (bindingRequired) return null;
                    return new ScramSaslServer(mechanism, protocol, serverName, cbh, ScramMechanism.SCRAM_SHA_256.createServer(
                        cbh, ScramUtil.getSecureRandom(props), callback, minimumIterationCount, maximumIterationCount, providers
                    ), callback);
                case SaslMechanismInformation.Names.SCRAM_SHA_384_PLUS:
                    if (! bindingOk) return null;
                    return new ScramSaslServer(mechanism, protocol, serverName, cbh, ScramMechanism.SCRAM_SHA_384_PLUS.createServer(
                        cbh, ScramUtil.getSecureRandom(props), callback, minimumIterationCount, maximumIterationCount, providers
                    ), callback);
                case SaslMechanismInformation.Names.SCRAM_SHA_384:
                    if (bindingRequired) return null;
                    return new ScramSaslServer(mechanism, protocol, serverName, cbh, ScramMechanism.SCRAM_SHA_384.createServer(
                        cbh, ScramUtil.getSecureRandom(props), callback, minimumIterationCount, maximumIterationCount, providers
                    ), callback);
                case SaslMechanismInformation.Names.SCRAM_SHA_512_PLUS:
                    if (! bindingOk) return null;
                    return new ScramSaslServer(mechanism, protocol, serverName, cbh, ScramMechanism.SCRAM_SHA_512_PLUS.createServer(
                        cbh, ScramUtil.getSecureRandom(props), callback, minimumIterationCount, maximumIterationCount, providers
                    ), callback);
                case SaslMechanismInformation.Names.SCRAM_SHA_512:
                    if (bindingRequired) return null;
                    return new ScramSaslServer(mechanism, protocol, serverName, cbh, ScramMechanism.SCRAM_SHA_512.createServer(
                        cbh, ScramUtil.getSecureRandom(props), callback, minimumIterationCount, maximumIterationCount, providers
                    ), callback);
                default: {
                    return null;
                }
            }
        } catch (AuthenticationMechanismException e) {
            throw e.toSaslException();
        }
    }

    public String[] getMechanismNames(final Map<String, ?> props) {
        if (props != null && !"true".equals(props.get(WildFlySasl.MECHANISM_QUERY_ALL)) && "true".equals(props.get(WildFlySasl.CHANNEL_BINDING_REQUIRED))) {
            return new String[] {
                SaslMechanismInformation.Names.SCRAM_SHA_512_PLUS,
                SaslMechanismInformation.Names.SCRAM_SHA_384_PLUS,
                SaslMechanismInformation.Names.SCRAM_SHA_256_PLUS,
                SaslMechanismInformation.Names.SCRAM_SHA_1_PLUS
            };
        } else {
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
}
