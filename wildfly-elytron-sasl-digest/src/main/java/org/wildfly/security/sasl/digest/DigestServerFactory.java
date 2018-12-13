/*
 * JBoss, Home of Professional Open Source
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

package org.wildfly.security.sasl.digest;

import static org.wildfly.security.mechanism._private.ElytronMessages.saslDigest;
import static org.wildfly.security.util.ProviderUtil.INSTALLED_PROVIDERS;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.util.Collections;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.function.Predicate;
import java.util.function.Supplier;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

import org.kohsuke.MetaInfServices;
import org.wildfly.common.Assert;
import org.wildfly.security.auth.callback.AvailableRealmsCallback;
import org.wildfly.security.sasl.WildFlySasl;

/**
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 *
 */
@MetaInfServices(value = SaslServerFactory.class)
public class DigestServerFactory extends AbstractDigestFactory implements SaslServerFactory {

    private final Supplier<Provider[]> providers;

    public DigestServerFactory() {
        providers = INSTALLED_PROVIDERS;
    }

    public DigestServerFactory(final Provider provider) {
        providers = () -> new Provider[] { provider };
    }

    /* (non-Javadoc)
     * @see javax.security.sasl.SaslServerFactory#createSaslServer(java.lang.String, java.lang.String, java.lang.String, java.util.Map, javax.security.auth.callback.CallbackHandler)
     */
    @Override
    public SaslServer createSaslServer(String mechanism, String protocol, String serverName, Map<String, ?> props,
            CallbackHandler cbh) throws SaslException {
        if (! matches(props, false) || ! matchesMech(mechanism)) {
            return null;
        }
        Assert.checkNotNullParam("cbh", cbh);
        if (props == null) props = Collections.emptyMap();

        String[] realms = null;
        final AvailableRealmsCallback availableRealmsCallback = new AvailableRealmsCallback();
        try {
            cbh.handle(new Callback[] { availableRealmsCallback });
            realms = availableRealmsCallback.getRealmNames();
        } catch (UnsupportedCallbackException ignored) {
        } catch (SaslException e) {
            throw e;
        } catch (IOException e) {
            throw saslDigest.mechCallbackHandlerFailedForUnknownReason(e).toSaslException();
        }
        final boolean defaultRealm;
        if (realms == null) {
            defaultRealm = true;
            realms = new String[] { serverName };
        } else {
            defaultRealm = false;
        }

        final String utf8 = (String)props.get(WildFlySasl.USE_UTF8);
        Charset charset = (utf8 == null || Boolean.parseBoolean(utf8)) ? StandardCharsets.UTF_8 : StandardCharsets.ISO_8859_1;

        String qopsString = (String)props.get(Sasl.QOP);
        String[] qops = qopsString == null ? null : qopsString.split(",");

        String supportedCipherOpts = (String)props.get(WildFlySasl.SUPPORTED_CIPHER_NAMES);
        String[] cipherOpts = (supportedCipherOpts == null ? null : supportedCipherOpts.split(","));

        final Predicate<String> protocolTest;
        String alternativeProtocols = (String)props.get(WildFlySasl.ALTERNATIVE_PROTOCOLS);
        if (alternativeProtocols != null) {
            final Set<String> acceptableProtocols = new HashSet<>();
            acceptableProtocols.add(protocol.toLowerCase(Locale.ROOT));

            StringTokenizer parser = new StringTokenizer(alternativeProtocols, ", \t\n");
            while (parser.hasMoreTokens()) {
                acceptableProtocols.add(parser.nextToken().trim().toLowerCase(Locale.ROOT));
            }
            protocolTest = acceptableProtocols::contains;
        } else {
            protocolTest = protocol.toLowerCase(Locale.ROOT)::equals;
        }

        final DigestSaslServer server = new DigestSaslServer(realms, defaultRealm, mechanism, protocol, serverName, cbh, charset, qops, cipherOpts, protocolTest, providers);
        server.init();
        return server;
    }
}
