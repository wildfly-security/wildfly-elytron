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

package org.wildfly.security.sasl.gs2;

import static org.wildfly.security.mechanism._private.ElytronMessages.saslGs2;
import static org.wildfly.security.sasl.gs2.Gs2.*;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;

import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.kohsuke.MetaInfServices;
import org.wildfly.common.Assert;
import org.wildfly.security.auth.callback.ChannelBindingCallback;
import org.wildfly.security.sasl.WildFlySasl;

/**
 * SaslClientFactory for the GS2 mechanism family as defined by RFC 5801.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
@MetaInfServices(value = SaslClientFactory.class)
public final class Gs2SaslClientFactory implements SaslClientFactory {

    private final GSSManager gssManager;

    /**
     * Construct a new instance.
     *
     * @param gssManager the GSS manager to use
     */
    public Gs2SaslClientFactory(final GSSManager gssManager) {
        this.gssManager = gssManager;
    }

    /**
     * Construct a new instance with the default GSS manager.
     */
    public Gs2SaslClientFactory() {
        this(GSSManager.getInstance());
    }

    public SaslClient createSaslClient(final String[] mechanisms, final String authorizationId, final String protocol,
            final String serverName, Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
        Assert.checkNotNullParam("cbh", cbh);
        if (props == null) props = Collections.emptyMap();

        GSSManager gssManager = this.gssManager;
        final String[] supportedMechanisms;
        try {
            supportedMechanisms = Gs2Util.getSupportedSaslNamesForMechanisms(gssManager.getMechs());
        } catch (GSSException e) {
            throw saslGs2.mechGettingSupportedMechanismsFailed(e).toSaslException();
        }

        String name = null;
        boolean plus = false;
        String bindingType = null;
        byte[] bindingData = null;
        boolean bindingOk = false;
        boolean bindingRequired = "true".equals(props.get(WildFlySasl.CHANNEL_BINDING_REQUIRED));
        boolean bindingStatusDetermined = false;
        for (String mechanism : mechanisms) {
            if (! Gs2Util.isIncluded(mechanism, supportedMechanisms)) continue;
            if (! bindingStatusDetermined) {
                final ChannelBindingCallback callback = new ChannelBindingCallback();
                try {
                    cbh.handle(new Callback[] { callback });
                } catch (SaslException e) {
                    throw e;
                } catch (IOException e) {
                    throw saslGs2.mechFailedToDetermineChannelBindingStatus(e).toSaslException();
                } catch (UnsupportedCallbackException e) {
                    // Ignored
                }
                bindingType = callback.getBindingType();
                bindingData = callback.getBindingData();
                bindingOk = (bindingType != null) && (bindingData != null);
                bindingStatusDetermined = true;
            }
            if (mechanism.endsWith(PLUS_SUFFIX)) {
                if (! bindingOk) continue;
                plus = true;
            }
            if (bindingRequired && ! plus) continue;
            name = mechanism;
            break;
        }
        if (name == null) return null;

        final Gs2SaslClient client = new Gs2SaslClient(name, protocol, serverName, cbh, authorizationId, props, gssManager, plus, bindingType, bindingData);
        client.init();
        return client;
    }

    public String[] getMechanismNames(final Map<String, ?> props) {
        String[] names;
        try {
            names = Gs2Util.getSupportedSaslNamesForMechanisms(gssManager.getMechs());
        } catch (GSSException e) {
            return WildFlySasl.NO_NAMES;
        }
        if (props != null && !"true".equals(props.get(WildFlySasl.MECHANISM_QUERY_ALL)) && "true".equals(props.get(WildFlySasl.CHANNEL_BINDING_REQUIRED))) {
            return Gs2Util.getPlusMechanisms(names);
        } else {
            return names;
        }
    }
}
