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

import static org.wildfly.security._private.ElytronMessages.saslGs2;
import static org.wildfly.security.sasl.gs2.Gs2.*;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.kohsuke.MetaInfServices;
import org.wildfly.common.Assert;
import org.wildfly.security.auth.callback.ChannelBindingCallback;
import org.wildfly.security.sasl.WildFlySasl;

/**
 * SaslServerFactory for the GS2 mechanism family as defined by RFC 5801.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
@MetaInfServices(value = SaslServerFactory.class)
public final class Gs2SaslServerFactory implements SaslServerFactory {
    private final GSSManager gssManager;

    /**
     * Construct a new instance.
     *
     * @param gssManager the GSS manager to use
     */
    public Gs2SaslServerFactory(final GSSManager gssManager) {
        this.gssManager = gssManager;
    }

    /**
     * Construct a new instance with the default GSS manager.
     */
    public Gs2SaslServerFactory() {
        this(GSSManager.getInstance());
    }

    public SaslServer createSaslServer(final String mechanism, final String protocol, final String serverName, Map<String, ?> props,
            final CallbackHandler cbh) throws SaslException {
        Assert.checkNotNullParam("cbh", cbh);
        if (props == null) props = Collections.emptyMap();
        boolean bindingRequired = "true".equals(props.get(WildFlySasl.CHANNEL_BINDING_REQUIRED));
        boolean bindingUnsupported = "true".equals(props.get(WildFlySasl.CHANNEL_BINDING_UNSUPPORTED));

        boolean bindingOk = false;
        String bindingType = null;
        byte[] bindingData = null;
        if (! bindingUnsupported) {
            ChannelBindingCallback callback = new ChannelBindingCallback();
            try {
                cbh.handle(new Callback[] { callback });
            } catch (SaslException e) {
                throw e;
            } catch (IOException e) {
                throw saslGs2.mechFailedToDetermineChannelBindingStatus(e).toSaslException();
            } catch (UnsupportedCallbackException e) {
                // ignored
            }
            bindingType = callback.getBindingType();
            bindingData = callback.getBindingData();
            bindingOk = bindingType != null && bindingData != null;
        }

        GSSManager gssManager = this.gssManager;
        final String[] supportedMechs;
        try {
            supportedMechs = Gs2Util.getSupportedSaslNamesForMechanisms(gssManager.getMechs());
        } catch (GSSException e) {
            throw saslGs2.mechGettingSupportedMechanismsFailed(e).toSaslException();
        }
        if (! Gs2Util.isIncluded(mechanism, supportedMechs)) return null;
        boolean plus = mechanism.endsWith(PLUS_SUFFIX);
        if (plus && ! bindingOk) return null;
        if (! plus && bindingRequired) return null;

        final Gs2SaslServer server = new Gs2SaslServer(mechanism, protocol, serverName, cbh, gssManager, plus, bindingType, bindingData);
        server.init();
        return server;
    }

    public String[] getMechanismNames(final Map<String, ?> props) {
        String[] names;
        try {
            names = Gs2Util.getSupportedSaslNamesForMechanisms(gssManager.getMechs());
        } catch (GSSException e) {
            saslGs2.trace("Obtaining GS2 mechanism names has failed", e);
            return WildFlySasl.NO_NAMES;
        }

        if (props != null && !"true".equals(props.get(WildFlySasl.MECHANISM_QUERY_ALL))) {
            if ("true".equals(props.get(WildFlySasl.CHANNEL_BINDING_REQUIRED)) && "true".equals(props.get(WildFlySasl.CHANNEL_BINDING_UNSUPPORTED))) {
                return WildFlySasl.NO_NAMES;
            }
            if ("true".equals(props.get(WildFlySasl.CHANNEL_BINDING_REQUIRED))) {
                return Gs2Util.getPlusMechanisms(names);
            }
            if ("true".equals(props.get(WildFlySasl.CHANNEL_BINDING_UNSUPPORTED))) {
                return Gs2Util.getNonPlusMechanisms(names);
            }
        }
        return names;
    }
}
