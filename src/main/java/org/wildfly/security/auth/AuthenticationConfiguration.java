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

package org.wildfly.security.auth;

import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Principal;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

import org.wildfly.security.auth.callback.CallbackUtils;
import org.wildfly.security.auth.principal.AnonymousPrincipal;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.util.NameRewriter;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.spec.ClearPasswordSpec;

/**
 * A configuration which controls how authentication is performed.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public abstract class AuthenticationConfiguration {
    // constants

    private static final Set<String> ONLY_ANONYMOUS = Collections.singleton("ANONYMOUS");

    /**
     * An empty configuration which can be used as the basis for any configuration.  This configuration supports no
     * remapping of any kind, and always uses an anonymous principal.
     */
    public static final AuthenticationConfiguration EMPTY = new AuthenticationConfiguration() {

        void handleCallback(final Callback[] callbacks, final int index) throws UnsupportedCallbackException {
            CallbackUtils.unsupported(callbacks[index]);
        }

        void handleCallbacks(final AuthenticationConfiguration config, final Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            final int length = callbacks.length;
            for (int i = 0; i < length; i ++) {
                config.handleCallback(callbacks, i);
            }
        }

        void configureSaslProperties(final Map<String, Object> properties) {
        }

        void filterSaslMechanisms(final Set<String> names) {
            // apparently no principal has been set; we only allow anonymous
            names.retainAll(ONLY_ANONYMOUS);
        }

        String doRewriteUser(final String original) {
            return original;
        }

        AuthenticationConfiguration reparent(final AuthenticationConfiguration newParent) {
            return this;
        }

        AuthenticationConfiguration without(final Class<? extends AuthenticationConfiguration> clazz) {
            return this;
        }

        String getHost(final URI uri) {
            return uri.getHost();
        }

        int getPort(final URI uri) {
            return uri.getPort();
        }

        Principal getPrincipal() {
            return AnonymousPrincipal.getInstance();
        }

        <T extends AuthenticationConfiguration> T get(final Class<T> clazz) {
            return null;
        }

        String getMatchHost() {
            return null;
        }

        String getMatchUser() {
            return null;
        }

        public boolean matchersEqual(final AuthenticationConfiguration _this, final AuthenticationConfiguration other) {
            return other.allMatchersArePresentIn(this);
        }
    };

    private final AuthenticationConfiguration parent;
    private final CallbackHandler callbackHandler = new CallbackHandler() {
        public void handle(final Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            AuthenticationConfiguration.this.handleCallbacks(AuthenticationConfiguration.this, callbacks);
        }
    };

    // constructors

    AuthenticationConfiguration() {
        this.parent = null;
    }

    AuthenticationConfiguration(final AuthenticationConfiguration parent) {
        this(parent, false);
    }

    AuthenticationConfiguration(final AuthenticationConfiguration parent, final boolean allowMultiple) {
        this.parent = allowMultiple ? parent : parent.without(getClass());
    }

    // test method

    Principal getPrincipal() {
        return parent.getPrincipal();
    }

    String getHost(URI uri) {
        return parent.getHost(uri);
    }

    int getPort(URI uri) {
        return parent.getPort(uri);
    }

    // internal actions

    void handleCallback(Callback[] callbacks, int index) throws IOException, UnsupportedCallbackException {
        parent.handleCallback(callbacks, index);
    }

    void handleCallbacks(AuthenticationConfiguration config, Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        parent.handleCallbacks(config, callbacks);
    }

    void configureSaslProperties(Map<String, Object> properties) {
        parent.configureSaslProperties(properties);
    }

    void filterSaslMechanisms(Set<String> names) {
        parent.filterSaslMechanisms(names);
    }

    String doRewriteUser(String original) {
        return parent.doRewriteUser(original);
    }

    abstract AuthenticationConfiguration reparent(AuthenticationConfiguration newParent);

    AuthenticationConfiguration without(Class<? extends AuthenticationConfiguration> clazz) {
        if (clazz.isInstance(this)) return parent;
        AuthenticationConfiguration newParent = parent.without(clazz);
        if (parent == newParent) return this;
        return reparent(newParent);
    }

    // assembly methods - rewrite

    /**
     * Create a new configuration which is the same as this configuration, but rewrites the user name using the given
     * name rewriter.
     *
     * @param rewriter the name rewriter
     * @return the new configuration
     */
    public AuthenticationConfiguration rewriteUser(NameRewriter rewriter) {
        if (rewriter == null) {
            return this;
        }
        return new RewriteNameAuthenticationConfiguration(this, rewriter);
    }

    // assembly methods - filter

    // assembly methods - configuration

    /**
     * Create a new configuration which is the same as this configuration, but which uses an anonymous login.
     *
     * @return the new configuration
     */
    public AuthenticationConfiguration useAnonymous() {
        return without(SetNamePrincipalAuthenticationConfiguration.class).without(SetPasswordAuthenticationConfiguration.class).without(SetCallbackHandlerAuthenticationConfiguration.class);
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given principal to authenticate.
     *
     * @param principal the principal to use
     * @return the new configuration
     */
    public AuthenticationConfiguration usePrincipal(NamePrincipal principal) {
        return new SetNamePrincipalAuthenticationConfiguration(this, principal);
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given login name to authenticate.
     *
     * @param name the principal to use
     * @return the new configuration
     */
    public AuthenticationConfiguration useName(String name) {
        return usePrincipal(new NamePrincipal(name));
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given password to authenticate.
     *
     * @param password the password to use
     * @return the new configuration
     */
    public AuthenticationConfiguration usePassword(Password password) {
        return password == null ? this : new SetPasswordAuthenticationConfiguration(this, password);
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given password to authenticate.
     *
     * @param password the password to use
     * @return the new configuration
     */
    public AuthenticationConfiguration usePassword(char[] password) {
        try {
            return password == null ? this : usePassword(PasswordFactory.getInstance("clear").generatePassword(new ClearPasswordSpec(password)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException();
        }
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given password to authenticate.
     *
     * @param password the password to use
     * @return the new configuration
     */
    public AuthenticationConfiguration usePassword(String password) {
        return password == null ? this : usePassword(password.toCharArray());
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given callback handler
     * to authenticate.
     *
     * @param callbackHandler the callback handler to use
     * @return the new configuration
     */
    public AuthenticationConfiguration useCallbackHandler(CallbackHandler callbackHandler) {
        return callbackHandler == null ? this : new SetCallbackHandlerAuthenticationConfiguration(this, callbackHandler);
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given key store and alias
     * to acquire the credential required for authentication.
     *
     * @param keyStore the key store to use
     * @param alias the key store alias
     * @return the new configuration
     */
    public AuthenticationConfiguration useKeyStoreCredential(KeyStore keyStore, String alias) {
        return keyStore == null || alias == null ? this : new SetKeyStoreCredentialAuthenticationConfiguration(this, keyStore, alias, null);
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given key store and alias
     * to acquire the credential required for authentication.
     *
     * @param keyStore the key store to use
     * @param alias the key store alias
     * @param protectionParameter the protection parameter to use to access the key store entry
     * @return the new configuration
     */
    public AuthenticationConfiguration useKeyStoreCredential(KeyStore keyStore, String alias, KeyStore.ProtectionParameter protectionParameter) {
        return keyStore == null || alias == null ? this : new SetKeyStoreCredentialAuthenticationConfiguration(this, keyStore, alias, protectionParameter);
    }

    /**
     * Create a new configuration which is the same as this configuration, but which connects to a different host name.
     *
     * @param hostName the host name to connect to
     * @return the new configuration
     */
    public AuthenticationConfiguration useHost(String hostName) {
        if (hostName != null && hostName.isEmpty()) hostName = null;
        return new SetHostAuthenticationConfiguration(this, hostName);
    }

    /**
     * Create a new configuration which is the same as this configuration, but which connects to a different port.
     *
     * @param port the port to connect to
     * @return the new configuration
     */
    public AuthenticationConfiguration usePort(int port) {
        if (port < 1 || port > 65535) throw new IllegalArgumentException("Invalid port " + port);
        return new SetPortAuthenticationConfiguration(this, port);
    }

    // Comparison

    boolean matchersEqual(AuthenticationConfiguration _this, AuthenticationConfiguration other) {
        return parent.matchersEqual(_this, other);
    }

    public final boolean matchersEqual(AuthenticationConfiguration other) {
        return other != null && matchersEqual(this, other);
    }

    boolean allMatchersArePresentIn(AuthenticationConfiguration other) {
        return other.get(getClass()) != null && parent.allMatchersArePresentIn(other);
    }

    <T extends AuthenticationConfiguration> T get(Class<T> clazz) {
        if (clazz.isInstance(this)) {
            return clazz.cast(this);
        } else {
            return parent.get(clazz);
        }
    }

    // SASL

    /**
     * Create a new configuration which is the same as this configuration, but which sets the allowed mechanism set
     * to only include the given named mechanisms.
     *
     * @param names the mechanism names
     * @return the new configuration
     */
    public AuthenticationConfiguration allowSaslMechanisms(String... names) {
        return names == null || names.length == 0 ? new FilterSaslMechanismAuthenticationConfiguration(this, true, Collections.<String>emptySet()) : new FilterSaslMechanismAuthenticationConfiguration(this, true, new HashSet<String>(Arrays.asList(names)));
    }

    /**
     * Create a new configuration which is the same as this configuration, but which sets the allowed mechanism set
     * to all available mechanisms except for the given named mechanisms.
     *
     * @param names the mechanism names
     * @return the new configuration
     */
    public AuthenticationConfiguration forbidSaslMechanisms(String... names) {
        return names == null || names.length == 0 ? this : new FilterSaslMechanismAuthenticationConfiguration(this, false, new HashSet<String>(Arrays.asList(names)));
    }

    // XML

    static AuthenticationConfiguration fromXml(XMLStreamReader reader) throws XMLStreamException {
        // todo
        return null;
    }

    String getMatchHost() {
        return parent.getMatchHost();
    }

    String getMatchUser() {
        return parent.getMatchUser();
    }

    CallbackHandler getCallbackHandler() {
        return callbackHandler;
    }
}
