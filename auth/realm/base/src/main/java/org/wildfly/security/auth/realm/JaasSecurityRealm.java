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

package org.wildfly.security.auth.realm;

import static org.wildfly.security.auth.realm.ElytronMessages.log;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URI;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.Security;
import java.security.URIParameter;
import java.security.spec.AlgorithmParameterSpec;

import org.wildfly.common.Assert;
import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.evidence.PasswordGuessEvidence;

/**
 * A JAAS based {@link SecurityRealm} implementation.
 *
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class JaasSecurityRealm implements SecurityRealm {

    private static final String DEFAULT_CONFIGURATION_POLICY_TYPE = "JavaLoginConfig";
    private final URI jaasConfigFilePath;
    private final String entry;
    private final CallbackHandler handler;
    private final ClassLoader classLoader;

    /**
     * Construct a new instance.
     *
     * @param entry JAAS configuration file entry (must not be {@code null})
     */
    public JaasSecurityRealm(final String entry) {
        this(entry, (String) null);
    }

    /**
     * Construct a new instance.
     *
     * @param entry       JAAS configuration file entry (must not be {@code null})
     * @param classLoader classLoader to use with LoginContext, this class loader must contain LoginModule CallbackHandler classes
     */
    public JaasSecurityRealm(final String entry, final ClassLoader classLoader) {
        this(entry, null, classLoader);
    }

    /**
     * Construct a new instance.
     *
     * @param entry       JAAS configuration file entry (must not be {@code null})
     * @param jaasConfigFilePath path to JAAS configuration file
     */
    public JaasSecurityRealm(final String entry, final String jaasConfigFilePath) {
        this(entry, jaasConfigFilePath, null);
    }

    /**
     * Construct a new instance.
     *
     * @param entry              JAAS configuration file entry (must not be {@code null})
     * @param jaasConfigFilePath path to JAAS configuration file
     * @param classLoader        classLoader to use with LoginContext, this class loader must contain LoginModule CallbackHandler classes
     */
    public JaasSecurityRealm(final String entry, final String jaasConfigFilePath, final ClassLoader classLoader) {
        this(entry, jaasConfigFilePath, classLoader, null);
    }

    /**
     * Construct a new instance.
     *
     * @param entry              JAAS configuration file entry (must not be {@code null})
     * @param jaasConfigFilePath path to JAAS configuration file
     * @param callbackHandler    callbackHandler to pass to LoginContext
     * @param classLoader        classLoader to use with LoginContext, this class loader must contain LoginModule CallbackHandler classes
     */
    public JaasSecurityRealm(final String entry, final String jaasConfigFilePath, final ClassLoader classLoader, final CallbackHandler callbackHandler) {
        Assert.checkNotNullParam("entry", entry);
        if (jaasConfigFilePath != null) {
            this.jaasConfigFilePath = Paths.get(jaasConfigFilePath).toUri();
        } else {
            this.jaasConfigFilePath = null;
        }
        this.entry = entry;
        this.handler = callbackHandler;
        if (classLoader != null) {
            this.classLoader = classLoader;
        } else {
            this.classLoader = Thread.currentThread().getContextClassLoader();
        }
    }

    @Override
    public RealmIdentity getRealmIdentity(final Principal principal) {
        if (principal instanceof NamePrincipal) {
            return new JaasRealmIdentity(principal);
        } else {
            NamePrincipal namePrincipal = NamePrincipal.from(principal);
            return namePrincipal != null ? new JaasRealmIdentity(namePrincipal) : RealmIdentity.NON_EXISTENT;
        }
    }

    @Override
    public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
        Assert.checkNotNullParam("credentialType", credentialType);
        return SupportLevel.UNSUPPORTED;
    }

    @Override
    public SupportLevel getEvidenceVerifySupport(final Class<? extends Evidence> evidenceType, final String algorithmName) throws RealmUnavailableException {
        Assert.checkNotNullParam("evidenceType", evidenceType);
        return SupportLevel.POSSIBLY_SUPPORTED;
    }

    /**
     * @param entry           login configuration file entry
     * @param subject         classLoader to use with LoginContext, this class loader must contain LoginModule CallbackHandler classes
     * @param callbackHandler callbackHandler to pass to LoginContext
     * @return the instance of LoginContext
     * @throws RealmUnavailableException
     */
    private LoginContext createLoginContext(final String entry, final Subject subject, final CallbackHandler callbackHandler) throws RealmUnavailableException {
        if (jaasConfigFilePath != null) {
            File file = new File(this.jaasConfigFilePath);
            if (!file.exists() && !file.isDirectory()) {
                throw ElytronMessages.log.failedToLoadJaasConfigFile();
            }
        }
        try {
            if (jaasConfigFilePath == null) {
                return new LoginContext(entry, subject, callbackHandler);
            } else {
                return new LoginContext(entry, subject, callbackHandler, Configuration.getInstance(DEFAULT_CONFIGURATION_POLICY_TYPE, new URIParameter(jaasConfigFilePath)));
            }
        } catch (LoginException | NoSuchAlgorithmException le) {
            throw ElytronMessages.log.failedToCreateLoginContext(le);
        }
    }

    private CallbackHandler createCallbackHandler(final Principal principal, final Evidence evidence) {
        if (handler != null) {
            try {
                final CallbackHandler callbackHandler = handler.getClass().getConstructor().newInstance();
                // custom handlers were allowed in the past as long as they had a public setSecurityInfo method. Use this method if it exists
                final Method setSecurityInfo = handler.getClass().getMethod("setSecurityInfo", Principal.class, Object.class);
                setSecurityInfo.invoke(callbackHandler, principal, evidence);
                return callbackHandler;
            } catch (InstantiationException | IllegalAccessException | NoSuchMethodException | InvocationTargetException e) {
                // ignore if this method does not exist
                return handler;
            }
        } else if (Security.getProperty("auth.login.defaultCallbackHandler") != null) {
            // security property "auth.login.defaultCallbackHandler" is not null so LoginContext will initialize it itself
            return null;
        } else {
            return new JaasSecurityRealmDefaultCallbackHandler(principal, evidence);
        }
    }

    private class JaasRealmIdentity implements RealmIdentity {

        private final Principal principal;
        private LoginContext loginContext;
        private Subject subject;

        private JaasRealmIdentity(final Principal principal) {
            this.principal = principal;
        }

        public Principal getRealmIdentityPrincipal() {
            return principal;
        }

        public Subject getSubject() {
            return subject;
        }

        @Override
        public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
            return JaasSecurityRealm.this.getCredentialAcquireSupport(credentialType, algorithmName, parameterSpec);
        }

        @Override
        public <C extends Credential> C getCredential(final Class<C> credentialType) throws RealmUnavailableException {
            return getCredential(credentialType, null);
        }

        @Override
        public <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName) throws RealmUnavailableException {
            return getCredential(credentialType, algorithmName, null);
        }

        @Override
        public <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
            return null;
        }

        @Override
        public SupportLevel getEvidenceVerifySupport(final Class<? extends Evidence> evidenceType, final String algorithmName) throws RealmUnavailableException {
            Assert.checkNotNullParam("evidenceType", evidenceType);
            return JaasSecurityRealm.this.getEvidenceVerifySupport(evidenceType, algorithmName);
        }

        @Override
        public boolean verifyEvidence(final Evidence evidence) throws RealmUnavailableException {
            Assert.checkNotNullParam("evidence", evidence);
            this.subject = null;
            boolean successfulLogin;
            ClassLoader oldClassLoader = Thread.currentThread().getContextClassLoader();
            try {
                if (classLoader != null) {
                    Thread.currentThread().setContextClassLoader(classLoader);
                }
                final CallbackHandler callbackHandler = createCallbackHandler(principal, evidence);
                final Subject subject = new Subject();
                loginContext = createLoginContext(entry, subject, callbackHandler);
                log.tracef("Trying to authenticate subject %s using LoginContext %s using JaasSecurityRealm", principal, loginContext);
                try {
                    loginContext.login();
                    successfulLogin = true;
                    this.subject = loginContext.getSubject();
                } catch (LoginException loginException) {
                    successfulLogin = false;
                    ElytronMessages.log.debugInfoJaasAuthenticationFailure(principal, loginException);
                }
            } finally {
                Thread.currentThread().setContextClassLoader(oldClassLoader);
            }
            return successfulLogin;
        }

        public boolean exists() {
            /* we don't really know that the identity exists, but we know that there is always
             * an authorization identity so that's as good as {@code true}
             */
            return true;
        }

        @Override
        public AuthorizationIdentity getAuthorizationIdentity() throws RealmUnavailableException {
            return JaasAuthorizationIdentity.fromSubject(subject);
        }

        @Override
        public void dispose() {
            // call logout in order to empty the subject
            ClassLoader oldClassLoader = Thread.currentThread().getContextClassLoader();
            try {
                try {
                    if (classLoader != null) {
                        Thread.currentThread().setContextClassLoader(classLoader);
                    }
                    if (loginContext != null) {
                        loginContext.logout();
                    }
                } catch (LoginException e) {
                    ElytronMessages.log.debugInfoJaasLogoutFailure(this.principal, e);
                }
            } finally {
                Thread.currentThread().setContextClassLoader(oldClassLoader);
            }
        }
    }

    /**
     * Default CallbackHandler passed to the LoginContext when none is provided to JAAS security realm and none is configured in the "auth.login.defaultCallbackHandler" security property.
     */
    private static class JaasSecurityRealmDefaultCallbackHandler implements CallbackHandler {

        private final Principal principal;
        private final Object evidence;

        private JaasSecurityRealmDefaultCallbackHandler(final Principal principal, final Evidence evidence) {
            this.principal = principal;
            this.evidence = evidence;
        }

        @Override
        public void handle(Callback[] callbacks) throws UnsupportedCallbackException {
            Assert.checkNotNullParam("callbacks", callbacks);
            for (Callback callback : callbacks) {
                if (callback instanceof NameCallback) {
                    NameCallback nc = (NameCallback) callback;
                    if (principal != null)
                        nc.setName(principal.getName());
                } else if (callback instanceof PasswordCallback) {
                    if (evidence instanceof PasswordGuessEvidence) {
                        ((PasswordCallback) callback).setPassword(((PasswordGuessEvidence) evidence).getGuess());
                    } else {
                        PasswordCallback pc = (PasswordCallback) callback;
                        char[] password = getPassword();
                        if (password != null)
                            pc.setPassword(password);
                    }
                } else if (callback instanceof CredentialCallback && evidence instanceof Credential) {
                    final CredentialCallback credentialCallback = (CredentialCallback) callback;
                    Credential credential = (Credential) evidence;
                    if (credentialCallback.isCredentialSupported(credential)) {
                        credentialCallback.setCredential(credential);
                    }
                } else {
                    throw ElytronMessages.log.unableToHandleCallback(callback, this.getClass().getName(), callback.getClass().getCanonicalName());
                }
            }
        }

        /**
         * Source: A utility method for obtaining of password taken from
         * https://github.com/picketbox/picketbox/blob/master/security-jboss-sx/jbosssx/src/main/java/org/jboss/security/auth/callback/JBossCallbackHandler.java
         * on November 2021
         * <p>
         * Try to convert the credential value into a char[] using the
         * first of the following attempts which succeeds:
         * <p>
         * 1. Check for instanceof char[]
         * 2. Check for instanceof String and then use toCharArray()
         * 3. See if credential has a toCharArray() method and use it
         * 4. Use toString() followed by toCharArray().
         *
         * @return a char[] representation of the credential.
         */
        private char[] getPassword() {
            char[] password = null;
            if (evidence instanceof char[]) {
                password = (char[]) evidence;
            } else if (evidence instanceof String) {
                String s = (String) evidence;
                password = s.toCharArray();
            } else {
                try {
                    Class<?>[] types = {};
                    Method m = evidence.getClass().getMethod("toCharArray", types);
                    Object[] args = {};
                    password = (char[]) m.invoke(evidence, args);
                } catch (Exception e) {
                    if (evidence != null) {
                        String s = evidence.toString();
                        password = s.toCharArray();
                    }
                }
            }
            return password;
        }
    }

    /**
     * A JAAS realm's authorization identity. Roles are mapped from all Subject's principals with the following rule:
     * key of the attribute is principal's simple classname and the value is principal's name
     */
    private static class JaasAuthorizationIdentity implements AuthorizationIdentity {

        private MapAttributes attributes;

        private static JaasAuthorizationIdentity fromSubject(final Subject subject) {
            MapAttributes attributes = new MapAttributes();
            // map all subject's principals to attributes with the following rule:
            // key of the attribute is principal's simple classname and the value is principal's name
            if (subject != null) {
                for (Principal principal : subject.getPrincipals()) {
                    attributes.addLast(principal.getClass().getSimpleName(), principal.getName());
                }
            }
            return new JaasAuthorizationIdentity(attributes);
        }

        private JaasAuthorizationIdentity(MapAttributes attributes) {
            this.attributes = attributes;
        }

        @Override
        public Attributes getAttributes() {
            return attributes;
        }
    }
}
