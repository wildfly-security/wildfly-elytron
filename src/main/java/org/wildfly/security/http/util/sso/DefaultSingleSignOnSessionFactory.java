/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.http.util.sso;

import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.cache.CachedIdentity;
import org.wildfly.security.http.HttpScope;
import org.wildfly.security.http.HttpServerRequest;
import org.wildfly.security.http.Scope;
import org.wildfly.security.util.ByteIterator;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import java.io.DataOutputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;

import static org.wildfly.common.Assert.checkNotNullParam;
import static org.wildfly.security._private.ElytronMessages.log;
import static org.wildfly.security.http.HttpScopeNotification.SessionNotificationType.INVALIDATED;

/**
 * <p>A {@link SingleSignOnSessionFactory} that relies on a single {@link Map} to store and manage {@link SingleSignOnSession}.
 *
 * <p>This implementation also supports single logout in order to invalidate local sessions for each participant of a single sign-on session, where participants
 * represent the applications with active sessions associated with a given single sign-on session.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class DefaultSingleSignOnSessionFactory implements SingleSignOnSessionFactory {

    private static final HostnameVerifier DEFAULT_HOSTNAME_VERIFIER = (s, sslSession) -> true;
    private static final Function<SecurityIdentity, String> DEFAULT_SESSION_IDENTIFIER_FACTORY = identity -> UUID.randomUUID().toString();
    private static final String DEFAULT_SIGNATURE_ALGORITHM = "SHA512withRSA";
    private static final String LOGOUT_REQUEST_PARAMETER = "ely_logout_message";
    private static final String SESSION_INVALIDATING_ATTRIBUTE = DefaultSingleSignOnSessionFactory.class.getName() + ".INVALIDATING";

    private final Map<String, Object> cache;
    private final KeyStore keyStore;
    private final Function<SecurityIdentity, String> identifierFactory;
    private final SSLContext sslContext;
    private final HostnameVerifier hostnameVerifier;
    private final String keyAlias;
    private final String keyPassword;

    public DefaultSingleSignOnSessionFactory(Map<String, Object> cache, KeyStore keyStore, String keyAlias, String keyPassword, SSLContext sslContext) {
        this(cache, keyStore, keyAlias, keyPassword, sslContext, DEFAULT_HOSTNAME_VERIFIER, DEFAULT_SESSION_IDENTIFIER_FACTORY);
    }

    public DefaultSingleSignOnSessionFactory(Map<String, Object> cache, KeyStore keyStore, String keyAlias, String keyPassword, SSLContext sslContext, HostnameVerifier hostnameVerifier, Function<SecurityIdentity, String> identifierFactory) {
        this.cache = checkNotNullParam("cache", cache);
        this.keyStore = checkNotNullParam("keyStore", keyStore);
        this.keyAlias = checkNotNullParam("keyAlias", keyAlias);
        this.keyPassword = checkNotNullParam("keyPassword", keyPassword);

        try {
            Key privateKey = keyStore.getKey(keyAlias, keyPassword.toCharArray());

            if (!(privateKey instanceof PrivateKey && "RSA".equals(privateKey.getAlgorithm()))) {
                throw log.httpMechSsoRSAPrivateKeyExpected(keyAlias);
            }

            Certificate certificate = keyStore.getCertificate(keyAlias);

            if (certificate == null) {
                throw log.httpMechSsoCertificateExpected(keyAlias);
            }
        } catch (Exception cause) {
            throw log.httpMechSsoFailedObtainKeyFromKeyStore(keyAlias, cause);
        }

        this.identifierFactory = checkNotNullParam("identifierFactory", identifierFactory);
        this.sslContext = sslContext;
        this.hostnameVerifier = hostnameVerifier;
    }

    @Override
    public SingleSignOnSession findById(String id, HttpServerRequest request) {
        checkNotNullParam("id", id);
        checkNotNullParam("request", request);

        if (cache.containsKey(id)) {
            log.debugf("Found SSO session with ID [%s]", id);
            return new AbstractSingleSignOnSession(request) {
                @Override
                public String getId() {
                    return id;
                }

                @Override
                public void put(SecurityIdentity identity) {
                    DefaultSingleSignOnSessionEntry entry = (DefaultSingleSignOnSessionEntry) cache.get(getId());
                    CachedIdentity cachedIdentity = entry.getCachedIdentity();
                    SecurityIdentity securityIdentity = cachedIdentity.getSecurityIdentity();

                    if (securityIdentity == null) {
                        log.debugf("Updating local copy of SSO [%s] with a new identity", id);
                        entry.setCachedIdentity(new CachedIdentity(cachedIdentity.getMechanismName(), identity));
                    }

                    addLocalSessionIfNecessary(entry);
                }
            };
        }

        return null;
    }

    @Override
    public SingleSignOnSession create(HttpServerRequest request, String mechanismName) {
        checkNotNullParam("request", request);
        checkNotNullParam("mechanismName", mechanismName);

        return new AbstractSingleSignOnSession(request) {
            private String id;

            @Override
            public String getId() {
                return id;
            }

            @Override
            public void put(SecurityIdentity identity) {
                id = identifierFactory.apply(identity);
                log.debugf("Creating new SSO [%s]", id);
                addLocalSessionIfNecessary(new DefaultSingleSignOnSessionEntry(new CachedIdentity(mechanismName, identity)));
            }
        };
    }

    @Override
    public void logout(String id) {
        checkNotNullParam("id", id);
        log.debugf("Performing a single logout for SSO [%s]", id);
        DefaultSingleSignOnSessionEntry entry = (DefaultSingleSignOnSessionEntry) cache.get(id);

        entry.getLocalSessions().forEach(localSessionId -> {
            String participant = localSessionId.substring(0, localSessionId.lastIndexOf(":"));

            try {
                URL participantUrl = new URL(participant);
                boolean isHttps = participantUrl.getProtocol().equalsIgnoreCase("https");
                HttpURLConnection connection = (HttpURLConnection) participantUrl.openConnection();

                if (isHttps) {
                    HttpsURLConnection https = (HttpsURLConnection) connection;
                    https.setSSLSocketFactory(sslContext.getSocketFactory());
                    https.setHostnameVerifier(hostnameVerifier);
                }

                connection.setRequestMethod("POST");
                connection.setDoOutput(true);
                connection.setAllowUserInteraction(false);
                connection.setConnectTimeout(10000);
                connection.setReadTimeout(10000);
                connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

                StringBuilder parameterBuilder = new StringBuilder();

                parameterBuilder.append(LOGOUT_REQUEST_PARAMETER).append("=").append(createLogoutRequest(localSessionId));

                connection.setRequestProperty("Content-Length", Integer.toString(parameterBuilder.length()));

                try (
                    OutputStream outputStream = connection.getOutputStream();
                    DataOutputStream wr = new DataOutputStream(outputStream);
                ) {
                    wr.writeBytes(parameterBuilder.toString());
                }

                connection.getInputStream().close();
            } catch (Exception cause) {
                log.warnHttpMechSsoFailedLogoutParticipant(participant.toString(), cause);
            }
        });

        cache.remove(id);
    }

    private abstract class AbstractSingleSignOnSession implements SingleSignOnSession {

        private final HttpServerRequest request;

        AbstractSingleSignOnSession(HttpServerRequest request) {
            this.request = request;
        }

        @Override
        public Set<String> getLocalSessions() {
            DefaultSingleSignOnSessionEntry entry = getEntry();

            if (entry == null) {
                return Collections.emptySet();
            }

            return Collections.unmodifiableSet(entry.getLocalSessions());
        }

        @Override
        public String getLocalSession() {
            DefaultSingleSignOnSessionEntry entry = getEntry();

            if (entry == null) {
                return null;
            }

            HttpScope scope = request.getScope(Scope.SESSION);

            if (scope == null) {
                return null;
            }

            return entry.getLocalSessions().stream().filter(localSession -> localSession.endsWith(scope.getID())).findFirst().orElse(null);
        }

        @Override
        public CachedIdentity get() {
            DefaultSingleSignOnSessionEntry entry = getEntry();

            if (entry == null) {
                return null;
            }

            return entry.getCachedIdentity();
        }

        @Override
        public CachedIdentity remove() {
            DefaultSingleSignOnSessionEntry entry = getEntry();

            if (entry == null) {
                return null;
            }

            DefaultSingleSignOnSessionEntry destroyed = (DefaultSingleSignOnSessionEntry) cache.remove(getId());

            invalidateLocalSession(request.getScope(Scope.SESSION));

            if (destroyed == null) {
                return null;
            }

            return destroyed.getCachedIdentity();
        }

        @Override
        public boolean logout() {
            String logoutMessage = request.getFirstParameterValue(LOGOUT_REQUEST_PARAMETER);

            if (logoutMessage == null) {
                return false;
            }

            log.debugf("Invalidating local session [%s] from SSO [%s]", getLocalSession(), getId());

            try {
                String localSessionId = verifyLogoutRequest(logoutMessage);
                HttpScope scope = request.getScope(Scope.SESSION, localSessionId);

                if (scope == null) {
                    return false;
                }

                invalidateLocalSession(scope);
            } catch (Exception e) {
                log.errorHttpMechSsoFailedInvalidateLocalSession(e);
            }

            request.authenticationInProgress(response -> response.setStatusCode(200));

            return true;
        }

        void removeLocalSession(String localSessionId) {
            DefaultSingleSignOnSessionEntry entry = getEntry();

            if (entry != null) {
                log.debugf("Removing local session [%s] from SSO [%s]", localSessionId, getId());
                entry.getLocalSessions().remove(localSessionId);

                if (entry.getLocalSessions().isEmpty()) {
                    log.debugf("Destroying SSO [%s]. SSO is not associated with participants", getId());
                    remove();
                } else if (cache.containsKey(getId())) {
                    cache.put(getId(), entry);
                }
            }
        }

        void addLocalSessionIfNecessary(DefaultSingleSignOnSessionEntry entry) {
            if (getLocalSession() == null) {
                HttpScope scope = request.getScope(Scope.SESSION);

                if (scope == null) {
                    scope = request.create(Scope.SESSION);
                }

                String localSessionId = createLocalSessionId(scope.getID(), request);

                entry.getLocalSessions().add(localSessionId);

                String id = getId();

                scope.registerForNotification(notification -> {
                    HttpScope sessionScope = notification.getScope(Scope.SESSION);
                    boolean invalidating = sessionScope.getAttachment(SESSION_INVALIDATING_ATTRIBUTE) != null;

                    removeLocalSession(localSessionId);

                    if (notification.isOfType(INVALIDATED) && !invalidating) {
                        DefaultSingleSignOnSessionFactory.this.logout(id);
                    }
                });

                cache.put(getId(), entry);
                log.debugf("Updating local sessions for SSO [%s]. New local session [%s]. Local sessions: [%s]", getId(), localSessionId, entry.getLocalSessions());
            }
        }

        void invalidateLocalSession(HttpScope scope) {
            if (scope == null) {
                return;
            }
            scope.setAttachment(SESSION_INVALIDATING_ATTRIBUTE, true);
            scope.invalidate();
            log.debugf("Local session [%s] invalidated for SSO [%s]", scope.getID(), getId());
        }

        DefaultSingleSignOnSessionEntry getEntry() {
            String id = getId();

            if (id == null) {
                return null;
            }

            return (DefaultSingleSignOnSessionEntry) cache.get(id);
        }

        String createLocalSessionId(String localSessionId, HttpServerRequest request) {
            return createParticipantUrl(request) + ":" + localSessionId;
        }

        String createParticipantUrl(HttpServerRequest request) {
            String scheme = request.getRequestURI().getScheme();
            String host = request.getRequestURI().getHost();
            int port = request.getRequestURI().getPort();
            String path = request.getRequestURI().getPath();

            if (path == null) {
                path = "/";
            }

            String[] paths = path.split("/");

            if (paths.length > 1) {
                path = "/" + paths[1];
            }

            return scheme + "://" + host + ":" + port + path;
        }
    }

    public static class DefaultSingleSignOnSessionEntry implements Serializable {

        private static final long serialVersionUID = 6051431359445846593L;

        private CachedIdentity cachedIdentity;
        private final Set<String> localSessions;

        public DefaultSingleSignOnSessionEntry(CachedIdentity cachedIdentity) {
            this.cachedIdentity = cachedIdentity;
            this.localSessions = new HashSet<>();
        }

        CachedIdentity getCachedIdentity() {
            return cachedIdentity;
        }

        void setCachedIdentity(CachedIdentity cachedIdentity) {
            this.cachedIdentity = cachedIdentity;
        }

        Set<String> getLocalSessions() {
            return localSessions;
        }
    }

    private String createLogoutRequest(String localSessionId) throws Exception {
        String participant = localSessionId.substring(0, localSessionId.lastIndexOf(":"));
        String participantSessionId = localSessionId.substring(participant.length() + 1);
        Signature signature = Signature.getInstance(DEFAULT_SIGNATURE_ALGORITHM);
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyAlias, keyPassword.toCharArray());

        signature.initSign(privateKey);

        Base64.Encoder urlEncoder = Base64.getUrlEncoder();

        return participantSessionId + "." + ByteIterator.ofBytes(urlEncoder.encode(ByteIterator.ofBytes((participantSessionId).getBytes())
                .sign(signature).drain())).asUtf8String().drainToString();
    }

    private String verifyLogoutRequest(String logoutRequest) throws Exception {
        String[] actionParts = logoutRequest.split("\\.");
        String localSessionId = ByteIterator.ofBytes(actionParts[0].getBytes()).asUtf8String().drainToString();
        Signature signature = Signature.getInstance(DEFAULT_SIGNATURE_ALGORITHM);

        signature.initVerify(keyStore.getCertificate(keyAlias));
        signature.update(localSessionId.getBytes());

        Base64.Decoder urlDecoder = Base64.getUrlDecoder();
        boolean verify = ByteIterator.ofBytes(urlDecoder.decode(actionParts[1].getBytes())).verify(signature);

        if (verify) {
            return localSessionId;
        }

        throw log.httpMechSsoInvalidLogoutMessage(localSessionId);
    }
}
