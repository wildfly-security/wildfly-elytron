/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017 Red Hat, Inc., and individual contributors
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

import static org.wildfly.common.Assert.checkNotNullParam;

import static org.wildfly.security._private.ElytronMessages.log;
import static org.wildfly.security.http.HttpScopeNotification.SessionNotificationType.INVALIDATED;

import java.io.DataOutputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.function.Function;

import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.cache.CachedIdentity;
import org.wildfly.security.http.HttpScope;
import org.wildfly.security.http.HttpServerRequest;
import org.wildfly.security.http.Scope;

/**
 * {@link SingleSignOnSession} that delegates its persistence strategy to a {@link SingleSignOnManager}.
 * {@link SingleSignOn} entries are created lazily in response to {@link #put(SecurityIdentity)}.
 * <br/>
 * This implementation supports single logout in order to invalidate local sessions for each participant of a single sign-on session, where participants
 * represent the applications with active sessions associated with a given single sign-on session.
 * @author Paul Ferraro
 */
public class DefaultSingleSignOnSession implements SingleSignOnSession {
    private static final String LOGOUT_REQUEST_PARAMETER = "ely_logout_message";
    private static final String SESSION_INVALIDATING_ATTRIBUTE = DefaultSingleSignOnSessionFactory.class.getName() + ".INVALIDATING";
    private static final Boolean SINGLE_SIGN_ON_KEY = Boolean.TRUE;

    private final HttpServerRequest request;
    // Serves as a lazy initializable atomic reference
    private final ConcurrentMap<Boolean, SingleSignOn> map = new ConcurrentHashMap<>(1);
    private final SingleSignOnSessionContext context;
    private final Function<SecurityIdentity, SingleSignOn> ssoFactory;

    public DefaultSingleSignOnSession(SingleSignOnSessionContext context, HttpServerRequest request, String mechanismName) {
        this.context = checkNotNullParam("context", context);
        this.request = checkNotNullParam("request", request);
        checkNotNullParam("mechanismName", mechanismName);
        this.ssoFactory = identity -> context.getSingleSignOnManager().create(mechanismName, identity);
    }

    public DefaultSingleSignOnSession(SingleSignOnSessionContext context, HttpServerRequest request, SingleSignOn sso) {
        this.context = checkNotNullParam("context", context);
        this.map.put(SINGLE_SIGN_ON_KEY, sso);
        this.request = checkNotNullParam("request", request);
        checkNotNullParam("sso", sso);
        this.ssoFactory = identity -> sso;
    }

    @Override
    public String getId() {
        SingleSignOn sso = this.map.get(SINGLE_SIGN_ON_KEY);
        return (sso != null) ? sso.getId() : null;
    }

    @Override
    public CachedIdentity get() {
        SingleSignOn sso = this.map.get(SINGLE_SIGN_ON_KEY);
        return (sso != null) ? getCachedIdentity(sso) : null;
    }

    @Override
    public void put(SecurityIdentity identity) {
        SingleSignOn sso = this.map.computeIfAbsent(SINGLE_SIGN_ON_KEY, key -> this.ssoFactory.apply(identity));
        sso.setIdentity(identity);

        HttpScope scope = this.request.getScope(Scope.SESSION);

        if (!scope.exists()) {
            scope.create();
        }

        URI uri = this.request.getRequestURI();
        String sessionId = scope.getID();
        String applicationId = this.request.getScope(Scope.APPLICATION).getID();
        if (sso.addParticipant(applicationId, sessionId, uri)) {
            String id = sso.getId();
            log.debugf("Updating local sessions for SSO [%s]. New local session [%s]. Local sessions: [%s]", id, sessionId, sso.getParticipants());

            scope.registerForNotification(notification -> {
                HttpScope sessionScope = notification.getScope(Scope.SESSION);
                Map<String, Map.Entry<String, URI>> logoutTargets = Collections.emptyMap();

                try (SingleSignOn target = this.context.getSingleSignOnManager().find(id)) {
                    if (target != null) {
                        Map.Entry<String, URI> localParticipant = target.removeParticipant(applicationId);
                        if (localParticipant != null) {
                            log.debugf("Removed local session [%s] from SSO [%s]", localParticipant.getKey(), target.getId());
                        }
                        if (sessionScope.getAttachment(SESSION_INVALIDATING_ATTRIBUTE) == null) {
                            Map<String, Map.Entry<String, URI>> participants = target.getParticipants();
                            if (participants.isEmpty()) {
                                log.debugf("Destroying SSO [%s]. SSO is not associated with participants", target.getId());
                                target.invalidate();
                            } else if (notification.isOfType(INVALIDATED)) {
                                logoutTargets = participants;
                            }
                        }
                    }
                }

                if (!logoutTargets.isEmpty()) {
                    logoutTargets.forEach((participantId, participant) -> {
                        String remoteSessionId = participant.getKey();
                        URI remoteURI = participant.getValue();
                        try {
                            URL participantUrl = remoteURI.toURL();
                            HttpURLConnection connection = (HttpURLConnection) participantUrl.openConnection();

                            this.context.configureLogoutConnection(connection);

                            connection.setRequestMethod("POST");
                            connection.setDoOutput(true);
                            connection.setAllowUserInteraction(false);
                            connection.setConnectTimeout(10000);
                            connection.setReadTimeout(10000);
                            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

                            StringBuilder parameterBuilder = new StringBuilder();

                            parameterBuilder.append(LOGOUT_REQUEST_PARAMETER).append("=").append(this.context.createLogoutParameter(remoteSessionId));

                            connection.setRequestProperty("Content-Length", Integer.toString(parameterBuilder.length()));

                            try (
                                OutputStream outputStream = connection.getOutputStream();
                                DataOutputStream wr = new DataOutputStream(outputStream);
                            ) {
                                wr.writeBytes(parameterBuilder.toString());
                            }

                            connection.getInputStream().close();
                        } catch (Exception cause) {
                            log.warnHttpMechSsoFailedLogoutParticipant(remoteURI.toString(), cause);
                        }
                    });

                    try (SingleSignOn target = this.context.getSingleSignOnManager().find(id)) {
                        if (target != null) {
                            // If all logout requests were successful, then there should be no participants, and we can invalidate the SSO
                            if (!target.getParticipants().isEmpty()) {
                                log.debugf("Destroying SSO [%s]. Participant list not empty.", target.getId());
                            } else {
                                log.debugf("Destroying SSO [%s]. SSO is no longer associated with any participants", target.getId());
                            }
                            target.invalidate();
                        }
                    }
                }
            });
        }
    }

    @Override
    public CachedIdentity remove() {
        SingleSignOn sso = this.map.get(SINGLE_SIGN_ON_KEY);

        if (sso == null) return null;

        sso.invalidate();

        HttpScope scope = this.request.getScope(Scope.SESSION);
        if (scope.exists()) {
            invalidateLocalSession(scope);
        }

        return getCachedIdentity(sso);
    }

    @Override
    public boolean logout() {
        String logoutMessage = this.request.getFirstParameterValue(LOGOUT_REQUEST_PARAMETER);

        if (logoutMessage == null) {
            return false;
        }

        try {
            String localSessionId = this.context.verifyLogoutParameter(logoutMessage);
            HttpScope scope = this.request.getScope(Scope.SESSION, localSessionId);

            if (!scope.exists()) {
                return false;
            }

            log.debugf("Invalidating local session [%s] from SSO [%s]", localSessionId, this.getId());

            invalidateLocalSession(scope);
        } catch (Exception e) {
            log.errorHttpMechSsoFailedInvalidateLocalSession(e);
        }

        this.request.authenticationInProgress(response -> response.setStatusCode(200));

        return true;
    }

    @Override
    public void close() {
        Optional.ofNullable(this.map.remove(SINGLE_SIGN_ON_KEY)).ifPresent(SingleSignOn::close);
    }

    void invalidateLocalSession(HttpScope scope) {
        scope.setAttachment(SESSION_INVALIDATING_ATTRIBUTE, true);
        scope.invalidate();
        log.debugf("Local session [%s] invalidated for SSO [%s]", scope.getID(), this.getId());
    }

    private static CachedIdentity getCachedIdentity(SingleSignOn sso) {
        String mechanism = sso.getMechanism();
        SecurityIdentity identity = sso.getIdentity();
        return (identity != null) ? new CachedIdentity(mechanism, identity) : new CachedIdentity(mechanism, new NamePrincipal(sso.getName()));
    }
}
