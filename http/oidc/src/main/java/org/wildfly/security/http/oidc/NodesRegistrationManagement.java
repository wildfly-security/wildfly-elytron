/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2021 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wildfly.security.http.oidc;

import static org.wildfly.security.http.oidc.ElytronMessages.log;
import static org.wildfly.security.http.oidc.Oidc.getCurrentTimeInSeconds;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Used for clustering with Keycloak.
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class NodesRegistrationManagement {

    private final Map<String, NodeRegistrationContext> nodeRegistrations = new ConcurrentHashMap<String, NodeRegistrationContext>();
    private final ExecutorService executor = Executors.newSingleThreadExecutor();

    // Sending registration event during first request to application or if re-registration is needed
    public void tryRegister(final OidcClientConfiguration resolvedDeployment) {
        if (resolvedDeployment.isRegisterNodeAtStartup()) {
            final String registrationUri = resolvedDeployment.getRegisterNodeUrl();
            if (needRefreshRegistration(registrationUri, resolvedDeployment)) {
                Runnable runnable = new Runnable() {

                    @Override
                    public void run() {
                        // Need to check it again in case that executor triggered by other thread already finished computation in the meantime
                        if (needRefreshRegistration(registrationUri, resolvedDeployment)) {
                            sendRegistrationEvent(resolvedDeployment);
                        }
                    }
                };
                executor.execute(runnable);
            }
        }
    }

    private boolean needRefreshRegistration(String registrationUri, OidcClientConfiguration resolvedDeployment) {
        NodeRegistrationContext currentRegistration = nodeRegistrations.get(registrationUri);
        /// We don't yet have any registration for this node
        if (currentRegistration == null) {
            return true;
        }

        return currentRegistration.lastRegistrationTime + resolvedDeployment.getRegisterNodePeriod() < getCurrentTimeInSeconds();
    }

    /**
     * Called during undeployment or server stop. De-register from all previously registered deployments
     */
    public void stop() {
        executor.shutdownNow();

        Collection<NodeRegistrationContext> allRegistrations = nodeRegistrations.values();
        for (NodeRegistrationContext registration : allRegistrations) {
            sendUnregistrationEvent(registration.resolvedDeployment);
        }
    }

    protected void sendRegistrationEvent(OidcClientConfiguration deployment) {
        // This method is invoked from single-thread executor, so no synchronization is needed
        // However, it could happen that the same deployment was submitted more than once to that executor
        // Hence we need to recheck that the registration is really needed
        final String registrationUri = deployment.getRegisterNodeUrl();
        if (! needRefreshRegistration(registrationUri, deployment)) {
            return;
        }
        if (Thread.currentThread().isInterrupted()) {
            return;
        }

        log.debug("Sending registration event right now");

        String host = getHostName();
        try {
            ServerRequest.invokeRegisterNodeForKeycloak(deployment, host);
            NodeRegistrationContext regContext = new NodeRegistrationContext(getCurrentTimeInSeconds(), deployment);
            nodeRegistrations.put(deployment.getRegisterNodeUrl(), regContext);
            log.debugf("Node '%s' successfully registered in Keycloak", host);
        } catch (ServerRequest.HttpFailure failure) {
            log.error("failed to register node to keycloak");
            log.error("status from server: " + failure.getStatus());
            if (failure.getError() != null) {
                log.error("   " + failure.getError());
            }
        } catch (IOException e) {
            log.error("failed to register node to keycloak", e);
        }
    }

    protected boolean sendUnregistrationEvent(OidcClientConfiguration deployment) {
        log.debug("Sending Unregistration event right now");

        String host = getHostName();
        try {
            ServerRequest.invokeUnregisterNodeForKeycloak(deployment, host);
            log.debugf("Node '%s' successfully unregistered from Keycloak", host);
            return true;
        } catch (ServerRequest.HttpFailure failure) {
            log.error("failed to unregister node from keycloak");
            log.error("status from server: " + failure.getStatus());
            if (failure.getError() != null) {
                log.error("   " + failure.getError());
            }
            return false;
        } catch (IOException e) {
            log.error("failed to unregister node from keycloak", e);
            return false;
        }
    }

    public static class NodeRegistrationContext {

        private final Integer lastRegistrationTime;
        // deployment instance used for registration request
        private final OidcClientConfiguration resolvedDeployment;

        public NodeRegistrationContext(Integer lastRegTime, OidcClientConfiguration deployment) {
            this.lastRegistrationTime = lastRegTime;
            this.resolvedDeployment = deployment;
        }
    }

    private static String getHostName() {
        return getHostNameImpl().trim().toLowerCase();
    }

    private static String getHostNameImpl() {
        // Return bind address if available
        String bindAddr = System.getProperty("jboss.bind.address");
        if (bindAddr != null && !bindAddr.trim().equals("0.0.0.0")) {
            return bindAddr;
        }

        // Fallback to qualified name
        String qualifiedHostName = System.getProperty("jboss.qualified.host.name");
        if (qualifiedHostName != null) {
            return qualifiedHostName;
        }

        // If not on jboss env, let's try other possible fallbacks
        // POSIX-like OSes including Mac should have this set
        qualifiedHostName = System.getenv("HOSTNAME");
        if (qualifiedHostName != null) {
            return qualifiedHostName;
        }

        // Certain versions of Windows
        qualifiedHostName = System.getenv("COMPUTERNAME");
        if (qualifiedHostName != null) {
            return qualifiedHostName;
        }

        try {
            return NetworkUtils.canonize(getLocalHost().getHostName());
        } catch (UnknownHostException uhe) {
            uhe.printStackTrace();
            return "unknown-host.unknown-domain";
        }
    }

    /**
     * Methods returns InetAddress for localhost
     *
     * @return InetAddress of the localhost
     * @throws UnknownHostException if localhost could not be resolved
     */
    private static InetAddress getLocalHost() throws UnknownHostException {
        InetAddress addr;
        try {
            addr = InetAddress.getLocalHost();
        } catch (ArrayIndexOutOfBoundsException e) {
            addr = InetAddress.getByName(null);
        }
        return addr;
    }
}
