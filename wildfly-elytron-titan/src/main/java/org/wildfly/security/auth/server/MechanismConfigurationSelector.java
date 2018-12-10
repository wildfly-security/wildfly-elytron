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
package org.wildfly.security.auth.server;

import java.util.function.Predicate;

/**
 * A selector to choose which {@link MechanismConfiguration} to use based on information know about the current authentication
 * attempt.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@FunctionalInterface
public interface MechanismConfigurationSelector {

    /**
     * Select the {@link MechanismConfiguration} to use for the current authentication attempt.
     *
     * @param mechanismInformation information about the current authentication attempt.
     * @return the {@link MechanismConfiguration} to use for the current authentication attempt.
     */
    MechanismConfiguration selectConfiguration(MechanismInformation mechanismInformation);

    /**
     * Create a simple {@link MechanismConfigurationSelector} that is paired with a {@link Predicate} to
     * test if the configuration should be used for the supplied information.
     *
     * @param predicate the predicate to test the {@code MechanismInformation}
     * @param mechanismConfiguration the {@code MechanismConfiguration} to return if the test passes.
     * @return a simple {@code MechanismConfigurationSelector} backed by a {@link Predicate} to test if the configuration should be returned.
     */
    static MechanismConfigurationSelector predicateSelector(final Predicate<MechanismInformation> predicate, final MechanismConfiguration mechanismConfiguration) {
        return information -> predicate.test(information) ? mechanismConfiguration : null;
    }

    /**
     * Create a {@link MechanismConfigurationSelector} that is an aggregation of other selectors, when called the selectors will be called in order and the first
     * {@link MechanismConfiguration} returned will be used.
     *
     * @param configurationSelectors the {@link MechanismConfigurationSelector} instances to aggregate.
     * @return the {@link MechanismConfigurationSelector} that is an aggregation of the supplied selectors.
     */
    static MechanismConfigurationSelector aggregate(final MechanismConfigurationSelector ... configurationSelectors) {
        return information -> {
            for (MechanismConfigurationSelector current : configurationSelectors) {
                MechanismConfiguration configuration = current.selectConfiguration(information);
                if (configuration != null) {
                    return configuration;
                }
            }
            return null;
        };
    }

    /**
     * Create a constant {@link MechanismConfigurationSelector} which will always return the same {@link MechanismConfiguration}
     * instance.
     *
     * @param mechanismConfiguration a configuration which will be always returned by created selector
     * @return the new configuration selector
     */
    static MechanismConfigurationSelector constantSelector(final MechanismConfiguration mechanismConfiguration) {
        return information -> mechanismConfiguration;
    }

}
