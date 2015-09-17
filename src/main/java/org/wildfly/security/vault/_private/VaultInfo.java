/*
 * JBoss, Home of Professional Open Source
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
package org.wildfly.security.vault._private;

import org.wildfly.security.storage.PasswordStorage;

import java.net.URI;

/**
 * Class to hold all information about vault configuration before initialized.
 * Used for lazy initialization of {@link PasswordStorage} instances.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>.
 */
class VaultInfo {
    volatile PasswordStorage vault;
    URI vaultUri;
    String providerName;
    String storageType;
    String base;
}
