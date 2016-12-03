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

package org.wildfly.security.credential.store.impl;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.wildfly.security._private.ElytronMessages;

/**
 * Compatibility class for PicketBox VAULT.dat files, which consist of a single serialized instance of
 * {@link #PICKETBOX_CLASS_NAME}.
 */
final class VaultData implements Serializable {
    private static final long serialVersionUID = -1L;

    static final String PICKETBOX_CLASS_NAME = "org.picketbox.plugins.vault.SecurityVaultData";

    private transient Map<String, byte[]> vaultData;

    VaultData(final Map<String, byte[]> vaultData) {
        this.vaultData = vaultData;
    }

    VaultData() {
    }

    Map<String, byte[]> getVaultData() {
        return vaultData;
    }

    @SuppressWarnings("unchecked")
    private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
        // do NOT read fields, against spec, for compatibility (though there are none anyway)
        int version = ((Integer) ois.readObject()).intValue();
        if (version == 1) {
            this.vaultData = new HashMap<>((Map<String, byte[]>)ois.readObject());
        } else {
            throw ElytronMessages.log.unableToCreateKeyStore(null);
        }
    }

    private void writeObject(ObjectOutputStream oos) throws IOException {
        // do NOT write fields, against spec, for compatibility (though there are none anyway)
        oos.writeObject(Integer.valueOf(1));
        oos.writeObject(new ConcurrentHashMap<>(vaultData));
    }
}
