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
import java.io.ObjectOutputStream;
import java.io.ObjectStreamClass;
import java.io.ObjectStreamConstants;
import java.io.OutputStream;

final class VaultObjectOutputStream extends ObjectOutputStream {

    VaultObjectOutputStream(final OutputStream out) throws IOException {
        super(out);
    }

    protected void writeClassDescriptor(final ObjectStreamClass desc) throws IOException {
        if (desc.forClass() == VaultData.class) {
            writeUTF(VaultData.PICKETBOX_CLASS_NAME);
            writeLong(-1L);
            writeByte(ObjectStreamConstants.SC_SERIALIZABLE | ObjectStreamConstants.SC_WRITE_METHOD);
            writeShort(0); // no fields
        } else {
            super.writeClassDescriptor(desc);
        }
    }
}
