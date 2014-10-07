/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2013 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.manager;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

import org.junit.Test;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class TestStackInspector {

    @Test
    public void simpleTest() {
        final StackInspector i = StackInspector.getInstance();
        assertEquals(i.getCallerClass(0), TestStackInspector.class);
        assertNotEquals(i.getCallerClass(1), TestStackInspector.class);

        assertEquals(i.getCallStack()[0], TestStackInspector.class);
        assertNotEquals(i.getCallStack()[1], TestStackInspector.class);

        assertEquals(i.getCallStack(0)[0], TestStackInspector.class);
        assertNotEquals(i.getCallStack(0)[1], TestStackInspector.class);

        assertEquals(i.getCallerClass(1), i.getCallStack(1)[0]);
        assertEquals(i.getCallerClass(1), i.getCallStack(0)[1]);
        assertEquals(i.getCallerClass(1), i.getCallStack(0, 2)[1]);

        assertEquals(1, i.getCallStack(0, 1).length);
        assertEquals(2, i.getCallStack(0, 2).length);
        assertEquals(3, i.getCallStack(0, 3).length);
    }
}
