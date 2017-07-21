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
package org.wildfly.security.util;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.temporal.TemporalAmount;
import java.time.temporal.TemporalUnit;

/**
 * A {@link Clock} implementation that offers controlled shifts of the time returned by {@link #instant()} via
 * {@code plus*} and {@code minus*} methods. For testing purposes of course.
 *
 * @author <a href="https://github.com/ppalaga">Peter Palaga</a>
 */
public class TestClock extends Clock {
    private volatile Instant instant;
    private final Object instantLock = new Object();
    private final ZoneId zone;

    public TestClock(Instant instant) {
        this(ZoneOffset.UTC);
        this.instant = instant;
    }

    private TestClock(ZoneId zone) {
        super();
        this.zone = zone;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof TestClock) {
            return zone.equals(((TestClock) obj).zone);
        }
        return false;
    }

    @Override
    public ZoneId getZone() {
        return zone;
    }

    @Override
    public int hashCode() {
        return zone.hashCode() + 1;
    }

    @Override
    public Instant instant() {
        return instant;
    }

    @Override
    public long millis() {
        return instant.toEpochMilli();
    }

    public TestClock minus(long amountToSubtract, TemporalUnit unit) {
        synchronized (instantLock) {
            this.instant = this.instant.minus(amountToSubtract, unit);
        }
        return this;
    }

    public TestClock minus(TemporalAmount amountToSubtract) {
        synchronized (instantLock) {
            this.instant = this.instant.minus(amountToSubtract);
        }
        return this;
    }

    public TestClock minusMillis(long millisToSubtract) {
        synchronized (instantLock) {
            this.instant = this.instant.minusMillis(millisToSubtract);
        }
        return this;
    }

    public TestClock minusNanos(long nanosToSubtract) {
        this.instant = this.instant.minusNanos(nanosToSubtract);
        return this;
    }

    public TestClock minusSeconds(long secondsToSubtract) {
        synchronized (instantLock) {
            this.instant = this.instant.minusSeconds(secondsToSubtract);
        }
        return this;
    }

    public TestClock plus(long amountToAdd, TemporalUnit unit) {
        synchronized (instantLock) {
            this.instant = this.instant.plus(amountToAdd, unit);
        }
        return this;
    }

    public TestClock plus(TemporalAmount amountToAdd) {
        this.instant = this.instant.plus(amountToAdd);
        return this;
    }

    public TestClock plusMillis(long millisToAdd) {
        synchronized (instantLock) {
            this.instant = this.instant.plusMillis(millisToAdd);
        }
        return this;
    }

    public TestClock plusNanos(long nanosToAdd) {
        synchronized (instantLock) {
            this.instant = this.instant.plusNanos(nanosToAdd);
        }
        return this;
    }

    public TestClock plusSeconds(long secondsToAdd) {
        synchronized (instantLock) {
            this.instant = this.instant.plusSeconds(secondsToAdd);
        }
        return this;
    }

    @Override
    public String toString() {
        return "TestClock [instant=" + instant + ", zone=" + zone + "]";
    }

    @Override
    public Clock withZone(ZoneId zone) {
        if (zone.equals(this.zone)) {
            return this;
        }
        return new TestClock(zone);
    }
}