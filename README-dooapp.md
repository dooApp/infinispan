# Infinispan 7.2.x — DooApp fork

Fork of Infinispan 7.2 maintained for the DooApp desktop stack, which uses the embedded cache with
`SingleFileStore` as a persistence layer. Versions are `7.2.N.dooapp` instead of upstream `7.2.N.Final`;
released artifacts carry no classifier, the version suffix is the only marker.

**Published artifacts:** `infinispan-bom`, `infinispan-parent`, `infinispan-commons`, `infinispan-core`.
Nothing else is published — in particular not `infinispan-cachestore-jdbc` / `-leveldb`. The other modules of
the reactor are kept only so every pom stays resolvable.

Because customer data is already on disk, **on-disk and on-wire compatibility is the hard constraint**:
externalizer ids, command ids and the `SingleFileStore` layout are frozen.

## Runtime requirements

Both of the following apply from `7.2.8.dooapp` onwards, and both are silent failures if missed.

### 1. Java 9 or later

`org.infinispan.security.Security` uses `java.lang.StackWalker` (a JDK 9 API) to identify the caller of
`doPrivileged`, because `sun.reflect.Reflection` was dropped in JDK 9 and JEP 486 permanently disables the
security manager in JDK 24+.

The artifact still *declares* Java 8 (`version.java` is `1.8`, and `maven-bundle-plugin` publishes
`osgi.ee=JavaSE 1.8`), so nothing stops it from being put on a Java 8 classpath. On a Java 8 JVM `Security`
then dies at class initialization with `NoClassDefFoundError: java/lang/StackWalker`, and since every
`SecurityActions` helper of `infinispan-core` routes through it, practically no cache operation works.

### 2. `--add-opens` on the launching JVM

jboss-marshalling 2.0.6 (`reflect.JDKSpecific$SerMethods`) calls `setAccessible` on the serialization members
of every `Serializable` class it marshals — the no-arg constructor of the first non-serializable superclass,
and `readObject`/`writeObject`. On JDK 9+ those members are not accessible unless the package is open, and the
write fails with `InaccessibleObjectException` wrapped in a `PersistenceException`.

Every JVM embedding the cache must therefore pass:

```
--add-opens java.base/java.util=ALL-UNNAMED
--add-opens java.base/java.util.concurrent=ALL-UNNAMED
--add-opens java.base/java.util.concurrent.locks=ALL-UNNAMED
```

This is a minimal set, measured one JVM per type. Without them, values that have a dedicated Infinispan
externalizer (`String`, `Integer`, `HashMap`, `ArrayList`, `HashSet`, `TreeMap`) still write correctly, while
**any plain application `Serializable` POJO**, `java.util.Date` and `ConcurrentHashMap` fail. `java.util` alone
is not enough (a POJO then trips on `ConcurrentHashMap.readObject`), and `.locks` is what a `ConcurrentHashMap`
*value* needs, its serialized form carrying a `Segment extends ReentrantLock`.

A jar manifest `Add-Opens` would only cover `java -jar` launches, so the flags belong on the launcher command
line or in `JAVA_TOOL_OPTIONS`. Consumers must check this when moving to `7.2.8.dooapp`.

## Release notes

### 7.2.8.dooapp

Builds and runs on **JDK 25**. Consumers must satisfy both runtime requirements above.

- `Security.java` no longer uses `sun.reflect.Reflection` (removed in JDK 9) nor a `SecurityManager` fallback
  (JEP 486): both `doPrivileged` overloads identify their caller with `StackWalker.getCallerClass()`. The old
  fallback silently returned `Security.class` itself, which made the trust check always true and granted the
  privilege to *any* caller — so this is a fix, not only a port. The boundary is `org.infinispan.*`
  subpackages, and the check is fail-closed on an unknown caller or a class in the default package.
- `Security.getSubject` falls back to `Subject.current()` instead of `Subject.getSubject(acc)`, which throws
  unconditionally on JDK 24+. `getSubjectUserPrincipal` no longer filters `java.security.acl.Group`
  principals: that package was removed in JDK 14, so no loadable class can implement the interface there. On
  JDK 9–13 a JAAS provider may still supply group principals, in which case the first principal is returned
  as-is.
- Build moved to `version.java` 1.8 with `-proc:full` (since JDK 23, javac no longer enables annotation
  processing just because a processor is on the classpath — without it the generated JBoss Logging loggers are
  silently missing from the jars). `--release` is not usable: `--release 8` rejects `sun.misc.Unsafe`, which
  `commons` uses.
- `infinispan-core` no longer packages `OSGI-INF/blueprint/blueprint.xml`. The Scala-based `generate-blueprint`
  goal cannot run on a modern JVM, and shipping the template unsubstituted left a literal `${services}` in the
  descriptor — which an OSGi container fails on, worse than no descriptor at all.

### Earlier

- `SingleFileStore` opens its data file in `"rwd"` (write-through) instead of `"rw"`, so entries survive a hard
  kill of the JVM.
- jboss-marshalling `1.4.10.Final` → `2.0.6.Final` for Java 11+ runtime compatibility, with the matching SPI
  change in `JBossExternalizerAdapter` (marshalling 2.x dropped the `Creator` argument of `createExternal` and
  the `readExternal` callback).

## Building

Requires JDK 25 (earlier JDKs no longer build this branch).

```bash
mvn -pl commons,core -am -DskipTests install
```

Do not pass `-s maven-settings.xml`: that file is upstream's and bypasses the Nexus mirror. The default
settings are correct.
