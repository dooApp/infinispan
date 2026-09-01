package org.infinispan.security;

import java.lang.reflect.Method;
import java.security.AccessControlContext;
import java.security.AccessControlException;
import java.security.AccessController;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Iterator;
import java.util.Stack;

import javax.security.auth.Subject;

/**
 * Security. A simple class to implement caller privileges without a security manager and a
 * much faster implementations of the {@link Subject#doAs(Subject, PrivilegedAction)} and
 * {@link Subject#doAs(Subject, PrivilegedExceptionAction)} when interaction with the
 * {@link AccessControlContext} is not needed.
 *
 * N.B. this uses the caller's {@link Package}, this can easily be subverted by placing the
 * calling code within the org.infinispan hierarchy. However for most purposes this is ok.
 *
 * N.B. this class requires Java 9 or later at runtime. The artifact is still built for Java 8
 * ({@code version.java} in {@code bom/pom.xml}), but {@link StackWalker} is a JDK 9 API: on a Java 8 JVM this
 * class fails its static initialization with {@code NoClassDefFoundError: java/lang/StackWalker}, and since every
 * {@code SecurityActions} helper of the core module goes through it, practically no cache operation works.
 *
 * @author Tristan Tarrant
 * @since 7.0
 */
@SuppressWarnings({ "deprecation", "removal" })
public final class Security {
   /**
    * Replaces {@code sun.reflect.Reflection}, dropped from the JDK in 9. The former fallback on a
    * {@code SecurityManager} subclass is gone too: JDK 24+ (JEP 486) permanently disables the security manager.
    * <p>
    * {@link StackWalker#getCallerClass()} requires {@link StackWalker.Option#RETAIN_CLASS_REFERENCE} and returns the
    * caller of the method that invokes it. Called straight from {@link #doPrivileged(PrivilegedAction)} it therefore
    * yields the caller of {@code doPrivileged}: no frame arithmetic to get wrong, and cheaper than materializing a
    * frame stream through {@link StackWalker#walk}.
    * <p>
    * {@code null} when the walker cannot be obtained: {@link StackWalker#getInstance(StackWalker.Option)} checks
    * {@code RuntimePermission("getStackWalkerWithClassReference")}, which a {@link SecurityManager} on JDK 9-23 may
    * refuse. Letting that fail the class initialization would leave every {@code SecurityActions} helper of the core
    * module dead with a {@link NoClassDefFoundError}, so this degrades instead: no walker means no identifiable
    * caller, which {@link #isTrustedClass(Class)} already treats as untrusted.
    */
   private static final StackWalker STACK_WALKER = stackWalker();
   /**
    * {@code Subject.current()}, introduced in JDK 18, or {@code null} on earlier JDKs - and on any JDK where a
    * {@link SecurityManager} refuses the reflective lookup, in which case {@link #currentSubject()} falls back to
    * {@code Subject.getSubject}.
    */
   private static final Method SUBJECT_CURRENT = findSubjectCurrent();

   private static final ThreadLocal<Boolean> PRIVILEGED = new ThreadLocal<Boolean>() {
      @Override
      protected Boolean initialValue() {
         return Boolean.FALSE;
      }
   };

   private static final ThreadLocal<Stack<Subject>> SUBJECT = new ThreadLocal<Stack<Subject>>();

   private static StackWalker stackWalker() {
      try {
         return StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE);
      } catch (SecurityException e) {
         return null;
      }
   }

   /**
    * Fail-closed: an unknown caller ({@code null}) or a caller in the default package ({@code getPackage()} returns
    * {@code null}) is untrusted, rather than failing the privilege check with a bare {@link NullPointerException}.
    */
   private static boolean isTrustedClass(Class<?> klass) {
      // TODO: implement a better way
      if (klass == null) {
         return false;
      }
      Package pkg = klass.getPackage();
      if (pkg == null) {
         return false;
      }
      // "org.infinispan" itself, not only its subpackages: CacheImpl and DefaultCacheManager live in it.
      String name = pkg.getName();
      return name.equals("org.infinispan") || name.startsWith("org.infinispan.");
   }

   public static <T> T doPrivileged(PrivilegedAction<T> action) {
      if (!isPrivileged() && STACK_WALKER != null && isTrustedClass(STACK_WALKER.getCallerClass())) {
         try {
            PRIVILEGED.set(true);
            return action.run();
         } finally {
            PRIVILEGED.remove();
         }
      } else {
         return action.run();
      }
   }

   public static <T> T doPrivileged(PrivilegedExceptionAction<T> action) throws PrivilegedActionException {
      if (!isPrivileged() && STACK_WALKER != null && isTrustedClass(STACK_WALKER.getCallerClass())) {
         try {
            PRIVILEGED.set(true);
            return action.run();
         } catch (Exception e) {
            throw new PrivilegedActionException(e);
         } finally {
            PRIVILEGED.remove();
         }
      } else {
         try {
            return action.run();
         } catch (Exception e) {
            throw new PrivilegedActionException(e);
         }
      }
   }

   /**
    * A "lightweight" implementation of {@link Subject#doAs(Subject, PrivilegedAction)} which uses a ThreadLocal
    * {@link Subject} instead of modifying the current {@link AccessControlContext}.
    *
    * @see Subject#doAs(Subject, PrivilegedAction)
    */
   public static <T> T doAs(final Subject subject, final java.security.PrivilegedAction<T> action) {
      Stack<Subject> stack = SUBJECT.get();
      if (stack == null) {
         stack = new Stack<Subject>();
         SUBJECT.set(stack);
      }
      stack.push(subject);
      try {
         return action.run();
      } finally {
         stack.pop();
         if (stack.isEmpty()) {
            SUBJECT.remove();
         }
      }
   }

   /**
    * A "lightweight" implementation of {@link Subject#doAs(Subject, PrivilegedExceptionAction)} which uses a ThreadLocal
    * {@link Subject} instead of modifying the current {@link AccessControlContext}.
    *
    * @see Subject#doAs(Subject, PrivilegedExceptionAction)
    */
   public static <T> T doAs(final Subject subject,
         final java.security.PrivilegedExceptionAction<T> action)
         throws java.security.PrivilegedActionException {
      Stack<Subject> stack = SUBJECT.get();
      if (stack == null) {
         stack = new Stack<Subject>();
         SUBJECT.set(stack);
      }
      stack.push(subject);
      try {
         return action.run();
      } catch (Exception e) {
         throw new PrivilegedActionException(e);
      } finally {
         stack.pop();
         if (stack.isEmpty()) {
            SUBJECT.remove();
         }
      }
   }


   public static void checkPermission(CachePermission permission) throws AccessControlException {
      if (!isPrivileged()) {
         throw new AccessControlException("Call from unprivileged code", permission);
      }
   }

   public static boolean isPrivileged() {
      return PRIVILEGED.get();
   }

   /**
    * If using {@link Security#doAs(Subject, PrivilegedAction)} or
    * {@link Security#doAs(Subject, PrivilegedExceptionAction)}, returns the {@link Subject} associated with the current thread
    * otherwise it returns the {@link Subject} associated with the current execution context.
    * <p>
    * JDK 24+ (JEP 486): {@code Subject.getSubject(AccessControlContext)} throws
    * {@code UnsupportedOperationException} unconditionally, an {@link AccessControlContext} no longer carries a
    * {@link Subject}. {@code Subject.current()} is the replacement, but it only exists since JDK 18, hence the
    * reflective call and the fallback for earlier JDKs.
    */
   public static Subject getSubject() {
      Stack<Subject> stack = SUBJECT.get();
      if (stack != null) {
         return stack.peek();
      }
      return currentSubject();
   }

   /**
    * The {@link Subject} of the current execution context, as set by {@link Subject#doAs(Subject, PrivilegedAction)}
    * or {@code Subject.callAs(Subject, Callable)}.
    */
   private static Subject currentSubject() {
      if (SUBJECT_CURRENT == null) {
         return Subject.getSubject(AccessController.getContext());
      }
      try {
         return (Subject) SUBJECT_CURRENT.invoke(null);
      } catch (ReflectiveOperationException e) {
         throw new IllegalStateException("Could not invoke Subject.current()", e);
      }
   }

   private static Method findSubjectCurrent() {
      try {
         return Subject.class.getMethod("current");
      } catch (NoSuchMethodException | SecurityException e) {
         return null;
      }
   }

   /**
    * Returns the first principal of a subject.
    * <p>
    * This used to skip principals of type {@code java.security.acl.Group}. That package was removed in JDK 14, so
    * on JDK 14+ no loadable class can implement the interface and the filter is vacuous. On JDK 9 to 13 the
    * interface still exists and a JAAS provider may supply Group principals, in which case this method now returns
    * the group instead of the user - visible in the records of {@code LoggingAuditLogger}, which logs this principal.
    */
   public static Principal getSubjectUserPrincipal(Subject s) {
      if (s != null) {
         Iterator<Principal> principals = s.getPrincipals().iterator();
         if (principals.hasNext()) {
            return principals.next();
         }
      }
      return null;
   }
}
