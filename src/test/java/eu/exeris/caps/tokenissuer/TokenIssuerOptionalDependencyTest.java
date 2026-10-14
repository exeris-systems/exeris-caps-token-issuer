package eu.exeris.caps.tokenissuer;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The audit-trail and service-boundary capabilities are optional dependencies, so the module and the
 * public service interfaces must load, reflect and be constructed for lifecycle with their jars
 * absent from the class path.
 */
@DisplayName("Token issuer without the optional audit-trail and service-boundary jars")
class TokenIssuerOptionalDependencyTest {

    private static final String[] HIDDEN_PREFIXES = {
            "eu.exeris.caps.audittrail.",
            "eu.exeris.caps.serviceboundarycore."
    };
    private static final String OWN_PREFIX = "eu.exeris.caps.tokenissuer.";
    /** The adapters are the only classes allowed to name an optional type. */
    private static final String[] ADAPTERS = {
            "eu.exeris.caps.tokenissuer.spi.AuditLogSinkRecorder",
            "eu.exeris.caps.tokenissuer.spi.ApiSurfaceRegistryRegistrar",
            "eu.exeris.caps.tokenissuer.internal.boundary.JwksHttpRoute"
    };

    /** Defines this capability's classes itself and refuses to see the optional capabilities' types. */
    private static final class WithoutOptionalJars extends ClassLoader {

        WithoutOptionalJars() {
            super(TokenIssuerOptionalDependencyTest.class.getClassLoader());
        }

        @Override
        protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
            for (String hidden : HIDDEN_PREFIXES) {
                if (name.startsWith(hidden)) {
                    throw new ClassNotFoundException(name);
                }
            }
            if (!name.startsWith(OWN_PREFIX)) {
                return super.loadClass(name, resolve);
            }
            synchronized (getClassLoadingLock(name)) {
                Class<?> loaded = findLoadedClass(name);
                if (loaded == null) {
                    try (InputStream in = getParent().getResourceAsStream(name.replace('.', '/') + ".class")) {
                        if (in == null) {
                            throw new ClassNotFoundException(name);
                        }
                        byte[] bytes = in.readAllBytes();
                        loaded = defineClass(name, bytes, 0, bytes.length);
                    } catch (IOException e) {
                        throw new ClassNotFoundException(name, e);
                    }
                }
                if (resolve) {
                    resolveClass(loaded);
                }
                return loaded;
            }
        }
    }

    @Test
    @DisplayName("the optional types really are hidden from the probe class loader")
    void probeHidesTheJars() {
        ClassLoader probe = new WithoutOptionalJars();
        assertThatThrownBy(() -> probe.loadClass("eu.exeris.caps.audittrail.api.AuditLogSink"))
                .isInstanceOf(ClassNotFoundException.class);
        assertThatThrownBy(() -> probe.loadClass("eu.exeris.caps.serviceboundarycore.api.ApiSurfaceRegistry"))
                .isInstanceOf(ClassNotFoundException.class);
        assertThatThrownBy(() -> probe.loadClass(ADAPTERS[0]).getConstructors())
                .isInstanceOf(NoClassDefFoundError.class);
    }

    @Test
    @DisplayName("the module and every public service interface resolve and reflect without the jars")
    void moduleAndServicesLoadWithoutTheJars() throws Exception {
        ClassLoader probe = new WithoutOptionalJars();
        for (String name : new String[]{
                "eu.exeris.caps.tokenissuer.TokenIssuerModule",
                "eu.exeris.caps.tokenissuer.api.AccessTokenIssuer",
                "eu.exeris.caps.tokenissuer.api.JwksPublisher",
                "eu.exeris.caps.tokenissuer.api.SigningKeyRotation",
                "eu.exeris.caps.tokenissuer.internal.DefaultAccessTokenIssuer",
                "eu.exeris.caps.tokenissuer.internal.DefaultJwksPublisher",
                "eu.exeris.caps.tokenissuer.internal.DefaultSigningKeyRotation",
                "eu.exeris.caps.tokenissuer.internal.audit.TokenIssuerAuditBridge",
                "eu.exeris.caps.tokenissuer.spi.AuditRecorder",
                "eu.exeris.caps.tokenissuer.spi.JwksRouteRegistrar"}) {
            Class<?> type = probe.loadClass(name);
            assertThat(type.getConstructors()).as(name).isNotNull();
            assertThat(type.getDeclaredConstructors()).as(name).isNotNull();
            assertThat(type.getMethods()).as(name).isNotNull();
            assertThat(type.getDeclaredMethods()).as(name).isNotNull();
            assertThat(type.getDeclaredFields()).as(name).isNotNull();
        }
        Class<?> module = probe.loadClass("eu.exeris.caps.tokenissuer.TokenIssuerModule");
        java.util.Map<String, String> env = java.util.Map.of(
                "EXERIS_TOKEN_ISSUER_ISSUER", "https://issuer.test.invalid",
                "EXERIS_TOKEN_ISSUER_AUDIENCE", "https://audience.test.invalid");
        Object instance = module.getConstructor(java.util.Map.class,
                probe.loadClass("eu.exeris.kernel.spi.persistence.TransactionalExecutor"),
                probe.loadClass("eu.exeris.kernel.spi.scheduling.JobScheduler"),
                probe.loadClass("eu.exeris.caps.tokenissuer.spi.JwksRouteRegistrar"),
                probe.loadClass("eu.exeris.caps.tokenissuer.spi.AuditRecorder"))
                .newInstance(env, null, null, null, null);
        module.getMethod("ready").invoke(instance);
        module.getMethod("terminate").invoke(instance);
    }
}
