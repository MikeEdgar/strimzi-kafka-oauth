/*
 * Copyright 2017-2020, Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.kafka.oauth.server;

import io.strimzi.kafka.oauth.common.BearerTokenWithPayload;
import io.strimzi.kafka.oauth.services.Principals;
import io.strimzi.kafka.oauth.services.Services;
import org.apache.kafka.common.Configurable;
import org.apache.kafka.common.config.internals.BrokerSecurityConfigs;
import org.apache.kafka.common.security.auth.AuthenticationContext;
import org.apache.kafka.common.security.auth.KafkaPrincipal;
import org.apache.kafka.common.security.auth.SaslAuthenticationContext;
import org.apache.kafka.common.security.authenticator.DefaultKafkaPrincipalBuilder;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule;
import org.apache.kafka.common.security.oauthbearer.internals.OAuthBearerSaslServer;
import org.apache.kafka.common.security.plain.internals.PlainSaslServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.sasl.SaslServer;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This class needs to be enabled as the PrincipalBuilder on Kafka Broker.
 * <p>
 * It ensures that additional session info is associated with the current session to allow enforcing access token lifetime,
 * for re-authentication to operate properly, and for custom authorizers to have access to additional session state -
 * i.e. the parsed access token. The extra information is in the form of <em>SessionInfo</em> object containing
 * the OAuthBearerToken token produced by <em>io.strimzi.kafka.oauth.server.JaasServerOauthValidatorCallbackHandler</em>.
 * </p>
 * <p>
 * It is also required for OAuth over PLAIN to operate properly.
 * </p>
 * <p>
 * Use 'principal.builder.class=io.strimzi.kafka.oauth.server.OAuthKafkaPrincipalBuilder'
 * property definition in server.properties to install it.
 * </p>
 */
public class OAuthKafkaPrincipalBuilder extends DefaultKafkaPrincipalBuilder implements Configurable {

    private static final Map<String, Logger> LOGS = new HashMap<>();

    static Logger logger(String listenerName) {
        return LOGS.computeIfAbsent(listenerName, key ->
            LoggerFactory.getLogger(String.format("%s.%s", OAuthKafkaPrincipalBuilder.class.getName(), listenerName)));
    }

    private static final SetAccessibleAction SET_PRINCIPAL_MAPPER = SetAccessibleAction.newInstance();

    private static class SetAccessibleAction implements PrivilegedAction<Void> {

        private Field field;

        SetAccessibleAction(Field field) {
            this.field = field;
        }

        @Override
        public Void run() {
            field.setAccessible(true);
            return null;
        }

        void invoke(DefaultKafkaPrincipalBuilder target, Object value) throws IllegalAccessException {
            AccessController.doPrivileged(this);
            field.set(target, value);
        }

        static SetAccessibleAction newInstance() {
            try {
                return new SetAccessibleAction(DefaultKafkaPrincipalBuilder.class.getDeclaredField("sslPrincipalMapper"));
            } catch (NoSuchFieldException e) {
                throw new IllegalStateException("Failed to install OAuthKafkaPrincipalBuilder. This Kafka version does not seem to be supported", e);
            }
        }
    }


    public OAuthKafkaPrincipalBuilder() {
        super(null, null);
    }

    @Override
    public void configure(Map<String, ?> configs) {

        Object sslPrincipalMappingRules = configs.get(BrokerSecurityConfigs.SSL_PRINCIPAL_MAPPING_RULES_CONFIG);
        Object sslPrincipalMapper;

        try {
            Class<?> clazz = Class.forName("org.apache.kafka.common.security.ssl.SslPrincipalMapper");
            try {
                Method m = clazz.getMethod("fromRules", List.class);
                if (sslPrincipalMappingRules == null) {
                    sslPrincipalMappingRules = Collections.singletonList("DEFAULT");
                }
                sslPrincipalMapper = m.invoke(null, sslPrincipalMappingRules);

            } catch (NoSuchMethodException ex) {
                Method m = clazz.getMethod("fromRules", String.class);
                if (sslPrincipalMappingRules == null) {
                    sslPrincipalMappingRules = "DEFAULT";
                }
                sslPrincipalMapper = m.invoke(null, sslPrincipalMappingRules);
            }

            // Hack setting sslPrincipalMapper to DefaultKafkaPrincipalBuilder
            // An alternative would be to copy paste the complete DefaultKafkaPrincipalBuilder implementation
            // into this class and extend it

            SET_PRINCIPAL_MAPPER.invoke(this, sslPrincipalMapper);

        } catch (RuntimeException e) {
            throw new RuntimeException("Failed to initialize OAuthKafkaPrincipalBuilder", e);

        } catch (ClassNotFoundException
                | NoSuchMethodException
                | IllegalAccessException
                | InvocationTargetException e) {
            throw new RuntimeException("Failed to initialize OAuthKafkaPrincipalBuilder", e);
        }
    }

    @Override
    public KafkaPrincipal build(AuthenticationContext context) {
        final String listenerName = context.listenerName();
        final Logger log = logger(listenerName);

        if (context instanceof SaslAuthenticationContext) {
            SaslServer saslServer = ((SaslAuthenticationContext) context).server();
            if (saslServer instanceof OAuthBearerSaslServer) {
                OAuthBearerSaslServer server = (OAuthBearerSaslServer) saslServer;
                if (OAuthBearerLoginModule.OAUTHBEARER_MECHANISM.equals(server.getMechanismName())) {
                    BearerTokenWithPayload token = (BearerTokenWithPayload) server.getNegotiatedProperty("OAUTHBEARER.token");
                    Services.getInstance().getSessions().put(token);

                    OAuthKafkaPrincipal kafkaPrincipal = new OAuthKafkaPrincipal(KafkaPrincipal.USER_TYPE,
                            server.getAuthorizationID(), token);

                    if (log.isDebugEnabled()) {
                        log.debug("Constructed new OAuthKafkaPrincipal: {}", kafkaPrincipal);
                    }

                    return kafkaPrincipal;
                } else if (log.isDebugEnabled()) {
                    log.debug("Unhandled mechanism for OAuthBearerSaslServer: {}", server.getMechanismName());
                }
            } else if (saslServer instanceof PlainSaslServer) {
                PlainSaslServer server = (PlainSaslServer) saslServer;

                // if PLAIN mechanism is used to communicate the OAuth token
                Principals principals = Services.getInstance().getPrincipals();
                OAuthKafkaPrincipal principal = (OAuthKafkaPrincipal) Services.getInstance().getCredentials().takeCredentials(server.getAuthorizationID());
                if (principal != null) {
                    if (log.isDebugEnabled()) {
                        log.debug("principal found in credentials with key: {}", server.getAuthorizationID());
                    }

                    principals.putPrincipal(saslServer, principal);
                    return principal;
                } else if (log.isDebugEnabled()) {
                    log.debug("principal not found in credentials with key: {}", server.getAuthorizationID());
                }

                // if principal is required by request / thread other than the one that was just authenticated
                principal = (OAuthKafkaPrincipal) principals.getPrincipal(saslServer);
                if (principal != null) {
                    if (log.isDebugEnabled()) {
                        log.debug("principal found in `Principals` with key: {}", saslServer);
                    }

                    return principal;
                } else if (log.isDebugEnabled()) {
                    log.debug("principal not found in `Principals` with key: {}", saslServer);
                }
            } else if (log.isDebugEnabled()) {
                if (saslServer != null) {
                    log.debug("saslServer was an unhandled type, class={}", saslServer.getClass().getName());
                } else {
                    log.debug("saslServer was null");
                }
            }
        } else if (log.isDebugEnabled()) {
            log.debug("context was not a SaslAuthenticationContext, class={}", context.getClass().getName());
        }

        KafkaPrincipal defaultPrincipal = super.build(context);

        if (log.isDebugEnabled()) {
            log.debug("Default KafkaPrincipal returned: {}", defaultPrincipal);
        }

        return defaultPrincipal;
    }
}
