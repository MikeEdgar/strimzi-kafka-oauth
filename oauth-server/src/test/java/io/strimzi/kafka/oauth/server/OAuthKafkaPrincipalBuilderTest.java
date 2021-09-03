package io.strimzi.kafka.oauth.server;

import io.strimzi.kafka.oauth.common.BearerTokenWithPayload;
import io.strimzi.kafka.oauth.services.Services;
import org.apache.kafka.common.security.auth.AuthenticationContext;
import org.apache.kafka.common.security.auth.KafkaPrincipal;
import org.apache.kafka.common.security.auth.SaslAuthenticationContext;
import org.apache.kafka.common.security.auth.SecurityProtocol;
import org.apache.kafka.common.security.plain.internals.PlainSaslServer;
import org.junit.Test;
import org.mockito.Mockito;

import javax.security.sasl.SaslServer;

import java.net.InetAddress;
import java.util.Collections;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;

public class OAuthKafkaPrincipalBuilderTest {

    @Test
    public void testBuildConcurrent() {
        String clientId = "client-123";

        SaslServer server1 = Mockito.mock(PlainSaslServer.class);
        Mockito.when(server1.getAuthorizationID()).thenReturn(clientId);
        BearerTokenWithPayload token1 = new MockBearerTokenWithPayload(clientId, 0, 0, "email", "token1", "payload1");
        KafkaPrincipal principal1 = new OAuthKafkaPrincipal(KafkaPrincipal.USER_TYPE, clientId, token1);
        AuthenticationContext context1 = new SaslAuthenticationContext(server1, SecurityProtocol.SASL_SSL, InetAddress.getLoopbackAddress(), "listener1");
        OAuthKafkaPrincipalBuilder builder1 = new OAuthKafkaPrincipalBuilder();

        SaslServer server2 = Mockito.mock(PlainSaslServer.class);
        Mockito.when(server2.getAuthorizationID()).thenReturn(clientId);
        AuthenticationContext context2 = new SaslAuthenticationContext(server2, SecurityProtocol.SASL_SSL, InetAddress.getLoopbackAddress(), "listener1");
        BearerTokenWithPayload token2 = new MockBearerTokenWithPayload(clientId, 0, 0, "email", "token2", "payload2");
        KafkaPrincipal principal2 = new OAuthKafkaPrincipal(KafkaPrincipal.USER_TYPE, clientId, token2);
        OAuthKafkaPrincipalBuilder builder2 = new OAuthKafkaPrincipalBuilder();

        Services.configure(Collections.emptyMap());

        // Request 1 stores credentials and builder retrieves to obtain the principal
        Services.getInstance().getCredentials().storeCredentials(clientId, principal1);
        assertSame(principal1, builder1.build(context1));
        assertNull(Services.getInstance().getCredentials().takeCredentials(clientId));
        // Request 1 second call obtains credentials from principals service
        assertSame(principal1, builder1.build(context1));

        // Request 2 stores credentials and builder retrieves to obtain the principal
        Services.getInstance().getCredentials().storeCredentials(clientId, principal2);
        // Request 1 third call "steals" credentials from request 2 principals service
        assertNotNull(builder1.build(context1));

        // Request 2 builder call gets
        assertSame(principal2, builder2.build(context2));
    }

}
