/*
 * Copyright 2017-2021, Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.kafka.oauth.server;

import org.apache.kafka.clients.CommonClientConfigs;
import org.apache.kafka.clients.admin.Admin;
import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.clients.admin.TopicDescription;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.common.Node;
import org.apache.kafka.common.config.SaslConfigs;
import org.apache.kafka.common.config.SslConfigs;
import org.apache.kafka.common.errors.UnknownTopicOrPartitionException;
import org.junit.Test;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ExecutionException;

public class CanaryImitationIT {

    private static final String SASL_PLAIN_CONFIG_TEMPLATE = "org.apache.kafka.common.security.plain.PlainLoginModule "
            + "required "
            + "username=\"%s\" "
            + "password=\"%s\";";

    String getCertificateChain(String url) throws Exception {
        TrustManager[] trustAllCerts = new TrustManager[] {
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() {
                    return null;
                }

                @Override
                public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
                }

                @Override
                public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
                }
            }
        };

        SSLContext sc = null;
        try {
            sc = SSLContext.getInstance("SSL");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        try {
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
        } catch (KeyManagementException e) {
            e.printStackTrace();
        }
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        // Create all-trusting host name verifier
        HostnameVerifier validHosts = new HostnameVerifier() {
            @Override
            public boolean verify(String arg0, SSLSession arg1) {
                return true;
            }
        };
        // All hosts will be valid
        HttpsURLConnection.setDefaultHostnameVerifier(validHosts);

        URL destinationURL = new URL(url);
        HttpsURLConnection conn = (HttpsURLConnection) destinationURL.openConnection();
        conn.connect();
        Certificate[] certs = conn.getServerCertificates();
        StringBuilder result = new StringBuilder();
        for (Certificate cert : certs) {
            if (cert instanceof X509Certificate) {
                try {
                    ((X509Certificate) cert).checkValidity();
                    result.append("-----BEGIN CERTIFICATE-----\n");
                    result.append(Base64.getEncoder().encodeToString(cert.getEncoded()));
                    result.append("\n-----END CERTIFICATE-----\n");
                } catch (CertificateExpiredException cee) {
                    System.out.println("Certificate is expired");
                }
            } else {
                System.err.println("Unknown certificate type: " + cert);
            }
        }

        return result.toString();
    }

    @Test
    public void testCanary() throws Throwable {
        String bootstrapServers = "test------c-ocjl-gn-e-ugt--e-g.mk.medgar-kafka.bbt1.s1.devshift.org:443";
        String username = "canary-c4ocjl8gn8e8ugt67e3g";
        String password = "ae90c078-d9ed-4911-9bfa-80e850ae5c9c";

        String bootstrapServerCert = getCertificateChain("https://" + bootstrapServers);
        Properties config = new Properties();
        config.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        config.put(SslConfigs.SSL_TRUSTSTORE_CERTIFICATES_CONFIG, bootstrapServerCert);
        config.put(SslConfigs.SSL_TRUSTSTORE_TYPE_CONFIG, "PEM");
        config.put(CommonClientConfigs.SECURITY_PROTOCOL_CONFIG, "SASL_SSL");
        config.put(SaslConfigs.SASL_MECHANISM, "PLAIN");
        config.put(SaslConfigs.SASL_JAAS_CONFIG, String.format(SASL_PLAIN_CONFIG_TEMPLATE, username, password));

        Admin adminClient = Admin.create(config);

        Collection<Node> nodes = adminClient.describeCluster().nodes().get();

        try {
            Map<String, TopicDescription> topics = adminClient.describeTopics(Arrays.asList("__strimzi_canary3")).all().get();
        } catch (ExecutionException e) {
            if (e.getCause() instanceof UnknownTopicOrPartitionException) {
                adminClient.createTopics(Collections.singleton(new NewTopic("__strimzi_canary3", 3, (short) 2)))
                    .all()
                    .get();
            } else {
                throw e.getCause();
            }
        }

//        for (int i = 0; i < 100; i++) {
//            Map<TopicPartition, OffsetAndMetadata> offsets = adminClient.listConsumerGroupOffsets("strimzi-canary3-group")
//                    .partitionsToOffsetAndMetadata()
//                    .get();
//
//            System.out.println(offsets);
//        }

    }

}
