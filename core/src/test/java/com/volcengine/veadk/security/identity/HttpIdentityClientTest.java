/** Copyright (c) 2025 Beijing Volcano Engine Technology Co., Ltd. */
package com.volcengine.veadk.security.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.volcengine.veadk.security.VolcengineV4Signer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.Test;

class HttpIdentityClientTest {
    private static final Clock CLOCK =
            Clock.fixed(Instant.parse("2026-10-14T00:00:00Z"), ZoneOffset.UTC);

    @Test
    void signsActualOpenApiQueriesAndUnwrapsEveryIdentityResult() throws Exception {
        List<Request> requests = new CopyOnWriteArrayList<>();
        HttpServer server = server();
        server.createContext(
                "/",
                exchange -> {
                    requests.add(Request.capture(exchange));
                    String query = String.valueOf(exchange.getRequestURI().getRawQuery());
                    String result;
                    if (query.startsWith("Action=CheckPermission&")) result = "{\"Allowed\":false}";
                    else if (query.startsWith("Action=GetResourceApiKey&"))
                        result = "{\"ApiKey\":\"managed-key\"}";
                    else if (query.startsWith("Action=GetResourceOauth2Token&"))
                        result = "{\"AuthorizationUrl\":\"https://login.example.com\"}";
                    else
                        result =
                                "{\"WorkloadAccessToken\":\"jwt-value\",\"ExpiresAt\":\"2026-10-14T01:00:00Z\"}";
                    respond(exchange, 200, "{\"ResponseMetadata\":{},\"Result\":" + result + "}");
                });
        server.start();
        try {
            HttpIdentityClient client = client(server);
            assertThat(client.getWorkloadToken("agent-a", null, null).value())
                    .isEqualTo("jwt-value");
            assertThat(client.getWorkloadToken("agent-a", "user-a", null).value())
                    .isEqualTo("jwt-value");
            assertThat(client.getWorkloadToken("agent-b", "ignored-user", "upstream-jwt").value())
                    .isEqualTo("jwt-value");
            assertThat(
                            client.checkPermission(
                                    new PermissionRequest(
                                            "default",
                                            new PermissionRequest.Principal("user", "u"),
                                            new PermissionRequest.Principal("Action", "invoke"),
                                            new PermissionRequest.Principal("tool", "search"),
                                            List.of())))
                    .isFalse();
            assertThat(client.getApiKey("github", "identity-token")).isEqualTo("managed-key");
            OAuth2Credential oauth =
                    client.getOAuth2Credential(
                            "github",
                            "identity-token",
                            "USER_FEDERATION",
                            List.of("repo"),
                            "https://callback",
                            true);
            assertThat(oauth.type()).isEqualTo(OAuth2Credential.Type.AUTHORIZATION_URL);
            assertThat(oauth.value()).isEqualTo("https://login.example.com");

            assertThat(requests.stream().map(r -> r.uri().getRawQuery()).toList())
                    .containsExactly(
                            "Action=GetWorkloadAccessToken&Version=2025-10-30",
                            "Action=GetWorkloadAccessTokenForUserId&Version=2025-10-30",
                            "Action=GetWorkloadAccessTokenForJWT&Version=2025-10-30",
                            "Action=CheckPermission&Version=2025-10-30",
                            "Action=GetResourceApiKey&Version=2025-10-30",
                            "Action=GetResourceOauth2Token&Version=2025-10-30");
            for (Request request : requests) {
                assertThat(request.method()).isEqualTo("POST");
                assertThat(request.uri().getPath()).isEqualTo("/");
                assertThat(request.contentType()).isEqualTo("application/json");
                assertThat(request.sessionToken()).isEqualTo("session");
                URI actual = URI.create(endpoint(server) + request.uri());
                assertThat(request.authorization())
                        .isEqualTo(
                                VolcengineV4Signer.sign(
                                                actual,
                                                request.uri().getRawQuery(),
                                                request.body(),
                                                "cn-test",
                                                "id",
                                                "ak",
                                                "sk",
                                                "session",
                                                CLOCK)
                                        .get("Authorization"));
            }
            var mapper = new ObjectMapper();
            assertThat(mapper.readTree(requests.get(0).body()).has("UserId")).isFalse();
            assertThat(mapper.readTree(requests.get(1).body()).path("UserId").asText())
                    .isEqualTo("user-a");
            assertThat(mapper.readTree(requests.get(2).body()).path("UserToken").asText())
                    .isEqualTo("upstream-jwt");
            assertThat(mapper.readTree(requests.get(2).body()).has("UserId")).isFalse();
            assertThat(mapper.readTree(requests.get(4).body()).path("IdentityToken").asText())
                    .isEqualTo("identity-token");
            assertThat(
                            mapper.readTree(requests.get(5).body())
                                    .path("ForceAuthentication")
                                    .asBoolean())
                    .isTrue();
        } finally {
            server.stop(0);
        }
    }

    @Test
    void parsesOAuthAccessTokenResult() throws Exception {
        withResponse(
                200,
                "{\"Result\":{\"AccessToken\":\"oauth-token\"}}",
                client -> {
                    var credential =
                            client.getOAuth2Credential(
                                    "provider", "identity", null, List.of(), null, false);
                    assertThat(credential.type()).isEqualTo(OAuth2Credential.Type.TOKEN);
                    assertThat(credential.value()).isEqualTo("oauth-token");
                });
    }

    @Test
    void surfacesOpenApiErrorsOnHttpSuccessAndFailureWithoutCredentialPayloads() throws Exception {
        for (int status : List.of(200, 403)) {
            withResponse(
                    status,
                    "{\"ResponseMetadata\":{\"RequestId\":\"request-123\",\"Error\":{"
                            + "\"Code\":\"AccessDenied\",\"Message\":\"secret-upstream-jwt\"}},"
                            + "\"Result\":{\"ApiKey\":\"secret-resource-key\"}}",
                    client ->
                            assertThatThrownBy(() -> client.getApiKey("provider", "identity"))
                                    .isInstanceOf(IllegalStateException.class)
                                    .hasMessageContaining("HTTP " + status)
                                    .hasMessageContaining("AccessDenied")
                                    .hasMessageContaining("request-123")
                                    .hasMessageNotContaining("secret-upstream-jwt")
                                    .hasMessageNotContaining("secret-resource-key")
                                    .hasNoCause());
        }
    }

    @Test
    void rejectsMissingAndMalformedResultWithoutBodyFragments() throws Exception {
        for (String body : List.of("{}", "{\"Result\":null}", "{\"Result\":[]}", "[]", "null")) {
            withResponse(
                    200,
                    body,
                    client ->
                            assertThatThrownBy(() -> client.getWorkloadToken("agent", "user", null))
                                    .hasMessage("Identity response is missing Result object."));
        }
        withResponse(
                502,
                "not-json-secret-jwt",
                client ->
                        assertThatThrownBy(() -> client.getWorkloadToken("agent", "user", null))
                                .hasMessage("Identity response is not valid JSON (HTTP 502).")
                                .hasNoCause());
    }

    private static HttpServer server() throws IOException {
        return HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    }

    private static String endpoint(HttpServer server) {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    private static HttpIdentityClient client(HttpServer server) {
        return new HttpIdentityClient(
                HttpClient.newHttpClient(),
                new ObjectMapper(),
                URI.create(endpoint(server)),
                "cn-test",
                "ak",
                "sk",
                "session",
                Duration.ofSeconds(2),
                CLOCK);
    }

    private static void withResponse(int status, String body, Check check) throws Exception {
        HttpServer server = server();
        server.createContext("/", exchange -> respond(exchange, status, body));
        server.start();
        try {
            check.run(client(server));
        } finally {
            server.stop(0);
        }
    }

    private static void respond(HttpExchange exchange, int status, String response)
            throws IOException {
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    private interface Check {
        void run(HttpIdentityClient client) throws Exception;
    }

    private record Request(
            URI uri,
            String method,
            byte[] body,
            String contentType,
            String sessionToken,
            String authorization) {
        static Request capture(HttpExchange exchange) throws IOException {
            return new Request(
                    exchange.getRequestURI(),
                    exchange.getRequestMethod(),
                    exchange.getRequestBody().readAllBytes(),
                    exchange.getRequestHeaders().getFirst("Content-Type"),
                    exchange.getRequestHeaders().getFirst("X-Security-Token"),
                    exchange.getRequestHeaders().getFirst("Authorization"));
        }
    }
}
