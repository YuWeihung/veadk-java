/** Copyright (c) 2025 Beijing Volcano Engine Technology Co., Ltd. */
package com.volcengine.veadk.security.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.adk.agents.CallbackContext;
import com.google.adk.agents.InvocationContext;
import com.google.adk.sessions.Session;
import com.google.adk.sessions.State;
import com.google.adk.tools.BaseTool;
import com.google.adk.tools.ToolContext;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class IdentityDelegationTest {
    private static final Instant NOW = Instant.parse("2026-10-14T00:00:00Z");
    private static final Instant EXPIRY = Instant.parse("2099-01-01T00:00:00Z");

    @Test
    void exchangesExplicitOrContextJwtAndIsolatesDelegationAndNonDelegationCaches()
            throws Exception {
        RecordingClient client = new RecordingClient();
        WorkloadTokenManager manager = new WorkloadTokenManager(client);
        Map<String, Object> state = new HashMap<>();
        String parentA = jwt("parent-a", null), parentB = jwt("parent-b", null);

        String plain = manager.get(state, "agent", "user");
        assertThat(manager.get(state, "agent", "user")).isEqualTo(plain);
        state.put(WorkloadTokenManager.UPSTREAM_TOKEN_STATE_KEY, "Bearer " + parentA);
        String delegatedA = manager.get(state, "agent", "user");
        assertThat(manager.get(state, "agent", "user", parentA)).isEqualTo(delegatedA);
        state.put(WorkloadTokenManager.UPSTREAM_TOKEN_STATE_KEY, parentB);
        String delegatedB = manager.get(state, "agent", "user");
        assertThat(delegatedB).isNotEqualTo(delegatedA).isNotEqualTo(plain);
        state.remove(WorkloadTokenManager.UPSTREAM_TOKEN_STATE_KEY);
        assertThat(manager.get(state, "agent", "user")).isEqualTo(plain);
        assertThat(client.requests)
                .containsExactly(
                        new TokenRequest("agent", "user", null),
                        new TokenRequest("agent", null, parentA),
                        new TokenRequest("agent", null, parentB));
        assertThat(state.keySet()).hasSize(3).allMatch(key -> key.startsWith("workload_token:v2:"));
        assertThat(state.keySet()).noneMatch(key -> key.contains(parentA) || key.contains(parentB));
    }

    @Test
    void scopeCannotCollideOnDelimitersOrReuseLegacyEntries() throws Exception {
        RecordingClient client = new RecordingClient();
        WorkloadTokenManager manager = new WorkloadTokenManager(client);
        Map<String, Object> state = new HashMap<>();
        state.put("workload_token:a:b:c", new WorkloadToken("legacy", EXPIRY));
        assertThat(manager.get(state, "a:b", "c")).isNotEqualTo("legacy");
        manager.get(state, "a", "b:c");
        manager.get(state, "agent", null);
        manager.get(state, "agent", "null");
        assertThat(client.requests).hasSize(4);
    }

    @Test
    void refreshKeepsUpstreamJwtAndDoesNotSilentlyDowngradeInvalidContext() throws Exception {
        RecordingClient client =
                new RecordingClient() {
                    @Override
                    public WorkloadToken getWorkloadToken(
                            String agent, String user, String upstream) throws Exception {
                        return new WorkloadToken(
                                super.getWorkloadToken(agent, user, upstream).value(),
                                NOW.plusSeconds(60));
                    }
                };
        WorkloadTokenManager manager =
                new WorkloadTokenManager(
                        client, Clock.fixed(NOW, ZoneOffset.UTC), Duration.ofSeconds(60));
        Map<String, Object> state = new HashMap<>();
        String parent = jwt("parent", null);
        state.put(WorkloadTokenManager.UPSTREAM_TOKEN_STATE_KEY, parent);
        manager.get(state, "agent", "user");
        manager.get(state, "agent", "user");
        assertThat(client.requests)
                .containsExactly(
                        new TokenRequest("agent", null, parent),
                        new TokenRequest("agent", null, parent));
        state.put(WorkloadTokenManager.UPSTREAM_TOKEN_STATE_KEY, 123);
        assertThatThrownBy(() -> manager.get(state, "agent", "user"))
                .isInstanceOf(IllegalArgumentException.class);
        state.put(WorkloadTokenManager.UPSTREAM_TOKEN_STATE_KEY, "Bearer ");
        assertThatThrownBy(() -> manager.get(state, "agent", "user"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(client.requests).hasSize(2);
    }

    @Test
    void defaultCredentialsPassContextToWorkloadApiKeyAndOAuthAndScopeApiKeyCache()
            throws Exception {
        RecordingClient client = new RecordingClient();
        IdentityCredentials credentials = new IdentityCredentials(client);
        Map<String, Object> state = new HashMap<>();
        String parentA = jwt("parent-a", null), parentB = jwt("parent-b", null);
        state.put(WorkloadTokenManager.UPSTREAM_TOKEN_STATE_KEY, parentA);
        String firstToken = credentials.workloadToken(state, "agent", "user");
        String firstKey = credentials.apiKey(state, "agent", "user", "provider");
        assertThat(credentials.apiKey(state, "agent", "user", "provider")).isEqualTo(firstKey);
        assertThat(
                        credentials
                                .oauth2(
                                        state,
                                        "agent",
                                        "user",
                                        "provider",
                                        "USER_FEDERATION",
                                        List.of(),
                                        null,
                                        false)
                                .value())
                .isEqualTo(firstToken);
        state.put(WorkloadTokenManager.UPSTREAM_TOKEN_STATE_KEY, parentB);
        assertThat(credentials.apiKey(state, "agent", "user", "provider")).isNotEqualTo(firstKey);
        assertThat(client.requests)
                .containsExactly(
                        new TokenRequest("agent", null, parentA),
                        new TokenRequest("agent", null, parentB));
        assertThat(client.apiKeyCalls).isEqualTo(2);
    }

    @Test
    void callbacksUseInvocationStateToRetainOriginalCallersForAgentAndToolChecks()
            throws Exception {
        RecordingClient client = new RecordingClient();
        IdentityAuthorization authorization = new IdentityAuthorization(client);
        State invocationState = new State(new HashMap<>());
        invocationState.put(WorkloadTokenManager.UPSTREAM_TOKEN_STATE_KEY, jwt("parent", null));
        CallbackContext callback = mock(CallbackContext.class);
        when(callback.state()).thenReturn(invocationState);
        when(callback.agentName()).thenReturn("child");
        when(callback.userId()).thenReturn("user");
        assertThat(authorization.beforeAgentCallback().call(callback).blockingGet()).isNull();
        assertThat(client.permission.originalCallers())
                .containsExactly(new PermissionRequest.Principal("agent", "parent"));

        InvocationContext invocation = mock(InvocationContext.class);
        Session session = mock(Session.class);
        when(invocation.session()).thenReturn(session);
        when(session.state()).thenReturn(new State(new HashMap<>()));
        var agent = mock(com.google.adk.agents.BaseAgent.class);
        when(invocation.agent()).thenReturn(agent);
        when(agent.name()).thenReturn("child");
        when(invocation.userId()).thenReturn("user");
        BaseTool tool = mock(BaseTool.class);
        when(tool.name()).thenReturn("search");
        ToolContext toolContext = mock(ToolContext.class);
        when(toolContext.state()).thenReturn(invocationState);
        assertThat(
                        authorization
                                .beforeToolCallback()
                                .call(invocation, tool, Map.of(), toolContext)
                                .blockingGet())
                .isNull();
        assertThat(client.permission.originalCallers())
                .containsExactly(
                        new PermissionRequest.Principal("agent", "child"),
                        new PermissionRequest.Principal("agent", "parent"));
        assertThat(client.requests).hasSize(1);
    }

    private record TokenRequest(String agent, String user, String upstream) {}

    private static String jwt(String agent, String upstream) throws Exception {
        var mapper = new ObjectMapper();
        var actor = mapper.createObjectNode().put("sub", agent);
        if (upstream != null) {
            actor.set(
                    "act",
                    mapper.readTree(Base64.getUrlDecoder().decode(upstream.split("\\.")[1]))
                            .get("act"));
        }
        var payload = mapper.createObjectNode().put("sub", "user");
        payload.set("act", actor);
        return Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString("{\"alg\":\"none\"}".getBytes(StandardCharsets.UTF_8))
                + "."
                + Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString(mapper.writeValueAsBytes(payload))
                + ".signature";
    }

    private static class RecordingClient implements IdentityClient {
        final List<TokenRequest> requests = new ArrayList<>();
        PermissionRequest permission;
        int apiKeyCalls;

        @Override
        public WorkloadToken getWorkloadToken(String agent, String user, String upstream)
                throws Exception {
            requests.add(new TokenRequest(agent, user, upstream));
            return new WorkloadToken(jwt(agent, upstream), EXPIRY);
        }

        @Override
        public boolean checkPermission(PermissionRequest request) {
            permission = request;
            return true;
        }

        @Override
        public String getApiKey(String provider, String token) {
            apiKeyCalls++;
            return provider + ":" + token;
        }

        @Override
        public OAuth2Credential getOAuth2Credential(
                String provider,
                String token,
                String flow,
                List<String> scopes,
                String redirect,
                boolean force) {
            return new OAuth2Credential(OAuth2Credential.Type.TOKEN, token);
        }
    }
}
