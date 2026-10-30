/** Copyright (c) 2025 Beijing Volcano Engine Technology Co., Ltd. */
package com.volcengine.veadk.security.identity;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Map;
import java.util.Objects;

/** Session-scoped workload token cache compatible with veadk-python. */
public final class WorkloadTokenManager {
    public static final Duration DEFAULT_REFRESH_BUFFER = Duration.ofSeconds(60);

    /** Authenticated request context only; never populate this from model/tool arguments. */
    public static final String UPSTREAM_TOKEN_STATE_KEY = "temp:veadk:identity:upstream_token";

    private final IdentityClient client;
    private final Clock clock;
    private final Duration refreshBuffer;

    public WorkloadTokenManager(IdentityClient client) {
        this(client, Clock.systemUTC(), DEFAULT_REFRESH_BUFFER);
    }

    public WorkloadTokenManager(IdentityClient client, Clock clock, Duration refreshBuffer) {
        this.client = Objects.requireNonNull(client, "client must be set.");
        this.clock = Objects.requireNonNull(clock, "clock must be set.");
        this.refreshBuffer = Objects.requireNonNull(refreshBuffer, "refreshBuffer must be set.");
    }

    public String get(Map<String, Object> state, String agentName, String userId) throws Exception {
        return get(state, agentName, userId, upstreamToken(state));
    }

    /** Exchange an explicitly supplied upstream JWT, or use the user/workload flow when absent. */
    public String get(Map<String, Object> state, String agentName, String userId, String userToken)
            throws Exception {
        Objects.requireNonNull(state, "state must be set.");
        String upstream = normalizeToken(userToken);
        String key = cacheKey("workload_token", agentName, userId, upstream);
        Object cached = state.get(key);
        if (cached instanceof WorkloadToken token
                && clock.instant().isBefore(token.expiresAt().minus(refreshBuffer))) {
            return token.value();
        }
        WorkloadToken token =
                client.getWorkloadToken(agentName, upstream == null ? userId : null, upstream);
        state.put(key, token);
        return token.value();
    }

    static String upstreamToken(Map<String, Object> state) {
        Objects.requireNonNull(state, "state must be set.");
        Object value = state.get(UPSTREAM_TOKEN_STATE_KEY);
        if (value == null) return null;
        if (!(value instanceof String token)) {
            throw new IllegalArgumentException("Upstream identity token must be a string.");
        }
        return normalizeToken(token);
    }

    private static String normalizeToken(String value) {
        if (value == null || value.isBlank()) return null;
        String token = value.trim();
        if (token.equalsIgnoreCase("Bearer")) {
            throw new IllegalArgumentException("Upstream identity token is empty.");
        }
        if (token.regionMatches(true, 0, "Bearer ", 0, 7)) {
            token = token.substring(7).trim();
            if (token.isEmpty())
                throw new IllegalArgumentException("Upstream identity token is empty.");
        }
        return token;
    }

    static String cacheKey(String prefix, String... scope) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (String value : scope) {
                byte[] bytes = value == null ? new byte[0] : value.getBytes(StandardCharsets.UTF_8);
                digest.update(
                        ByteBuffer.allocate(4).putInt(value == null ? -1 : bytes.length).array());
                digest.update(bytes);
            }
            // Do not expose upstream JWTs in keys or reuse pre-delegation cache entries.
            return prefix + ":v2:" + HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Unable to scope identity credential cache.", e);
        }
    }
}
