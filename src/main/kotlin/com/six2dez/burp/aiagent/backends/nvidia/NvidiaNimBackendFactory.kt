package com.six2dez.burp.aiagent.backends.nvidia

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.six2dez.burp.aiagent.backends.AgentConnection
import com.six2dez.burp.aiagent.backends.AiBackend
import com.six2dez.burp.aiagent.backends.AiBackendFactory
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import com.six2dez.burp.aiagent.backends.HealthCheckResult
import com.six2dez.burp.aiagent.backends.http.HttpBackendSupport
import com.six2dez.burp.aiagent.backends.openai.OpenAiCompatibleBackend
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.util.HeaderParser
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

class NvidiaNimBackendFactory : AiBackendFactory {
    override fun create(): AiBackend = NvidiaNimBackend()

    companion object {
        const val DEFAULT_BASE_URL: String = "https://integrate.api.nvidia.com"
    }
}

private class NvidiaNimBackend : AiBackend {
    override val id: String = "nvidia-nim"
    override val displayName: String = "NVIDIA NIM"
    override val supportsSystemRole: Boolean = true

    private val delegate = OpenAiCompatibleBackend(
        id = id,
        displayName = displayName,
        defaultBaseUrl = NvidiaNimBackendFactory.DEFAULT_BASE_URL,
        baseUrlSelector = { it.nvidiaNimUrl.trim() },
        modelSelector = { it.nvidiaNimModel.trim() },
        apiKeySelector = { it.nvidiaNimApiKey },
        headersSelector = { it.nvidiaNimHeaders },
        timeoutSelector = { it.nvidiaNimTimeoutSeconds }
    )
    private val mapper = ObjectMapper().registerKotlinModule()

    override fun launch(config: BackendLaunchConfig): AgentConnection = delegate.launch(config)

    override fun healthCheck(settings: AgentSettings): HealthCheckResult {
        val baseUrl = settings.nvidiaNimUrl.trim().ifBlank { NvidiaNimBackendFactory.DEFAULT_BASE_URL }
        val model = settings.nvidiaNimModel.trim()
        if (model.isBlank()) {
            return HealthCheckResult.Unavailable("NVIDIA NIM model is empty.")
        }

        val headers = HeaderParser.withBearerToken(
            settings.nvidiaNimApiKey,
            HeaderParser.parse(settings.nvidiaNimHeaders)
        )
        val payload = mapOf(
            "model" to model,
            "messages" to listOf(mapOf("role" to "user", "content" to "ping")),
            "max_tokens" to 1,
            "stream" to false,
            "temperature" to 0.0
        )

        return try {
            val client = HttpBackendSupport.sharedClient(baseUrl, settings.nvidiaNimTimeoutSeconds.toLong().coerceIn(5L, 30L))
            val request = Request.Builder()
                .url(buildChatCompletionsUrl(baseUrl))
                .post(mapper.writeValueAsString(payload).toRequestBody("application/json".toMediaType()))
                .apply { headers.forEach { (name, value) -> header(name, value) } }
                .build()
            client.newCall(request).execute().use { response ->
                when {
                    response.isSuccessful -> HealthCheckResult.Healthy
                    response.code == 401 || response.code == 403 ->
                        HealthCheckResult.Degraded("Endpoint reachable but authentication failed (HTTP ${response.code}).")
                    else -> HealthCheckResult.Unavailable("HTTP ${response.code}.")
                }
            }
        } catch (e: Exception) {
            HealthCheckResult.Unavailable(e.message ?: "Request failed")
        }
    }

    private fun buildChatCompletionsUrl(baseUrl: String): String {
        val trimmed = baseUrl.trimEnd('/')
        val lower = trimmed.lowercase()
        if (lower.endsWith("/chat/completions")) return trimmed
        if (VERSIONED_ENDPOINT_REGEX.matches(trimmed)) return trimmed
        if (VERSIONED_BASE_REGEX.matches(trimmed)) return "$trimmed/chat/completions"
        return "$trimmed/v1/chat/completions"
    }

    private companion object {
        private val VERSIONED_BASE_REGEX = Regex(".*/v\\d+$", RegexOption.IGNORE_CASE)
        private val VERSIONED_ENDPOINT_REGEX = Regex(".*/v\\d+/chat/completions$", RegexOption.IGNORE_CASE)
    }
}
