package com.six2dez.burp.aiagent.backends.nvidia

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.six2dez.burp.aiagent.backends.AgentConnection
import com.six2dez.burp.aiagent.backends.AiBackend
import com.six2dez.burp.aiagent.backends.AiBackendFactory
import com.six2dez.burp.aiagent.backends.BackendDiagnostics
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import com.six2dez.burp.aiagent.backends.HealthCheckResult
import com.six2dez.burp.aiagent.backends.TokenUsage
import com.six2dez.burp.aiagent.backends.UsageAwareConnection
import com.six2dez.burp.aiagent.backends.http.CircuitBreaker
import com.six2dez.burp.aiagent.backends.http.ConversationHistory
import com.six2dez.burp.aiagent.backends.http.HttpBackendSupport
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.util.HeaderParser
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.BufferedReader
import java.io.InputStreamReader
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

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

    private val mapper = ObjectMapper().registerKotlinModule()

    override fun launch(config: BackendLaunchConfig): AgentConnection {
        val baseUrl = effectiveBaseUrl(config.baseUrl)
        val model = config.model?.ifBlank { "" } ?: ""
        val timeoutSeconds = (config.requestTimeoutSeconds ?: 120L).coerceIn(30L, 3600L)
        val client = HttpBackendSupport.sharedClient(baseUrl, timeoutSeconds)
        return NvidiaNimConnection(
            client = client,
            mapper = mapper,
            baseUrl = baseUrl,
            model = model,
            headers = withDefaultAcceptHeader(config.headers),
            determinismMode = config.determinismMode,
            sessionId = config.sessionId,
            circuitBreaker = HttpBackendSupport.newCircuitBreaker(),
            debugLog = { BackendDiagnostics.log("[nvidia-nim] $it") },
            errorLog = { BackendDiagnostics.logError("[nvidia-nim] $it") }
        )
    }

    override fun healthCheck(settings: AgentSettings): HealthCheckResult {
        val baseUrl = settings.nvidiaNimUrl.trim().ifBlank { NvidiaNimBackendFactory.DEFAULT_BASE_URL }
        val model = settings.nvidiaNimModel.trim()
        if (model.isBlank()) {
            return HealthCheckResult.Unavailable("NVIDIA NIM model is empty.")
        }

        val headers = withDefaultAcceptHeader(
            HeaderParser.withBearerToken(
                settings.nvidiaNimApiKey,
                HeaderParser.parse(settings.nvidiaNimHeaders)
            )
        )
        val payload = mapOf(
            "model" to model,
            "messages" to listOf(mapOf("role" to "user", "content" to "Hey")),
            "max_tokens" to 16,
            "temperature" to 1.0,
            "top_p" to 1.0,
            "stream" to false,
            "chat_template_kwargs" to mapOf("thinking" to true)
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
                    response.code == 429 ->
                        HealthCheckResult.Degraded("Endpoint reachable but rate limited (HTTP 429).")
                    else -> HealthCheckResult.Unavailable("HTTP ${response.code}.")
                }
            }
        } catch (e: Exception) {
            HealthCheckResult.Unavailable(e.message ?: "Request failed")
        }
    }

    private class NvidiaNimConnection(
        private val client: okhttp3.OkHttpClient,
        private val mapper: ObjectMapper,
        private val baseUrl: String,
        private val model: String,
        private val headers: Map<String, String>,
        private val determinismMode: Boolean,
        private val sessionId: String?,
        private val circuitBreaker: CircuitBreaker,
        private val debugLog: (String) -> Unit,
        private val errorLog: (String) -> Unit
    ) : AgentConnection, UsageAwareConnection {
        private val alive = AtomicBoolean(true)
        private val exec = Executors.newSingleThreadExecutor { runnable ->
            Thread(runnable, "nvidia-nim-connection").apply { isDaemon = true }
        }
        private val conversationHistory = ConversationHistory(20)
        private val lastTokenUsageRef = AtomicReference<TokenUsage?>(null)

        override fun isAlive(): Boolean = alive.get()

        override fun lastTokenUsage(): TokenUsage? = lastTokenUsageRef.get()

        override fun send(
            text: String,
            history: List<com.six2dez.burp.aiagent.backends.ChatMessage>?,
            onChunk: (String) -> Unit,
            onComplete: (Throwable?) -> Unit,
            systemPrompt: String?
        ) {
            if (!isAlive()) {
                onComplete(IllegalStateException("Connection closed"))
                return
            }

            exec.submit {
                try {
                    lastTokenUsageRef.set(null)
                    if (history != null) {
                        conversationHistory.setHistory(history)
                    }
                    conversationHistory.setSystemPrompt(systemPrompt)
                    val maxAttempts = 6
                    var attempt = 0
                    var lastError: Exception? = null
                    while (attempt < maxAttempts) {
                        val permission = circuitBreaker.tryAcquire()
                        if (!permission.allowed) {
                            val failFastError = HttpBackendSupport.openCircuitError("NVIDIA NIM", permission.retryAfterMs)
                            debugLog("circuit open: ${failFastError.message}")
                            onComplete(failFastError)
                            return@submit
                        }
                        if (!isAlive()) {
                            onComplete(IllegalStateException("Connection closed"))
                            return@submit
                        }
                        try {
                            conversationHistory.addUser(text)
                            val messages = conversationHistory.snapshot()
                            val payload = mapOf(
                                "model" to model,
                                "messages" to messages,
                                "max_tokens" to 16384,
                                "temperature" to if (determinismMode) 0.0 else 1.0,
                                "top_p" to 1.0,
                                "stream" to true,
                                "chat_template_kwargs" to mapOf("thinking" to true)
                            )

                            val req = Request.Builder()
                                .url(buildChatCompletionsUrl(baseUrl))
                                .post(mapper.writeValueAsString(payload).toRequestBody("application/json".toMediaType()))
                                .apply {
                                    headers.forEach { (name, value) -> header(name, value) }
                                    if (!sessionId.isNullOrBlank()) {
                                        header("X-Session-Id", sessionId)
                                    }
                                }
                                .build()

                            debugLog("request -> ${req.url}")
                            client.newCall(req).execute().use { resp ->
                                if (!resp.isSuccessful) {
                                    val bodyText = resp.body?.string().orEmpty()
                                    errorLog("HTTP ${resp.code}: ${bodyText.take(500)}")
                                    val retryAfter = resp.header("Retry-After")
                                    val message = when (resp.code) {
                                        429 -> {
                                            val retryHint = retryAfter?.takeIf { it.isNotBlank() }?.let { " Retry after: $it." }.orEmpty()
                                            "NVIDIA NIM rate limited (HTTP 429). The provider accepted the request shape but rejected it for quota/capacity.$retryHint"
                                        }
                                        else -> "NVIDIA NIM HTTP ${resp.code}: $bodyText"
                                    }
                                    onComplete(IllegalStateException(message))
                                    return@submit
                                }

                                val body = resp.body ?: run {
                                    onComplete(IllegalStateException("NVIDIA NIM response body was empty"))
                                    return@submit
                                }
                                val streamReader = BufferedReader(InputStreamReader(body.byteStream()))
                                var emittedAny = false
                                var line: String?
                                while (isAlive()) {
                                    line = streamReader.readLine() ?: break
                                    val trimmed = line.trim()
                                    if (trimmed.isEmpty() || !trimmed.startsWith("data:")) continue
                                    val data = trimmed.removePrefix("data:").trim()
                                    if (data == "[DONE]") break
                                    val node = mapper.readTree(data)
                                    extractUsage(node)?.let { lastTokenUsageRef.set(it) }
                                    val chunkText = extractChunkText(node)
                                    if (!chunkText.isNullOrEmpty()) {
                                        emittedAny = true
                                        onChunk(chunkText)
                                    }
                                }

                                if (!emittedAny) {
                                    onComplete(IllegalStateException("NVIDIA NIM response content was empty"))
                                    return@submit
                                }
                                circuitBreaker.recordSuccess()
                                onComplete(null)
                                return@submit
                            }
                        } catch (e: Exception) {
                            lastError = e
                            val retryable = HttpBackendSupport.isRetryableConnectionError(e)
                            if (retryable) {
                                circuitBreaker.recordFailure()
                            }
                            if (!retryable || attempt == maxAttempts - 1) {
                                throw e
                            }
                            val delayMs = HttpBackendSupport.retryDelayMs(attempt)
                            BackendDiagnostics.logRetry("nvidia-nim", attempt + 1, delayMs, e.message)
                            debugLog("retrying in ${delayMs}ms after: ${e.message}")
                            try {
                                Thread.sleep(delayMs)
                            } catch (_: InterruptedException) {
                                Thread.currentThread().interrupt()
                                throw e
                            }
                            attempt++
                        }
                    }
                    if (lastError != null) {
                        throw lastError
                    }
                } catch (e: Exception) {
                    errorLog("exception: ${e.message}")
                    onComplete(e)
                } finally {
                    if (!isAlive()) {
                        exec.shutdownNow()
                    }
                }
            }
        }

        override fun stop() {
            alive.set(false)
            exec.shutdownNow()
        }

        private fun extractChunkText(node: JsonNode): String? {
            val choice = node.path("choices").path(0)
            val deltaContent = choice.path("delta").path("content").asText()
            if (deltaContent.isNotBlank()) return deltaContent
            val messageContent = choice.path("message").path("content").asText()
            if (messageContent.isNotBlank()) return messageContent
            return null
        }

        private fun extractUsage(node: JsonNode): TokenUsage? {
            val usageNode = node.path("usage")
            val promptTokens = usageNode.path("prompt_tokens").asInt(-1)
            val completionTokens = usageNode.path("completion_tokens").asInt(-1)
            if (promptTokens < 0 && completionTokens < 0) return null
            return TokenUsage(
                inputTokens = promptTokens.coerceAtLeast(0),
                outputTokens = completionTokens.coerceAtLeast(0)
            )
        }
    }

    private fun effectiveBaseUrl(candidate: String?): String {
        val trimmed = candidate?.trim()?.trimEnd('/').orEmpty()
        if (trimmed.isNotBlank()) return trimmed
        return NvidiaNimBackendFactory.DEFAULT_BASE_URL
    }

    private companion object {
        private val versionedBaseRegex = Regex(".*/v\\d+$", RegexOption.IGNORE_CASE)
        private val versionedEndpointRegex = Regex(".*/v\\d+/chat/completions$", RegexOption.IGNORE_CASE)

        private fun buildChatCompletionsUrl(baseUrl: String): String {
            val trimmed = baseUrl.trimEnd('/')
            val lower = trimmed.lowercase()
            if (lower.endsWith("/chat/completions")) return trimmed
            if (versionedEndpointRegex.matches(trimmed)) return trimmed
            if (versionedBaseRegex.matches(trimmed)) return "$trimmed/chat/completions"
            return "$trimmed/v1/chat/completions"
        }

        private fun withDefaultAcceptHeader(headers: Map<String, String>): Map<String, String> {
            val merged = LinkedHashMap<String, String>()
            merged.putAll(headers)
            if (merged.keys.none { it.equals("accept", ignoreCase = true) }) {
                merged["Accept"] = "text/event-stream"
            }
            return merged
        }
    }
}
