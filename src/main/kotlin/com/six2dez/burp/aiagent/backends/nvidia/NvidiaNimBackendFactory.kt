package com.six2dez.burp.aiagent.backends.nvidia

import com.six2dez.burp.aiagent.backends.AiBackend
import com.six2dez.burp.aiagent.backends.AiBackendFactory
import com.six2dez.burp.aiagent.backends.openai.OpenAiCompatibleBackend

class NvidiaNimBackendFactory : AiBackendFactory {
    override fun create(): AiBackend {
        return OpenAiCompatibleBackend(
            id = "nvidia-nim",
            displayName = "NVIDIA NIM",
            defaultBaseUrl = DEFAULT_BASE_URL,
            baseUrlSelector = { it.nvidiaNimUrl.trim() },
            modelSelector = { it.nvidiaNimModel.trim() },
            apiKeySelector = { it.nvidiaNimApiKey },
            headersSelector = { it.nvidiaNimHeaders },
            timeoutSelector = { it.nvidiaNimTimeoutSeconds }
        )
    }

    companion object {
        const val DEFAULT_BASE_URL: String = "https://integrate.api.nvidia.com"
    }
}
