package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.lang.reflect.Method

class PassiveAiScannerClassificationTest {

    private fun scanner(): PassiveAiScanner {
        return PassiveAiScanner(
            api = mock<MontoyaApi>(),
            supervisor = mock<AgentSupervisor>(),
            audit = mock<AuditLogger>()
        ) {
            throw IllegalStateException("Settings not needed for classification tests")
        }
    }

    @Test
    fun mapTitleToVulnClass_recognizesVersionDisclosure() {
        val scanner = scanner()

        val result = invokePrivate<VulnClass?>(scanner, "mapTitleToVulnClass", "Version Disclosure via Server Header")

        assertEquals(VulnClass.VERSION_DISCLOSURE, result)
    }

    @Test
    fun normalizeAiSeverity_promotesInformationalVersionDisclosureToLow() {
        val scanner = scanner()

        val result = invokePrivate<String>(
            scanner,
            "normalizeAiSeverity",
            "Version Disclosure via X-Powered-By",
            "Information"
        )

        assertEquals("Low", result)
    }

    @Test
    fun shouldSuppressAiFinding_rejectsMissingSecurityHeaders() {
        val scanner = scanner()

        val suppressed = invokePrivate<Boolean>(scanner, "shouldSuppressAiFinding", "Missing Security Header: CSP")
        val allowed = invokePrivate<Boolean>(scanner, "shouldSuppressAiFinding", "Version Disclosure")

        assertTrue(suppressed)
        assertFalse(allowed)
    }

    @Test
    fun runLocalChecks_detectsVersionDisclosureAndInsecureCookieFlags() {
        val scanner = scanner()
        val request = mock<HttpRequest>()
        val response = mock<HttpResponse>()
        val serverHeader = header("Server", "nginx/1.24.0")
        val cookieHeader = header("Set-Cookie", "sessionid=abc123; Path=/")

        whenever(request.parameters()).thenReturn(emptyList())
        whenever(request.method()).thenReturn("GET")
        whenever(request.url()).thenReturn("https://example.test/")
        whenever(request.headers()).thenReturn(emptyList())
        whenever(response.headers()).thenReturn(listOf(serverHeader, cookieHeader))
        whenever(response.statusCode()).thenReturn(200.toShort())
        whenever(response.headerValue("Content-Type")).thenReturn("text/html")

        @Suppress("UNCHECKED_CAST")
        val findings = invokePrivate<List<Any>>(
            scanner,
            "runLocalChecks",
            request,
            response,
            "",
            "<html><body>Hello</body></html>"
        )

        val titles = findings.map { finding ->
            val titleField = finding.javaClass.getDeclaredField("title")
            titleField.isAccessible = true
            titleField.get(finding) as String
        }

        assertTrue("Version Disclosure" in titles)
        assertTrue("Insecure Cookie Flags" in titles)
    }

    private fun header(name: String, value: String): HttpHeader {
        val header = mock<HttpHeader>()
        whenever(header.name()).thenReturn(name)
        whenever(header.value()).thenReturn(value)
        return header
    }

    private inline fun <reified T> invokePrivate(scanner: PassiveAiScanner, methodName: String, vararg args: Any?): T {
        val parameterTypes = args.map { arg ->
            when (arg) {
                is String -> String::class.java
                is HttpRequest -> HttpRequest::class.java
                is HttpResponse -> HttpResponse::class.java
                else -> arg?.javaClass ?: Any::class.java
            }
        }.toTypedArray()

        val method: Method = scanner.javaClass.getDeclaredMethod(methodName, *parameterTypes)
        method.isAccessible = true
        @Suppress("UNCHECKED_CAST")
        return method.invoke(scanner, *args) as T
    }
}
