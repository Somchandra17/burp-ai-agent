package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

class ResponseAnalyzerTest {

    private val analyzer = ResponseAnalyzer()

    @Test
    fun calculateDifferenceReturnsPerfectSimilarityForEqualBodies() {
        val diff = analyzer.calculateDifference("a\nb\nc", "a\nb\nc")

        assertEquals(1.0, diff.similarity)
        assertEquals(0, diff.addedLines)
        assertEquals(0, diff.removedLines)
    }

    @Test
    fun calculateDifferenceDetectsAddedAndRemovedLines() {
        val diff = analyzer.calculateDifference("a\nb\nc", "a\nc\nd")

        assertTrue(diff.similarity in 0.0..1.0)
        assertEquals(1, diff.addedLines)
        assertEquals(1, diff.removedLines)
    }

    @Test
    fun analyzeTimeBasedRejectsSlowBaseline() {
        val result = analyzer.analyzeTimeBased(
            baselineTimeMs = 1_500,
            payloadTimeMs = 6_500,
            expectedDelayMs = 5_000
        )

        assertFalse(result)
    }

    @Test
    fun analyzeTimeBasedAcceptsDelayWithinStrictWindow() {
        val result = analyzer.analyzeTimeBased(
            baselineTimeMs = 200,
            payloadTimeMs = 5_200,
            expectedDelayMs = 5_000
        )

        assertTrue(result)
    }

    @Test
    fun analyzeTimeBasedRejectsDelayOutsideStrictWindow() {
        val tooLow = analyzer.analyzeTimeBased(
            baselineTimeMs = 100,
            payloadTimeMs = 4_200,
            expectedDelayMs = 5_000
        )
        val tooHigh = analyzer.analyzeTimeBased(
            baselineTimeMs = 100,
            payloadTimeMs = 8_000,
            expectedDelayMs = 5_000
        )

        assertFalse(tooLow)
        assertFalse(tooHigh)
    }

    @Test
    fun apiVersionBypassIgnoresDocumentationLikeResponses() {
        val payload = Payload("/api/v1/", VulnClass.API_VERSION_BYPASS, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Old API version accessible")
        val original = requestResponse(
            url = "https://example.test/docs",
            path = "/docs",
            statusCode = 200.toShort(),
            contentType = "text/html",
            body = "<html><body>Documentation home</body></html>"
        )
        val modified = requestResponse(
            url = "https://example.test/docs",
            path = "/docs",
            statusCode = 200.toShort(),
            contentType = "text/html",
            body = "<html><body>API documentation for legacy and beta endpoints. See migration guide.</body></html>"
        )

        val result = analyzer.analyze(original, modified, payload, VulnClass.API_VERSION_BYPASS)

        assertNull(result)
    }

    @Test
    fun apiVersionBypassAcceptsStructuredDeprecatedVersionResponse() {
        val payload = Payload("/api/v1/", VulnClass.API_VERSION_BYPASS, DetectionMethod.CONTENT_BASED, PayloadRisk.SAFE, "Old API version accessible")
        val original = requestResponse(
            url = "https://example.test/api/v2/users",
            path = "/api/v2/users",
            statusCode = 200.toShort(),
            contentType = "application/json",
            body = """{"data":[{"id":1}]}"""
        )
        val modified = requestResponse(
            url = "https://example.test/api/v1/users",
            path = "/api/v1/users",
            statusCode = 200.toShort(),
            contentType = "application/json",
            headers = listOf(header("X-API-Version", "v1")),
            body = """{"apiVersion":"v1","data":[{"id":1}],"deprecatedVersion":"v1"}"""
        )

        val result = analyzer.analyze(original, modified, payload, VulnClass.API_VERSION_BYPASS)

        assertNotNull(result)
        assertTrue(result.confirmed)
        assertTrue(result.evidence.contains("Deprecated API version accessible"))
    }

    private fun requestResponse(
        url: String,
        path: String,
        statusCode: Short,
        contentType: String,
        body: String,
        headers: List<HttpHeader> = emptyList()
    ): HttpRequestResponse {
        val request = mock<HttpRequest>()
        val response = mock<HttpResponse>()
        val requestResponse = mock<HttpRequestResponse>()
        val responseHeaders = listOf(header("Content-Type", contentType)) + headers

        whenever(request.url()).thenReturn(url)
        whenever(request.path()).thenReturn(path)
        whenever(request.method()).thenReturn("GET")
        whenever(response.statusCode()).thenReturn(statusCode)
        whenever(response.bodyToString()).thenReturn(body)
        whenever(response.headers()).thenReturn(responseHeaders)
        whenever(response.headerValue("Content-Type")).thenReturn(contentType)
        whenever(requestResponse.request()).thenReturn(request)
        whenever(requestResponse.response()).thenReturn(response)

        return requestResponse
    }

    private fun header(name: String, value: String): HttpHeader {
        val header = mock<HttpHeader>()
        whenever(header.name()).thenReturn(name)
        whenever(header.value()).thenReturn(value)
        return header
    }
}
