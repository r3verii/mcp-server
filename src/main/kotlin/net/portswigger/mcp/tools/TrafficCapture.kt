package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ToolType
import burp.api.montoya.http.handler.HttpHandler
import burp.api.montoya.http.handler.HttpRequestToBeSent
import burp.api.montoya.http.handler.HttpResponseReceived
import burp.api.montoya.http.handler.RequestToBeSentAction
import burp.api.montoya.http.handler.ResponseReceivedAction
import kotlinx.serialization.Serializable
import java.util.concurrent.ConcurrentHashMap

private const val MAX_CAPTURED_PER_TOOL = 1000

/** Montoya's method()/path()/statusCode() can throw on malformed messages (e.g. Intruder payloads). */
private inline fun <T> safeCapture(block: () -> T): T? = try { block() } catch (e: Exception) { null }

/**
 * In-memory ring buffer of HTTP traffic seen by tools that the Montoya API cannot otherwise
 * expose (Repeater, Intruder). The Montoya API has no way to read existing Repeater tabs or
 * past Intruder attacks, so we register a single [HttpHandler] and record the exchanges that
 * flow through those tools while the extension is loaded.
 */
data class CapturedExchange(
    val messageId: Int,
    val tool: String,
    val method: String?,
    val host: String?,
    val path: String?,
    val httpStatusCode: Int?,
    val request: String,
    val response: String
)

object TrafficStore {
    /** One bounded buffer per tool, so a large Intruder run can't evict Repeater captures. */
    private val buffers = ConcurrentHashMap<String, ToolBuffer>()

    @Volatile
    private var registered = false

    private class ToolBuffer {
        private val items = ArrayDeque<CapturedExchange>()

        @Synchronized
        fun add(exchange: CapturedExchange) {
            items.addLast(exchange)
            while (items.size > MAX_CAPTURED_PER_TOOL) {
                items.removeFirst()
            }
        }

        @Synchronized
        fun snapshot(): List<CapturedExchange> = ArrayList(items)
    }

    @Synchronized
    fun ensureRegistered(api: MontoyaApi) {
        if (registered) return

        api.http().registerHttpHandler(object : HttpHandler {
            override fun handleHttpRequestToBeSent(requestToBeSent: HttpRequestToBeSent): RequestToBeSentAction =
                RequestToBeSentAction.continueWith(requestToBeSent)

            override fun handleHttpResponseReceived(responseReceived: HttpResponseReceived): ResponseReceivedAction {
                val tool = responseReceived.toolSource().toolType()
                if (tool == ToolType.REPEATER || tool == ToolType.INTRUDER) {
                    val req = responseReceived.initiatingRequest()
                    val exchange = CapturedExchange(
                        messageId = responseReceived.messageId(),
                        tool = tool.name,
                        method = req?.let { safeCapture { it.method() } },
                        host = req?.let { safeCapture { it.httpService()?.host() } },
                        path = req?.let { safeCapture { it.path() } },
                        httpStatusCode = safeCapture { responseReceived.statusCode().toInt() },
                        request = req?.toString() ?: "<no request>",
                        response = responseReceived.toString()
                    )
                    buffers.computeIfAbsent(tool.name) { ToolBuffer() }.add(exchange)
                }
                return ResponseReceivedAction.continueWith(responseReceived)
            }
        })

        registered = true
    }

    fun summaries(tool: ToolType, newestFirst: Boolean): Sequence<CapturedExchangeSummary> {
        val snapshot = buffers[tool.name]?.snapshot() ?: emptyList()
        val ordered = if (newestFirst) snapshot.asReversed() else snapshot
        return ordered.asSequence().map {
            CapturedExchangeSummary(
                messageId = it.messageId,
                tool = it.tool,
                method = it.method,
                host = it.host,
                path = it.path,
                httpStatusCode = it.httpStatusCode,
                requestLength = it.request.length,
                responseLength = it.response.length
            )
        }
    }

    fun byIds(ids: Set<Int>): List<CapturedExchange> =
        buffers.values.asSequence()
            .flatMap { it.snapshot().asSequence() }
            .filter { it.messageId in ids }
            .toList()
}

@Serializable
data class CapturedExchangeSummary(
    val messageId: Int,
    val tool: String,
    val method: String?,
    val host: String?,
    val path: String?,
    val httpStatusCode: Int?,
    val requestLength: Int,
    val responseLength: Int
)

@Serializable
data class CapturedExchangeDetail(
    val messageId: Int,
    val tool: String,
    val request: String,
    val response: String
)
