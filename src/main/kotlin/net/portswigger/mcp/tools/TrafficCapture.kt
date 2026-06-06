package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ToolType
import burp.api.montoya.http.handler.HttpHandler
import burp.api.montoya.http.handler.HttpRequestToBeSent
import burp.api.montoya.http.handler.HttpResponseReceived
import burp.api.montoya.http.handler.RequestToBeSentAction
import burp.api.montoya.http.handler.ResponseReceivedAction
import kotlinx.serialization.Serializable
import java.util.concurrent.ConcurrentLinkedDeque

private const val MAX_CAPTURED_EXCHANGES = 1000

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
    private val exchanges = ConcurrentLinkedDeque<CapturedExchange>()

    @Volatile
    private var registered = false

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
                    exchanges.addLast(
                        CapturedExchange(
                            messageId = responseReceived.messageId(),
                            tool = tool.name,
                            method = req?.method(),
                            host = req?.httpService()?.host(),
                            path = req?.path(),
                            httpStatusCode = responseReceived.statusCode().toInt(),
                            request = req?.toString() ?: "<no request>",
                            response = responseReceived.toString()
                        )
                    )
                    while (exchanges.size > MAX_CAPTURED_EXCHANGES) {
                        exchanges.pollFirst()
                    }
                }
                return ResponseReceivedAction.continueWith(responseReceived)
            }
        })

        registered = true
    }

    fun summaries(tool: ToolType): Sequence<CapturedExchangeSummary> =
        exchanges.asSequence()
            .filter { it.tool == tool.name }
            .map {
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

    fun byIds(ids: Set<Int>): List<CapturedExchange> =
        exchanges.filter { it.messageId in ids }
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
