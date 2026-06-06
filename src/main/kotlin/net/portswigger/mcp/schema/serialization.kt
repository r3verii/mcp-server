package net.portswigger.mcp.schema

import burp.api.montoya.collaborator.Interaction as CollaboratorInteraction
import burp.api.montoya.organizer.OrganizerItem
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.proxy.ProxyWebSocketMessage
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.websocket.Direction
import kotlinx.serialization.Serializable

/**
 * Montoya's HttpRequest.method()/path()/url() and HttpResponse.statusCode() can throw
 * MalformedRequestException/RuntimeException on malformed messages (common in a pentest
 * workspace). Use this so a single bad item degrades to null fields instead of failing
 * the whole listing.
 */
private inline fun <T> safeMontoya(block: () -> T): T? = try { block() } catch (e: Exception) { null }

fun AuditIssue.toSerializableForm(): IssueDetails {
    return IssueDetails(
        name = name(),
        detail = detail(),
        remediation = remediation(),
        httpService = HttpService(
            host = httpService().host(),
            port = httpService().port(),
            secure = httpService().secure()
        ),
        baseUrl = baseUrl(),
        severity = AuditIssueSeverity.valueOf(severity().name),
        confidence = AuditIssueConfidence.valueOf(confidence().name),
        requestResponses = requestResponses().map { it.toSerializableForm() },
        collaboratorInteractions = collaboratorInteractions().map {
            Interaction(
                interactionId = it.id().toString(),
                timestamp = it.timeStamp().toString()
            )
        },
        definition = AuditIssueDefinition(
            id = definition().name(),
            background = definition().background(),
            remediation = definition().remediation(),
            typeIndex = definition().typeIndex(),
        )
    )
}

fun burp.api.montoya.http.message.HttpRequestResponse.toSerializableForm(): HttpRequestResponse {
    return HttpRequestResponse(
        request = request()?.toString() ?: "<no request>",
        response = response()?.toString() ?: "<no response>",
        notes = annotations().notes()
    )
}

fun ProxyHttpRequestResponse.toSerializableForm(): HttpRequestResponse {
    return HttpRequestResponse(
        request = request()?.toString() ?: "<no request>",
        response = response()?.toString() ?: "<no response>",
        notes = annotations().notes()
    )
}

fun OrganizerItem.toSerializableForm(): OrganizerItemDetails {
    return OrganizerItemDetails(
        id = id(),
        status = status().displayName(),
        request = request()?.toString() ?: "<no request>",
        response = response()?.toString() ?: "<no response>",
        notes = annotations().notes()
    )
}

fun OrganizerItem.toSummaryForm(): OrganizerItemSummary {
    val req = request()
    return OrganizerItemSummary(
        id = id(),
        method = req?.let { safeMontoya { it.method() } },
        host = safeMontoya { httpService()?.host() },
        path = req?.let { safeMontoya { it.path() } },
        httpStatusCode = safeMontoya { response()?.statusCode()?.toInt() },
        status = status().displayName(),
        notes = annotations().notes(),
        requestLength = req?.toString()?.length ?: 0,
        responseLength = safeMontoya { response()?.toString()?.length } ?: 0
    )
}

fun ProxyHttpRequestResponse.toHistorySummary(index: Int): ProxyHistorySummary {
    val req = request()
    return ProxyHistorySummary(
        index = index,
        method = req?.let { safeMontoya { it.method() } },
        host = req?.let { safeMontoya { it.httpService()?.host() } },
        path = req?.let { safeMontoya { it.path() } },
        httpStatusCode = safeMontoya { response()?.statusCode()?.toInt() },
        responseLength = safeMontoya { response()?.toString()?.length } ?: 0,
        notes = annotations().notes()
    )
}

fun burp.api.montoya.http.message.HttpRequestResponse.toSiteMapSummary(): SiteMapEntrySummary {
    val req = request()
    return SiteMapEntrySummary(
        method = req?.let { safeMontoya { it.method() } },
        host = req?.let { safeMontoya { it.httpService()?.host() } },
        path = req?.let { safeMontoya { it.path() } },
        httpStatusCode = safeMontoya { response()?.statusCode()?.toInt() },
        responseLength = safeMontoya { response()?.toString()?.length } ?: 0
    )
}

fun ProxyWebSocketMessage.toSerializableForm(): WebSocketMessage {
    return WebSocketMessage(
        payload = payload()?.toString() ?: "<no payload>",
        direction =
            if (direction() == Direction.CLIENT_TO_SERVER)
                WebSocketMessageDirection.CLIENT_TO_SERVER
            else
                WebSocketMessageDirection.SERVER_TO_CLIENT,
        notes = annotations().notes()
    )
}

@Serializable
data class IssueDetails(
    val name: String?,
    val detail: String?,
    val remediation: String?,
    val httpService: HttpService?,
    val baseUrl: String?,
    val severity: AuditIssueSeverity,
    val confidence: AuditIssueConfidence,
    val requestResponses: List<HttpRequestResponse>,
    val collaboratorInteractions: List<Interaction>,
    val definition: AuditIssueDefinition
)

@Serializable
data class HttpService(
    val host: String,
    val port: Int,
    val secure: Boolean
)

@Serializable
enum class AuditIssueSeverity {
    HIGH,
    MEDIUM,
    LOW,
    INFORMATION,
    FALSE_POSITIVE;
}

@Serializable
enum class AuditIssueConfidence {
    CERTAIN,
    FIRM,
    TENTATIVE
}

@Serializable
data class HttpRequestResponse(
    val request: String?,
    val response: String?,
    val notes: String?
)

@Serializable
data class OrganizerItemDetails(
    val id: Int,
    val status: String,
    val request: String?,
    val response: String?,
    val notes: String?
)

@Serializable
data class OrganizerItemSummary(
    val id: Int,
    val method: String?,
    val host: String?,
    val path: String?,
    val httpStatusCode: Int?,
    val status: String,
    val notes: String?,
    val requestLength: Int,
    val responseLength: Int
)

@Serializable
data class ProxyHistorySummary(
    val index: Int,
    val method: String?,
    val host: String?,
    val path: String?,
    val httpStatusCode: Int?,
    val responseLength: Int,
    val notes: String?
)

@Serializable
data class SiteMapEntrySummary(
    val method: String?,
    val host: String?,
    val path: String?,
    val httpStatusCode: Int?,
    val responseLength: Int
)

@Serializable
data class Interaction(
    val interactionId: String,
    val timestamp: String
)

@Serializable
data class AuditIssueDefinition(
    val id: String,
    val background: String?,
    val remediation: String?,
    val typeIndex: Int
)


@Serializable
enum class WebSocketMessageDirection {
    CLIENT_TO_SERVER,
    SERVER_TO_CLIENT
}

@Serializable
data class WebSocketMessage(
    val payload: String?,
    val direction: WebSocketMessageDirection,
    val notes: String?
)

fun CollaboratorInteraction.toSerializableForm(): CollaboratorInteractionDetails {
    return CollaboratorInteractionDetails(
        id = id().toString(),
        type = type().name,
        timestamp = timeStamp().toString(),
        clientIp = clientIp().hostAddress,
        clientPort = clientPort(),
        customData = customData().orElse(null),
        dnsDetails = dnsDetails().orElse(null)?.let {
            CollaboratorDnsDetails(queryType = it.queryType().name)
        },
        httpDetails = httpDetails().orElse(null)?.let {
            CollaboratorHttpDetails(
                protocol = it.protocol().name,
                request = it.requestResponse()?.request()?.toString(),
                response = it.requestResponse()?.response()?.toString()
            )
        },
        smtpDetails = smtpDetails().orElse(null)?.let {
            CollaboratorSmtpDetails(
                protocol = it.protocol().name,
                conversation = it.conversation()
            )
        }
    )
}

@Serializable
data class CollaboratorInteractionDetails(
    val id: String,
    val type: String,
    val timestamp: String,
    val clientIp: String,
    val clientPort: Int,
    val customData: String?,
    val dnsDetails: CollaboratorDnsDetails?,
    val httpDetails: CollaboratorHttpDetails?,
    val smtpDetails: CollaboratorSmtpDetails?
)

@Serializable
data class CollaboratorDnsDetails(
    val queryType: String
)

@Serializable
data class CollaboratorHttpDetails(
    val protocol: String,
    val request: String?,
    val response: String?
)

@Serializable
data class CollaboratorSmtpDetails(
    val protocol: String,
    val conversation: String
)