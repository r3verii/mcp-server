package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.PAUSED
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.RUNNING
import burp.api.montoya.collaborator.InteractionFilter
import burp.api.montoya.core.Annotations
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.core.HighlightColor
import burp.api.montoya.core.ToolType
import burp.api.montoya.sitemap.SiteMapFilter
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.schema.toSerializableForm
import net.portswigger.mcp.schema.toSummaryForm
import net.portswigger.mcp.schema.toHistorySummary
import net.portswigger.mcp.schema.toSiteMapSummary
import net.portswigger.mcp.security.DataAccessSecurity
import net.portswigger.mcp.security.DataAccessType
import net.portswigger.mcp.security.HttpRequestSecurity
import net.portswigger.mcp.security.filterConfigCredentials
import java.awt.KeyboardFocusManager
import java.util.regex.Pattern
import javax.swing.JTextArea

private suspend fun checkDataAccessOrDeny(
    accessType: DataAccessType, config: McpConfig, api: MontoyaApi, logMessage: String
): Boolean {
    val allowed = DataAccessSecurity.checkDataAccessPermission(accessType, config)
    if (!allowed) {
        api.logging().logToOutput("MCP $logMessage access denied")
        return false
    }
    api.logging().logToOutput("MCP $logMessage access granted")
    return true
}

private fun truncateIfNeeded(serialized: String, maxLength: Int): String {
    return if (maxLength > 0 && serialized.length > maxLength) {
        serialized.substring(0, maxLength) + "... (truncated)"
    } else {
        serialized
    }
}

/** Returns the list newest-first (reversed view) when [newestFirst] is true, otherwise unchanged. */
private fun <T> List<T>.orderedBy(newestFirst: Boolean?): List<T> =
    if (newestFirst == true) asReversed() else this

private fun buildHttp2HeaderList(
    pseudoHeaders: Map<String, String>, headers: Map<String, String>
): List<HttpHeader> {
    val orderedPseudoHeaderNames = listOf(":scheme", ":method", ":path", ":authority")

    val fixedPseudoHeaders = LinkedHashMap<String, String>().apply {
        orderedPseudoHeaderNames.forEach { name ->
            val value = pseudoHeaders[name.removePrefix(":")] ?: pseudoHeaders[name]
            if (value != null) {
                put(name, value)
            }
        }

        pseudoHeaders.forEach { (key, value) ->
            val properKey = if (key.startsWith(":")) key else ":$key"
            if (!containsKey(properKey)) {
                put(properKey, value)
            }
        }
    }

    return (fixedPseudoHeaders + headers).map { HttpHeader.httpHeader(it.key.lowercase(), it.value) }
}

/**
 * Normalizes HTTP request line endings from MCP clients.
 *
 * MCP clients (e.g. Claude Code) often emit `\r\n` as the 4-character literal
 * sequence backslash-r-backslash-n in JSON tool parameters rather than actual
 * CR (0x0D) + LF (0x0A) bytes. The resulting text parses as a single line,
 * which strict servers (e.g. Apache-Coyote) reject with 400 Bad Request and
 * which Burp/Montoya may "repair" by injecting headers after the body
 * separator.
 *
 * Normalization is applied only to the request prelude (request line and
 * headers, up to and including the first blank line). The body is preserved
 * verbatim so that legitimate escape sequences in bodies — e.g. `\n` inside a
 * JSON string literal — and binary payloads remain byte-exact. If no blank
 * line is present, the entire content is treated as prelude.
 */
internal fun normalizeHttpContent(content: String): String {
    val preludeEnd = findPreludeEnd(content) ?: return normalizePrelude(content)
    return normalizePrelude(content.substring(0, preludeEnd)) + content.substring(preludeEnd)
}

private val BLANK_LINE_MARKERS = listOf(
    "\r\n\r\n",         // actual CRLF blank line
    "\n\n",              // actual LF blank line
    "\\r\\n\\r\\n",     // literal CRLF blank line
    "\\n\\n",            // literal LF blank line
)

private fun findPreludeEnd(content: String): Int? {
    var bestStart = -1
    var bestLen = 0
    for (marker in BLANK_LINE_MARKERS) {
        val idx = content.indexOf(marker)
        if (idx >= 0 && (bestStart < 0 || idx < bestStart)) {
            bestStart = idx
            bestLen = marker.length
        }
    }
    return if (bestStart < 0) null else bestStart + bestLen
}

private fun normalizePrelude(prelude: String): String = prelude
    .replace("\\r\\n", "\n")   // Literal \r\n escape sequences → LF
    .replace("\\n", "\n")      // Remaining literal \n → LF
    .replace("\\r", "")        // Remaining literal \r → remove
    .replace("\r", "")          // Actual CR → remove
    .replace("\n", "\r\n")      // All LF → proper CRLF

/**
 * Usage manual sent to the MCP client at initialize time (MCP server "instructions").
 * Teaches the client to use the compact index tools and fetch details on demand instead of
 * dumping everything.
 */
val SERVER_INSTRUCTIONS = """
    This server exposes Burp Suite data and actions for web security testing.

    GOLDEN RULE — be precise, never dump everything. To read recorded traffic, ALWAYS start
    with a compact INDEX tool (it returns id/method/host/path/status/sizes WITHOUT bodies, so
    you can scan many items cheaply), identify the item(s) by method+host+path, then fetch only
    those full request/response by id/index:
      - Organizer:      list_organizer_items(newestFirst?) -> get_organizer_items_by_id(ids)
      - Proxy history:  list_proxy_http_history(hostFilter?, newestFirst?) -> get_proxy_http_history_by_index(indices)
        (for the latest/most-recent N requests use newestFirst=true with count=N)
      - Site map:       get_site_map(prefix?)        (compact index of the attack surface)
      - Repeater:       get_repeater_traffic         -> get_captured_exchange_by_id(ids)
      - Intruder:       get_intruder_traffic         -> get_captured_exchange_by_id(ids)

    AVOID the raw bulk tools (get_proxy_http_history, get_organizer_items,
    get_proxy_websocket_history): they return FULL request+response per item and can produce
    huge output that gets truncated. Only use them with a SMALL count, and only when you
    actually need the bodies.

    Filter instead of scanning: list_proxy_http_history takes a hostFilter; get_site_map takes a
    URL prefix; the *_regex tools match request/response content.

    count/offset are pagination over item COUNT (not bytes): keep count small, page with offset.
    Most history/traffic list tools also accept newestFirst=true to return the most recent items
    first (e.g. newestFirst=true, count=5 = the 5 latest).

    When the user says "read/look at the X request", first list the relevant index, match X by
    method+host+path, then fetch that single item by id/index — do not pull everything.

    Save/triage findings: send_to_organizer (saves a request+response, optional note),
    set_organizer_item_notes / set_organizer_item_highlight (tag items by id; notes work as
    ad-hoc "collections"). Sending requests respects Burp's scope/approval rules.
""".trimIndent()

fun Server.registerTools(api: MontoyaApi, config: McpConfig) {

    TrafficStore.ensureRegistered(api)

    mcpTool<SendHttp1Request>("Issues an HTTP/1.1 request and returns the response.") {
        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(targetHostname, targetPort, config, content, api)
        }
        if (!allowed) {
            api.logging().logToOutput("MCP HTTP request denied: $targetHostname:$targetPort")
            return@mcpTool "Send HTTP request denied by Burp Suite"
        }

        api.logging().logToOutput("MCP HTTP/1.1 request: $targetHostname:$targetPort")

        val fixedContent = normalizeHttpContent(content)

        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        val response = api.http().sendRequest(request)

        response?.toString() ?: "<no response>"
    }

    mcpTool<SendHttp2Request>("Issues an HTTP/2 request and returns the response. Do NOT pass headers to the body parameter.") {
        val http2RequestDisplay = buildString {
            pseudoHeaders.forEach { (key, value) ->
                val headerName = if (key.startsWith(":")) key else ":$key"
                appendLine("$headerName: $value")
            }
            headers.forEach { (key, value) ->
                appendLine("$key: $value")
            }
            if (requestBody.isNotBlank()) {
                appendLine()
                append(requestBody)
            }
        }

        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(targetHostname, targetPort, config, http2RequestDisplay, api)
        }
        if (!allowed) {
            api.logging().logToOutput("MCP HTTP request denied: $targetHostname:$targetPort")
            return@mcpTool "Send HTTP request denied by Burp Suite"
        }

        api.logging().logToOutput("MCP HTTP/2 request: $targetHostname:$targetPort")

        val headerList = buildHttp2HeaderList(pseudoHeaders, headers)

        val request = HttpRequest.http2Request(toMontoyaService(), headerList, requestBody)
        val response = api.http().sendRequest(request, HttpMode.HTTP_2)

        response?.toString() ?: "<no response>"
    }

    mcpTool<CreateRepeaterTab>("Creates an HTTP/1.1 Repeater tab with the specified raw HTTP request and optional tab name. Make sure to use carriage returns appropriately. Prefer create_repeater_tab_http2 for modern web targets that speak HTTP/2.") {
        val fixedContent = normalizeHttpContent(content)
        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        api.repeater().sendToRepeater(request, tabName)
    }

    mcpTool<CreateRepeaterTabHttp2>("Creates an HTTP/2 Repeater tab with the specified HTTP/2 request and optional tab name. Use this by default for modern web targets. Do NOT pass headers to the body parameter.") {
        val headerList = buildHttp2HeaderList(pseudoHeaders, headers)
        val request = HttpRequest.http2Request(toMontoyaService(), headerList, requestBody)
        api.repeater().sendToRepeater(request, tabName)
    }

    mcpTool<SendToIntruder>("Sends an HTTP request to Intruder with the specified HTTP request and optional tab name. Make sure to use carriage returns appropriately.") {
        val fixedContent = normalizeHttpContent(content)
        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        api.intruder().sendToIntruder(request, tabName)
    }

    mcpTool<UrlEncode>("URL encodes the input string") {
        api.utilities().urlUtils().encode(content)
    }

    mcpTool<UrlDecode>("URL decodes the input string") {
        api.utilities().urlUtils().decode(content)
    }

    mcpTool<Base64Encode>("Base64 encodes the input string") {
        api.utilities().base64Utils().encodeToString(content)
    }

    mcpTool<Base64Decode>("Base64 decodes the input string") {
        api.utilities().base64Utils().decode(content).toString()
    }

    mcpTool<GenerateRandomString>("Generates a random string of specified length and character set") {
        api.utilities().randomUtils().randomString(length, characterSet)
    }

    mcpTool(
        "output_project_options",
        "Outputs current project-level configuration in JSON format. You can use this to determine the schema for available config options."
    ) {
        val json = api.burpSuite().exportProjectOptionsAsJson()
        if (config.filterConfigCredentials) {
            filterConfigCredentials(json)
        } else {
            json
        }
    }

    mcpTool(
        "output_user_options",
        "Outputs current user-level configuration in JSON format. You can use this to determine the schema for available config options."
    ) {
        val json = api.burpSuite().exportUserOptionsAsJson()
        if (config.filterConfigCredentials) {
            filterConfigCredentials(json)
        } else {
            json
        }
    }

    val toolingDisabledMessage =
        "User has disabled configuration editing. They can enable it in the MCP tab in Burp by selecting 'Enable tools that can edit your config'"

    mcpTool<SetProjectOptions>("Sets project-level configuration in JSON format. This will be merged with existing configuration. Make sure to export before doing this, so you know what the schema is. Make sure the JSON has a top level 'user_options' object!") {
        if (config.configEditingTooling) {
            api.logging().logToOutput("Setting project-level configuration: $json")
            api.burpSuite().importProjectOptionsFromJson(json)

            "Project configuration has been applied"
        } else {
            toolingDisabledMessage
        }
    }


    mcpTool<SetUserOptions>("Sets user-level configuration in JSON format. This will be merged with existing configuration. Make sure to export before doing this, so you know what the schema is. Make sure the JSON has a top level 'project_options' object!") {
        if (config.configEditingTooling) {
            api.logging().logToOutput("Setting user-level configuration: $json")
            api.burpSuite().importUserOptionsFromJson(json)

            "User configuration has been applied"
        } else {
            toolingDisabledMessage
        }
    }

    if (api.burpSuite().version().edition() == BurpSuiteEdition.PROFESSIONAL) {
        mcpPaginatedTool<GetScannerIssues>("Displays information about issues identified by the scanner") {
            api.siteMap().issues().asSequence().map { Json.encodeToString(it.toSerializableForm()) }
        }

        val collaboratorClient by lazy { api.collaborator().createClient() }

        mcpTool<GenerateCollaboratorPayload>(
            "Generates a Burp Collaborator payload URL for out-of-band (OOB) testing. " +
            "Inject this payload into requests to detect server-side interactions (DNS lookups, HTTP requests, SMTP). " +
            "Use get_collaborator_interactions with the returned payloadId to check for interactions."
        ) {
            api.logging().logToOutput("MCP generating Collaborator payload${customData?.let { " with custom data" } ?: ""}")

            val payload = if (customData != null) {
                collaboratorClient.generatePayload(customData)
            } else {
                collaboratorClient.generatePayload()
            }

            val server = collaboratorClient.server()
            "Payload: $payload\nPayload ID: ${payload.id()}\nCollaborator server: ${server.address()}"
        }

        mcpTool<GetCollaboratorInteractions>(
            "Polls Burp Collaborator for out-of-band interactions (DNS, HTTP, SMTP). " +
            "Optionally filter by payloadId from generate_collaborator_payload. " +
            "Returns interaction details including type, timestamp, client IP, and protocol-specific data."
        ) {
            api.logging().logToOutput("MCP polling Collaborator interactions${payloadId?.let { " for payload: $it" } ?: ""}")

            val interactions = if (payloadId != null) {
                collaboratorClient.getInteractions(InteractionFilter.interactionIdFilter(payloadId))
            } else {
                collaboratorClient.getAllInteractions()
            }

            if (interactions.isEmpty()) {
                "No interactions detected"
            } else {
                interactions.joinToString("\n\n") {
                    Json.encodeToString(it.toSerializableForm())
                }
            }
        }
    }

    mcpPaginatedTool<GetProxyHttpHistory>("Displays proxy HTTP history items with FULL request and response bodies (can be very large). PREFER list_proxy_http_history for a compact index, then get_proxy_http_history_by_index for the items you need. If you use this, keep count small.") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("HTTP history access denied by Burp Suite")
        }

        api.proxy().history().orderedBy(newestFirst).asSequence().map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm()), config.maxItemLength) }
    }

    mcpPaginatedTool<GetProxyHttpHistoryRegex>("Displays items matching a specified regex within the proxy HTTP history") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("HTTP history access denied by Burp Suite")
        }

        val compiledRegex = Pattern.compile(regex)
        api.proxy().history { it.contains(compiledRegex) }.orderedBy(newestFirst).asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm()), config.maxItemLength) }
    }

    mcpPaginatedTool<GetOrganizerItems>("Displays Organizer items with FULL request and response bodies (can be very large). PREFER list_organizer_items for a compact index, then get_organizer_items_by_id for the items you need. If you use this, keep count small.") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.ORGANIZER, config, api, "Organizer")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("Organizer access denied by Burp Suite")
        }

        api.organizer().items().orderedBy(newestFirst).asSequence().map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm()), config.maxItemLength) }
    }

    mcpPaginatedTool<GetOrganizerItemsRegex>("Displays items matching a specified regex within the Organizer tab") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.ORGANIZER, config, api, "Organizer")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("Organizer access denied by Burp Suite")
        }

        val compiledRegex = Pattern.compile(regex)
        api.organizer().items { it.contains(compiledRegex) }.orderedBy(newestFirst).asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm()), config.maxItemLength) }
    }

    mcpPaginatedTool<ListOrganizerItems>("Lists Organizer items as a compact index: id, method, host, path, HTTP status code, organizer status, notes and request/response sizes, WITHOUT the request/response bodies. Use this first to see every item, then fetch the full request/response of the ones you need with get_organizer_items_by_id. Set newestFirst=true to list the most recently added items first. The 'id' is the same id accepted by get_organizer_items_by_id.") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.ORGANIZER, config, api, "Organizer")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("Organizer access denied by Burp Suite")
        }

        val items = api.organizer().items()
        val ordered = if (newestFirst == true) items.reversed() else items
        ordered.asSequence().map { Json.encodeToString(it.toSummaryForm()) }
    }

    mcpTool<GetOrganizerItemsById>("Returns the full Organizer items (request, response, notes) for the given id(s). Get the ids from list_organizer_items.") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.ORGANIZER, config, api, "Organizer")
        }
        if (!allowed) {
            return@mcpTool "Organizer access denied by Burp Suite"
        }

        val wanted = ids.toSet()
        val items = api.organizer().items().filter { it.id() in wanted }
        if (items.isEmpty()) {
            "No Organizer items match id(s): $ids"
        } else {
            items.joinToString(separator = "\n\n") {
                truncateIfNeeded(Json.encodeToString(it.toSerializableForm()), config.maxItemLength)
            }
        }
    }

    mcpPaginatedTool<GetSiteMap>("Lists site map entries as a compact index (method, host, path, HTTP status code, response size), optionally under a URL prefix, WITHOUT bodies. Use this to review the discovered attack surface.") {
        val items = if (prefix.isNullOrBlank()) {
            api.siteMap().requestResponses()
        } else {
            api.siteMap().requestResponses(SiteMapFilter.prefixFilter(prefix))
        }
        items.asSequence().map { Json.encodeToString(it.toSiteMapSummary()) }
    }

    mcpTool<SendToOrganizer>("Sends an HTTP request and its live response to Burp's Organizer, optionally with a note. Use this to save interesting requests for later analysis or reporting.") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.ORGANIZER, config, api, "Organizer")
        }
        if (!allowed) {
            return@mcpTool "Organizer access denied by Burp Suite"
        }

        val allowedHttp = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(targetHostname, targetPort, config, content, api)
        }
        if (!allowedHttp) {
            api.logging().logToOutput("MCP send_to_organizer denied: $targetHostname:$targetPort")
            return@mcpTool "Send HTTP request denied by Burp Suite"
        }

        val request = HttpRequest.httpRequest(toMontoyaService(), normalizeHttpContent(content))
        val requestResponse = api.http().sendRequest(request)
        val annotated = if (notes != null) {
            requestResponse.withAnnotations(Annotations.annotations(notes))
        } else {
            requestResponse
        }
        api.organizer().sendToOrganizer(annotated)

        val noteSuffix = if (notes != null) " with note" else ""
        if (requestResponse.response() == null) {
            "Sent request to Organizer$noteSuffix (no response received)"
        } else {
            "Sent to Organizer$noteSuffix"
        }
    }

    mcpTool<SetOrganizerItemNotes>("Sets the notes on an Organizer item, identified by the id from list_organizer_items. Useful to tag items (pseudo-collections) or record findings.") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.ORGANIZER, config, api, "Organizer")
        }
        if (!allowed) {
            return@mcpTool "Organizer access denied by Burp Suite"
        }

        val item = api.organizer().items().firstOrNull { it.id() == id }
            ?: return@mcpTool "No Organizer item with id $id"
        item.annotations().setNotes(notes)
        "Notes updated for Organizer item $id"
    }

    mcpTool<SetOrganizerItemHighlight>("Sets the highlight color of an Organizer item (id from list_organizer_items). Colors: RED, ORANGE, YELLOW, GREEN, CYAN, BLUE, PINK, MAGENTA, GRAY, NONE.") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.ORGANIZER, config, api, "Organizer")
        }
        if (!allowed) {
            return@mcpTool "Organizer access denied by Burp Suite"
        }

        val item = api.organizer().items().firstOrNull { it.id() == id }
            ?: return@mcpTool "No Organizer item with id $id"
        val color = try {
            HighlightColor.valueOf(colorName.trim().uppercase())
        } catch (e: Exception) {
            return@mcpTool "Invalid color: $colorName"
        }
        item.annotations().setHighlightColor(color)
        "Highlight updated for Organizer item $id"
    }

    mcpPaginatedTool<ListProxyHttpHistory>("Lists proxy HTTP history as a compact index (index, method, host, path, HTTP status code, size, notes), optionally filtered by host substring, WITHOUT bodies. Order is chronological (index 0 = oldest). Set newestFirst=true to get the most recent first — e.g. newestFirst=true, count=10, offset=0 returns the last 10 requests. 'index' is the absolute position in the history; pass it to get_proxy_http_history_by_index for the full request/response.") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("HTTP history access denied by Burp Suite")
        }

        val indexed = api.proxy().history().withIndex().let { iv ->
            if (newestFirst == true) iv.reversed() else iv.toList()
        }
        val filtered = if (hostFilter.isNullOrBlank()) {
            indexed.asSequence()
        } else {
            indexed.asSequence().filter { (_, rr) ->
                rr.request()?.httpService()?.host()?.contains(hostFilter, ignoreCase = true) == true
            }
        }
        filtered.map { (idx, rr) -> Json.encodeToString(rr.toHistorySummary(idx)) }
    }

    mcpTool<GetProxyHttpHistoryByIndex>("Returns full proxy HTTP history items (request, response, notes) for the given indices, as listed by list_proxy_http_history.") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) {
            return@mcpTool "HTTP history access denied by Burp Suite"
        }

        val history = api.proxy().history()
        val items = indices.mapNotNull { history.getOrNull(it) }
        if (items.isEmpty()) {
            "No history items at indices: $indices"
        } else {
            items.joinToString(separator = "\n\n") {
                truncateIfNeeded(Json.encodeToString(it.toSerializableForm()), config.maxItemLength)
            }
        }
    }

    mcpPaginatedTool<GetProxyWebsocketHistory>("Displays proxy WebSocket messages with full payloads. Keep count small to avoid large output.") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.WEBSOCKET_HISTORY, config, api, "WebSocket history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("WebSocket history access denied by Burp Suite")
        }

        api.proxy().webSocketHistory().orderedBy(newestFirst).asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm()), config.maxItemLength) }
    }

    mcpPaginatedTool<GetProxyWebsocketHistoryRegex>("Displays items matching a specified regex within the proxy WebSocket history") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.WEBSOCKET_HISTORY, config, api, "WebSocket history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("WebSocket history access denied by Burp Suite")
        }

        val compiledRegex = Pattern.compile(regex)
        api.proxy().webSocketHistory { it.contains(compiledRegex) }.orderedBy(newestFirst).asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm()), config.maxItemLength) }
    }

    mcpPaginatedTool<GetRepeaterTraffic>("Lists HTTP traffic captured from Burp Repeater while this extension has been loaded, as a compact index (messageId, method, host, path, HTTP status, sizes) WITHOUT bodies. NOTE: Burp's API cannot read existing Repeater tabs, so only Sends made after the extension was loaded are captured (re-Send an old tab to capture it). Use get_captured_exchange_by_id for the full request/response.") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "Repeater traffic")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("Repeater traffic access denied by Burp Suite")
        }

        TrafficStore.summaries(ToolType.REPEATER, newestFirst == true).map { Json.encodeToString(it) }
    }

    mcpPaginatedTool<GetIntruderTraffic>("Lists HTTP traffic captured from Burp Intruder attacks run while this extension has been loaded, as a compact index (messageId, method, host, path, HTTP status, sizes) WITHOUT bodies. Use get_captured_exchange_by_id for the full request/response of specific ids.") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "Intruder traffic")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("Intruder traffic access denied by Burp Suite")
        }

        TrafficStore.summaries(ToolType.INTRUDER, newestFirst == true).map { Json.encodeToString(it) }
    }

    mcpTool<GetCapturedExchangeById>("Returns the full request/response of captured Repeater/Intruder exchanges by their messageId (from get_repeater_traffic / get_intruder_traffic).") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "captured traffic")
        }
        if (!allowed) {
            return@mcpTool "Captured traffic access denied by Burp Suite"
        }

        val matches = TrafficStore.byIds(ids.toSet())
        if (matches.isEmpty()) {
            "No captured exchanges with messageId(s): $ids"
        } else {
            matches.joinToString(separator = "\n\n") {
                truncateIfNeeded(
                    Json.encodeToString(CapturedExchangeDetail(it.messageId, it.tool, it.request, it.response)),
                    config.maxItemLength
                )
            }
        }
    }

    mcpTool<SetTaskExecutionEngineState>("Sets the state of Burp's task execution engine (paused or unpaused)") {
        api.burpSuite().taskExecutionEngine().state = if (running) RUNNING else PAUSED

        "Task execution engine is now ${if (running) "running" else "paused"}"
    }

    mcpTool<SetProxyInterceptState>("Enables or disables Burp Proxy Intercept") {
        if (intercepting) {
            api.proxy().enableIntercept()
        } else {
            api.proxy().disableIntercept()
        }

        "Intercept has been ${if (intercepting) "enabled" else "disabled"}"
    }

    mcpTool("get_active_editor_contents", "Outputs the contents of the user's active message editor") {
        getActiveEditor(api)?.text ?: "<No active editor>"
    }

    mcpTool<SetActiveEditorContents>("Sets the content of the user's active message editor") {
        val editor = getActiveEditor(api) ?: return@mcpTool "<No active editor>"

        if (!editor.isEditable) {
            return@mcpTool "<Current editor is not editable>"
        }

        editor.text = text

        "Editor text has been set"
    }
}

fun getActiveEditor(api: MontoyaApi): JTextArea? {
    val frame = api.userInterface().swingUtils().suiteFrame()

    val focusManager = KeyboardFocusManager.getCurrentKeyboardFocusManager()
    val permanentFocusOwner = focusManager.permanentFocusOwner

    val isInBurpWindow = generateSequence(permanentFocusOwner) { it.parent }.any { it == frame }

    return if (isInBurpWindow && permanentFocusOwner is JTextArea) {
        permanentFocusOwner
    } else {
        null
    }
}

interface HttpServiceParams {
    val targetHostname: String
    val targetPort: Int
    val usesHttps: Boolean

    fun toMontoyaService(): HttpService = HttpService.httpService(targetHostname, targetPort, usesHttps)
}

@Serializable
data class SendHttp1Request(
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class SendHttp2Request(
    val pseudoHeaders: Map<String, String>,
    val headers: Map<String, String>,
    val requestBody: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class CreateRepeaterTab(
    val tabName: String?,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class CreateRepeaterTabHttp2(
    val tabName: String?,
    val pseudoHeaders: Map<String, String>,
    val headers: Map<String, String>,
    val requestBody: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class SendToIntruder(
    val tabName: String?,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class UrlEncode(val content: String)

@Serializable
data class UrlDecode(val content: String)

@Serializable
data class Base64Encode(val content: String)

@Serializable
data class Base64Decode(val content: String)

@Serializable
data class GenerateRandomString(val length: Int, val characterSet: String)

@Serializable
data class SetProjectOptions(val json: String)

@Serializable
data class SetUserOptions(val json: String)

@Serializable
data class SetTaskExecutionEngineState(val running: Boolean)

@Serializable
data class SetProxyInterceptState(val intercepting: Boolean)

@Serializable
data class SetActiveEditorContents(val text: String)

@Serializable
data class GetScannerIssues(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyHttpHistory(val newestFirst: Boolean? = false, override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyHttpHistoryRegex(val regex: String, val newestFirst: Boolean? = false, override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetOrganizerItems(val newestFirst: Boolean? = false, override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetOrganizerItemsRegex(val regex: String, val newestFirst: Boolean? = false, override val count: Int, override val offset: Int) : Paginated

@Serializable
data class ListOrganizerItems(val newestFirst: Boolean? = false, override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetOrganizerItemsById(val ids: List<Int>)

@Serializable
data class GetSiteMap(val prefix: String? = null, override val count: Int, override val offset: Int) : Paginated

@Serializable
data class SendToOrganizer(
    val content: String,
    val notes: String? = null,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class SetOrganizerItemNotes(val id: Int, val notes: String)

@Serializable
data class SetOrganizerItemHighlight(val id: Int, val colorName: String)

@Serializable
data class ListProxyHttpHistory(
    val hostFilter: String? = null,
    val newestFirst: Boolean? = false,
    override val count: Int,
    override val offset: Int
) : Paginated

@Serializable
data class GetProxyHttpHistoryByIndex(val indices: List<Int>)

@Serializable
data class GetRepeaterTraffic(val newestFirst: Boolean? = false, override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetIntruderTraffic(val newestFirst: Boolean? = false, override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetCapturedExchangeById(val ids: List<Int>)

@Serializable
data class GetProxyWebsocketHistory(val newestFirst: Boolean? = false, override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyWebsocketHistoryRegex(val regex: String, val newestFirst: Boolean? = false, override val count: Int, override val offset: Int) :
    Paginated

@Serializable
data class GenerateCollaboratorPayload(
    val customData: String? = null
)

@Serializable
data class GetCollaboratorInteractions(
    val payloadId: String? = null
)
