package net.portswigger.mcp.tools

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Regression test for https://github.com/PortSwigger/mcp-server/issues/28 — some MCP clients send
 * integer arguments as JSON floats (e.g. count = 10.0). coerceWholeNumberFloats must turn those
 * into integers while leaving everything else (fractions, strings, booleans) untouched.
 */
class McpToolArgumentCoercionTest {

    @Test
    fun `whole-number floats are coerced to integers, everything else is left untouched`() {
        val input = Json.parseToJsonElement(
            """{"count":10.0,"offset":0.0,"neg":-4.0,"ratio":1.5,"asString":"10.0","ids":[1.0,2.0,3.5],"flag":true}"""
        )

        val out = coerceWholeNumberFloats(input).jsonObject

        // whole-number floats -> integers
        assertEquals("10", out.getValue("count").jsonPrimitive.content)
        assertEquals("0", out.getValue("offset").jsonPrimitive.content)
        assertEquals("-4", out.getValue("neg").jsonPrimitive.content)

        // fractions stay as-is
        assertEquals("1.5", out.getValue("ratio").jsonPrimitive.content)

        // quoted strings are never touched
        assertTrue(out.getValue("asString").jsonPrimitive.isString)
        assertEquals("10.0", out.getValue("asString").jsonPrimitive.content)

        // arrays are processed element by element (1.0/2.0 -> 1/2, 3.5 kept)
        assertEquals(listOf("1", "2", "3.5"), out.getValue("ids").jsonArray.map { it.jsonPrimitive.content })

        // booleans are untouched
        assertEquals("true", out.getValue("flag").jsonPrimitive.content)
    }

    @Test
    fun `an oversized whole-number float is left as-is instead of throwing`() {
        val input = Json.parseToJsonElement("""{"big":100000000000000000000.0}""")
        val out = coerceWholeNumberFloats(input).jsonObject
        // Cannot fit in Long -> keep the original token rather than crashing.
        assertEquals("100000000000000000000.0", out.getValue("big").jsonPrimitive.content)
    }
}
