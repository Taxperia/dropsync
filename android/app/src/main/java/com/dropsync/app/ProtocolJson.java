package com.dropsync.app;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

/** Canonical bytes shared with src/utils.js, independent of Android's JSON escaping. */
final class ProtocolJson {
    private ProtocolJson() { }

    static String canonical(Object value) throws Exception {
        if (value == null || value == JSONObject.NULL) return "null";
        if (value instanceof JSONObject) {
            JSONObject object = (JSONObject) value;
            List<String> keys = new ArrayList<>();
            Iterator<String> iterator = object.keys();
            while (iterator.hasNext()) keys.add(iterator.next());
            Collections.sort(keys);
            StringBuilder result = new StringBuilder("{");
            for (int index = 0; index < keys.size(); index++) {
                if (index > 0) result.append(',');
                String key = keys.get(index);
                result.append(quote(key)).append(':').append(canonical(object.get(key)));
            }
            return result.append('}').toString();
        }
        if (value instanceof JSONArray) {
            JSONArray array = (JSONArray) value;
            StringBuilder result = new StringBuilder("[");
            for (int index = 0; index < array.length(); index++) {
                if (index > 0) result.append(',');
                result.append(canonical(array.get(index)));
            }
            return result.append(']').toString();
        }
        if (value instanceof String) return quote((String) value);
        if (value instanceof Boolean) return Boolean.TRUE.equals(value) ? "true" : "false";
        return JSONObject.numberToString((Number) value);
    }

    private static String quote(String value) {
        // JSONObject.quote escapes '/' on Android; JSON.stringify does not.
        // Public-key PEM bodies can contain '/', so that difference breaks signatures.
        StringBuilder result = new StringBuilder("\"");
        for (int index = 0; index < value.length(); index++) {
            char c = value.charAt(index);
            switch (c) {
                case '"': result.append("\\\""); break;
                case '\\': result.append("\\\\"); break;
                case '\b': result.append("\\b"); break;
                case '\f': result.append("\\f"); break;
                case '\n': result.append("\\n"); break;
                case '\r': result.append("\\r"); break;
                case '\t': result.append("\\t"); break;
                default:
                    boolean unpaired = Character.isHighSurrogate(c)
                            ? index + 1 >= value.length() || !Character.isLowSurrogate(value.charAt(index + 1))
                            : Character.isLowSurrogate(c) && (index == 0 || !Character.isHighSurrogate(value.charAt(index - 1)));
                    if (c < 0x20 || unpaired) result.append(String.format(java.util.Locale.ROOT, "\\u%04x", (int) c));
                    else result.append(c);
            }
        }
        return result.append('"').toString();
    }
}
