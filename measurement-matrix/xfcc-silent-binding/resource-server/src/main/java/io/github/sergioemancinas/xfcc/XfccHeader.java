package io.github.sergioemancinas.xfcc;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Parser for Envoy's {@code x-forwarded-client-cert} header, text format.
 *
 * <p>Format, from Envoy's HTTP connection manager documentation and from
 * {@code source/common/http/conn_manager_utility.cc}
 * ({@code ConnectionManagerUtility::mutateXfccRequestHeader}):
 *
 * <pre>
 *   XFCC      := element *( "," element )
 *   element   := kv *( ";" kv )
 *   kv        := key "=" value
 *   value     := token / quoted-string
 * </pre>
 *
 * Envoy emits the keys {@code By}, {@code Hash}, {@code Cert}, {@code Chain},
 * {@code Subject}, {@code URI} and {@code DNS}. {@code Cert} and {@code Chain} are
 * always double-quoted and always percent-encoded; {@code Subject} is always
 * double-quoted. Envoy replaces a literal double quote inside a value with
 * {@code \"}.
 *
 * <p>There is no RFC for any of this. XFCC is a vendor convention. RFC 8705
 * section 6.5 explicitly leaves proxy-to-application propagation of client
 * certificate metadata out of scope, which is why this class has to exist at all.
 */
final class XfccHeader {

	private XfccHeader() {
	}

	/**
	 * Parse one XFCC header value into its elements, in wire order. Each element is a
	 * map from key to raw (unquoted, unescaped) value. Keys are compared
	 * case-insensitively by {@link #firstValue}; the map preserves the wire casing.
	 *
	 * <p>The parser is tolerant: a malformed element yields whatever key/value pairs could
	 * be read rather than an exception. The tolerance is not the defect under study. The
	 * defect under study is what the caller does with a {@code Cert} value it cannot turn
	 * into a certificate.
	 */
	static List<Map<String, String>> parse(String header) {
		List<Map<String, String>> elements = new ArrayList<>();
		Map<String, String> current = new LinkedHashMap<>();
		StringBuilder key = new StringBuilder();
		StringBuilder value = new StringBuilder();
		boolean inValue = false;
		boolean quoted = false;
		boolean escaped = false;

		for (int i = 0; i < header.length(); i++) {
			char c = header.charAt(i);

			if (inValue && quoted) {
				if (escaped) {
					value.append(c);
					escaped = false;
				}
				else if (c == '\\') {
					escaped = true;
				}
				else if (c == '"') {
					quoted = false;
				}
				else {
					value.append(c);
				}
				continue;
			}

			switch (c) {
				case '=' -> {
					if (inValue) {
						value.append(c);
					}
					else {
						inValue = true;
					}
				}
				case '"' -> {
					if (inValue && value.isEmpty()) {
						quoted = true;
					}
					else if (inValue) {
						value.append(c);
					}
				}
				case ';' -> {
					flush(current, key, value);
					inValue = false;
				}
				case ',' -> {
					flush(current, key, value);
					inValue = false;
					if (!current.isEmpty()) {
						elements.add(current);
						current = new LinkedHashMap<>();
					}
				}
				default -> {
					if (inValue) {
						value.append(c);
					}
					else {
						key.append(c);
					}
				}
			}
		}
		flush(current, key, value);
		if (!current.isEmpty()) {
			elements.add(current);
		}
		return elements;
	}

	private static void flush(Map<String, String> into, StringBuilder key, StringBuilder value) {
		String k = key.toString().trim();
		if (!k.isEmpty()) {
			into.put(k, value.toString());
		}
		key.setLength(0);
		value.setLength(0);
	}

	/**
	 * First value for {@code key}, searching elements in wire order.
	 *
	 * <p>Wire order is the order the request traversed the proxies, so element 0 is the
	 * outermost hop. With a single terminating proxy there is exactly one element. A
	 * multi-hop deployment would need a policy about which element to trust; that
	 * question is out of scope here and is called out in the README.
	 */
	static String firstValue(List<Map<String, String>> elements, String key) {
		for (Map<String, String> element : elements) {
			for (Map.Entry<String, String> entry : element.entrySet()) {
				if (entry.getKey().equalsIgnoreCase(key)) {
					return entry.getValue();
				}
			}
		}
		return null;
	}

	/**
	 * Percent-decode a value Envoy produced with
	 * {@code Http::Utility::PercentEncoding::urlEncode}.
	 *
	 * <p>That function percent-encodes every octet except {@code ALPHA}, {@code DIGIT},
	 * {@code *}, {@code -}, {@code .} and {@code _}, using uppercase hex, and encodes
	 * space as {@code %20} rather than {@code +}.
	 *
	 * <p>{@link java.net.URLDecoder#decode} happens to produce the same result on Envoy
	 * output, because Envoy never emits a bare {@code +}. It is not used here because
	 * that equivalence is an accident of Envoy's encoder, not a property of the
	 * {@code application/x-www-form-urlencoded} decoder.
	 */
	static String percentDecode(String value) {
		StringBuilder out = new StringBuilder(value.length());
		for (int i = 0; i < value.length(); i++) {
			char c = value.charAt(i);
			if (c == '%' && i + 2 < value.length()) {
				int hi = Character.digit(value.charAt(i + 1), 16);
				int lo = Character.digit(value.charAt(i + 2), 16);
				if (hi >= 0 && lo >= 0) {
					out.append((char) ((hi << 4) + lo));
					i += 2;
					continue;
				}
			}
			out.append(c);
		}
		return out.toString();
	}

}
