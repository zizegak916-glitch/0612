package com.fool.ipbatch;

import java.io.ByteArrayOutputStream;

final class Base64Compat {
    private Base64Compat() {}

    static byte[] decode(String input) throws Exception {
        String value = input == null ? "" : input.replace('-', '+').replace('_', '/').replaceAll("\\s", "");
        while (value.length() % 4 != 0) value += "=";
        ByteArrayOutputStream out = new ByteArrayOutputStream(value.length() * 3 / 4);
        for (int i = 0; i < value.length(); i += 4) {
            int a = code(value.charAt(i));
            int b = code(value.charAt(i + 1));
            int c = value.charAt(i + 2) == '=' ? -1 : code(value.charAt(i + 2));
            int d = value.charAt(i + 3) == '=' ? -1 : code(value.charAt(i + 3));
            if (a < 0 || b < 0 || c < -1 || d < -1) throw new Exception("invalid base64");
            out.write((a << 2) | (b >> 4));
            if (c >= 0) out.write(((b & 15) << 4) | (c >> 2));
            if (d >= 0 && c >= 0) out.write(((c & 3) << 6) | d);
        }
        return out.toByteArray();
    }

    private static int code(char c) {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -2;
    }
}
