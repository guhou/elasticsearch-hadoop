package org.elasticsearch.hadoop.rest.commonshttp;

import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.util.regex.Pattern;


public class AwsSigner {

    private static SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMdd");
    private static SimpleDateFormat dateTimeFormat = new SimpleDateFormat("yyyyMMdd'T'HHmmss'Z'");

    static {
        dateTimeFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
    }

    private static byte[] EMPTY = new byte[]{};


    public static String formatDateTime(Date date) {
        return dateTimeFormat.format(date);
    }

    private static byte[] hmac(String data, byte[] key) throws Exception {
        String algorithm = "HmacSHA256";
        Mac mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(key, algorithm));
        return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] getSignatureKey(String awsSecretKey, String dateStamp, String regionName, String serviceName) throws Exception {
        byte[] kSecret = ("AWS4" + awsSecretKey).getBytes(StandardCharsets.UTF_8);
        byte[] kDate = hmac(dateStamp, kSecret);
        byte[] kRegion = hmac(regionName, kDate);
        byte[] kService = hmac(serviceName, kRegion);
        byte[] kSigning = hmac("aws4_request", kService);
        return kSigning;
    }

    private static byte[] hashSHA256(byte[] payload) throws NoSuchAlgorithmException {
        final MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(payload);
        return md.digest();
    }

    private static String getCanonicalQueryString(SortedMap queryMap) throws UnsupportedEncodingException {
        ArrayList<String> list = new ArrayList<String>();
        for (String key : queryMap.keys()) {
            for (String val : queryMap.get(key)) {
                String k = URLEncoder.encode(key, "UTF-8")
                        .replace("+", "%20")
                        .replace("*", "%2A")
                        .replace("%7E", "~");
                String v = URLEncoder.encode(val, "UTF-8")
                        .replace("+", "%20")
                        .replace("*", "%2A")
                        .replace("%7E", "~");
                list.add(k + "=" + v);
            }
        }
        return U.stringJoin("&", list);
    }

    private static SortedMap createSortedMap(List<AbstractMap.SimpleEntry<String, String>> headers, Boolean keysToLower) {
        SortedMap sortedMap = new SortedMap();
        for (Map.Entry<String, String> e : headers) {
            String k;
            if (keysToLower) k = e.getKey().toLowerCase();
            else k = e.getKey();
            String v = e.getValue();
            v = v != null ? v.trim() : "";
            sortedMap.put(k, v);
        }
        return sortedMap;
    }

    private static String getCanonicalHeaders(SortedMap sortedMap) {
        StringBuilder acc = new StringBuilder();
        for (String key : sortedMap.keys()) {
            acc.append(key);
            acc.append(":" + U.stringJoin(",", sortedMap.get(key)) + "\n");
        }
        return acc.toString();
    }

    private static String getSignedHeaders(SortedMap sortedMap) {
        return U.stringJoin(";", sortedMap.keys()).toLowerCase();
    }

    private static String getCanonicalRequest(
            String method,
            String uri,
            List<AbstractMap.SimpleEntry<String, String>> headers,
            List<AbstractMap.SimpleEntry<String, String>> queryParams,
            byte[] requestPayload) throws NoSuchAlgorithmException, UnsupportedEncodingException {

        SortedMap headerMap = createSortedMap(headers, true);
        SortedMap queryMap = createSortedMap(queryParams, false);
        if (requestPayload == null) requestPayload = EMPTY;
        String canonical = method + "\n" +
                uri + "\n" +
                getCanonicalQueryString(queryMap) + "\n" +
                getCanonicalHeaders(headerMap) + "\n" +
                getSignedHeaders(headerMap) + "\n" +
                U.base16(hashSHA256(requestPayload));       
        return canonical;

    }

    private static String getStringToSign(
            Date date,
            String region,
            String service,
            String method,
            String uri,
            List<AbstractMap.SimpleEntry<String, String>> headers,
            List<AbstractMap.SimpleEntry<String, String>> queryParams,
            byte[] payload) throws NoSuchAlgorithmException, UnsupportedEncodingException {

        return "AWS4-HMAC-SHA256" + "\n" +
                dateTimeFormat.format(date) + "\n" +
                dateFormat.format(date) + "/" + region + "/" + service + "/aws4_request" + "\n" +
                U.base16(hashSHA256(getCanonicalRequest(method, uri, headers, queryParams, payload).getBytes(StandardCharsets.UTF_8)));
    }

    // Add Authorization:
    public static String getAuthHeader(
            String awsAccessKey,
            String awsSecretKey,
            Date date,
            String region,
            String service,
            String method,
            String path,
            List<AbstractMap.SimpleEntry<String, String>> headers,
            List<AbstractMap.SimpleEntry<String, String>> queryParams,
            byte[] payload) throws Exception {

        String _date = dateFormat.format(date);
        String stringToSign = getStringToSign(date, region, service, method, U.absolute(path), headers, queryParams, payload);
        String signature = U.encodeHex(hmac(stringToSign, getSignatureKey(awsSecretKey, _date, region, service)));
        return "AWS4-HMAC-SHA256 " +
                "Credential=" +
                awsAccessKey + U.stringJoin("/", Arrays.asList(new String[]{"", _date, region, service, "aws4_request"})) + ", " +
                "SignedHeaders=" + getSignedHeaders(createSortedMap(headers, true)) + ", " +
                "Signature=" + signature;
    }

    public static ArrayList<AbstractMap.SimpleEntry<String, String>> parseQuery(String query) {
        return Query.parse(query);
    }

    public static void main(String[] args) throws Exception {
        ArrayList<AbstractMap.SimpleEntry<String, String>> headers = new ArrayList<AbstractMap.SimpleEntry<String, String>>();
        ArrayList<AbstractMap.SimpleEntry<String, String>> queryParams = new ArrayList<AbstractMap.SimpleEntry<String, String>>();
        queryParams.add(new AbstractMap.SimpleEntry<String, String>("foo", "Zoo"));
        queryParams.add(new AbstractMap.SimpleEntry<String, String>("foo", "aha"));
        headers.add(new AbstractMap.SimpleEntry<String, String>("Host", "es.amazonaws.com"));
        String awsAccessKey = "ACCESS_KEY";
        String awsSecretKey = "SECRET_KEY";
        Date date = Calendar.getInstance().getTime();
        String region = "eu-west-1";
        String service = "es";
        String method = "GET";
        String uri = "/";
        byte[] payload = EMPTY;


        System.out.println("********* AUTH_HEADER************");
        System.out.println(getAuthHeader(awsAccessKey, awsSecretKey, date, region, service, method, uri, headers, queryParams, payload));
        System.out.println("********* STRING_TO_SIGN ************");
        System.out.println(getStringToSign(date, region, service, method, uri, headers, queryParams, payload));
        System.out.println("********* CANONICAL_STRING ************");
        System.out.println(getCanonicalRequest(method, uri, headers, queryParams, payload));
    }
}

class U {

    private final static char[] DIGITS_LOWER = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    public static String absolute(String relative) throws MalformedURLException {
        Stack<String> stack = new Stack<String>();
        String[] parts = relative.split("/");
        try {
            for (String p : parts) {
                if (p.equals("..")) {
                    stack.pop();
                } else if (p.equals(".")) {
                    continue;
                } else if (p.isEmpty() && !stack.isEmpty() && stack.peek().isEmpty()) {
                    continue;
                } else {
                    stack.push(p);
                }
            }
        } catch (EmptyStackException e) {
            throw new MalformedURLException();
        }
        String result = stringJoin("/", stack);
        result = prepend(result);
        if (relative.endsWith("/")) result = append(result);
        return result;
    }

    private static String prepend(String s) {
        if (!s.startsWith("/")) return "/" + s;
        return s;
    }

    private static String append(String s) {
        if (!s.endsWith("/")) return s + "/";
        return s;
    }


    public static String encodeHex(byte[] data) {
        return String.valueOf(encodeHex(data, DIGITS_LOWER));
    }

    public static String base16(byte[] data) {
        StringBuilder hexBuffer = new StringBuilder(data.length * 2);
        for (byte aData : data) {
            hexBuffer.append(DIGITS_LOWER[(aData >> (4)) & 0xF]);
            hexBuffer.append(DIGITS_LOWER[(aData) & 0xF]);
        }
        return hexBuffer.toString();
    }

    public static String stringJoin(String sep, Iterable<String> iterable) {
        StringBuilder acc = new StringBuilder();
        Iterator<String> it = iterable.iterator();
        if (it.hasNext()) {
            acc.append(it.next());
        }
        while (it.hasNext()) {
            acc.append(sep + it.next());
        }
        return acc.toString();
    }

    // Stolen from apache commons
    public static char[] encodeHex(byte[] data, char[] toDigits) {
        final int l = data.length;
        final char[] out = new char[l << 1];
        // two characters form the hex value.
        for (int i = 0, j = 0; i < l; i++) {
            out[j++] = toDigits[(0xF0 & data[i]) >>> 4];
            out[j++] = toDigits[0x0F & data[i]];
        }
        return out;
    }
}

class Query {
    private static boolean isEnd(String q, int i) {
        if (q.isEmpty()) return true;
        if (i >= q.length()) return true;
        return false;
    }

    private static boolean nextMatches(String q, int i, String m) {
        if (isEnd(q, i + 1)) return false;
        return ("" + q.charAt(i + 1)).matches(m);
    }

    private static int parseString(String q, int i, String stopWhen) {
        if (i > q.length()) return -1;
        while (!isEnd(q, i) && !(nextMatches(q, i, stopWhen))) {
            i += 1;
        }
        return Math.min(i, q.length());
    }

    private static int parseKey(String q, int i) {
        return parseString(q, i, Pattern.quote("="));
    }

    private static int parseValue(String q, int i) {
        return parseString(q, i, Pattern.quote("&"));
    }

    // fails on post-vanilla-query-nonunreserved
    public static ArrayList<AbstractMap.SimpleEntry<String, String>> parse(String query) {
        int spaceIndex = query.indexOf(' ');
        if (spaceIndex > 0) {
            query = query.substring(0, spaceIndex);
        }
        ArrayList<AbstractMap.SimpleEntry<String, String>> list = new ArrayList<AbstractMap.SimpleEntry<String, String>>();
        int len = query.length();
        if (len == 0) return list;
        String k, v;
        int i = 0;
        int ni;
        for (; ; ) {
            ni = parseKey(query, i);
            if (ni == -1) break;
            k = query.substring(i, Math.min(len, ni + 1));
            i = ni + 2;
            ni = parseValue(query, i);
            if (ni == -1) v = "";
            else if (ni == len) v = query.substring(i);
            else v = query.substring(i, Math.min(len, ni + 1));
            list.add(new AbstractMap.SimpleEntry<String, String>(k, v));
            if (ni == -1) break;
            i = ni + 2;
        }
        return list;
    }
}

class SortedMap {
    private TreeMap<String, ArrayList<String>> storage = new TreeMap<String, ArrayList<String>>();

    public String put(String key, String value) {
        ArrayList<String> list = storage.get(key);
        if (list == null) {
            list = new ArrayList<String>();
            storage.put(key, list);
        }
        list.add(value);
        return value;
    }

    public Iterable<String> get(String key) {
        ArrayList<String> list = storage.get(key);
        Collections.sort(list);
        return list;
    }

    public Iterable<String> keys() {
        return storage.keySet();
    }
}
