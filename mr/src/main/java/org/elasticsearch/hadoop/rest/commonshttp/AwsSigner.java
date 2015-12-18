package org.elasticsearch.hadoop.rest.commonshttp;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;


public class AwsSigner {

    private static SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMdd");
    private static SimpleDateFormat dateTimeFormat = new SimpleDateFormat("yyyyMMdd'T'HHmmss'Z'");

    private final static char[] DIGITS_LOWER = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    static {
        dateTimeFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
    }

    private static byte[] EMPTY = new byte[]{};

    private static String encodeHex(byte[] data) {
        return String.valueOf(encodeHex(data, DIGITS_LOWER));
    }


    public static String formatDateTime(Date date) {
        return dateTimeFormat.format(date);
    }

    public static String formatDate(Date date) {
        return dateFormat.format(date);
    }

    // Stolen from apache commons
    private static char[] encodeHex(byte[] data, char[] toDigits) {
        final int l = data.length;
        final char[] out = new char[l << 1];
        // two characters form the hex value.
        for (int i = 0, j = 0; i < l; i++) {
            out[j++] = toDigits[(0xF0 & data[i]) >>> 4];
            out[j++] = toDigits[0x0F & data[i]];
        }
        return out;
    }

    // http://stackoverflow.com/a/13592567
    public static ArrayList<AbstractMap.SimpleEntry<String, String>> splitQuery(String query) throws UnsupportedEncodingException {
        ArrayList<AbstractMap.SimpleEntry<String, String>> list = new ArrayList<AbstractMap.SimpleEntry<String, String>>();
        final String[] pairs = query.split("&");
        for (String pair : pairs) {
            int idx = pair.indexOf("=");
            String key = idx > 0 ? URLDecoder.decode(pair.substring(0, idx), "UTF-8") : pair;
            final String value = idx > 0 && pair.length() > idx + 1 ? URLDecoder.decode(pair.substring(idx + 1), "UTF-8") : null;
            list.add(new AbstractMap.SimpleEntry<String, String>(key, value));
        }
        return list;
    }

    private static String stringJoin(String sep, Iterable<String> iterable) {
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

    private static String getCanonicalQueryString(ArrayList<AbstractMap.SimpleEntry<String, String>> queryParams) {

        Collections.sort(queryParams, new Comparator<AbstractMap.SimpleEntry<String, String>>() {
            @Override
            public int compare(AbstractMap.SimpleEntry<String, String> o1, AbstractMap.SimpleEntry<String, String> o2) {
                return o1.getKey().compareTo(o2.getKey());
            }
        });
        ArrayList<String> query = new ArrayList<String>();
        for (Map.Entry<String, String> e : queryParams) {
            query.add(e.getKey() + "=" + e.getValue());
        }
        return stringJoin("&", query);
    }

    private static String getCanonicalHeaders(ArrayList<AbstractMap.SimpleEntry<String, String>> headers) {
        StringBuilder acc = new StringBuilder();
        for (Map.Entry<String, String> e : headers) {
            acc.append(e.getKey().toLowerCase());
            acc.append(":" + e.getValue().trim() + "\n");
        }
        return acc.toString();
    }

    private static String getSignedHeaders(ArrayList<AbstractMap.SimpleEntry<String, String>> headers) {
        ArrayList<String> keys = new ArrayList<String>();
        for (Map.Entry<String, String> e : headers) {
            keys.add(e.getKey());
        }
        return stringJoin(";", keys).toLowerCase();
    }

    private static String base16(byte[] data) {
        StringBuilder hexBuffer = new StringBuilder(data.length * 2);
        for (byte aData : data) {
            hexBuffer.append(DIGITS_LOWER[(aData >> (4)) & 0xF]);
            hexBuffer.append(DIGITS_LOWER[(aData) & 0xF]);
        }
        return hexBuffer.toString();
    }

    private static String getCanonicalRequest(
            String method,
            String uri,
            ArrayList<AbstractMap.SimpleEntry<String, String>> headers,
            ArrayList<AbstractMap.SimpleEntry<String, String>> queryParams,
            byte[] requestPayload) throws NoSuchAlgorithmException {

        if (requestPayload == null) requestPayload = EMPTY;
        return method + "\n" +
                uri + "\n" +
                getCanonicalQueryString(queryParams) + "\n" +
                getCanonicalHeaders(headers) + "\n" +
                getSignedHeaders(headers) + "\n" +
                base16(hashSHA256(requestPayload));

    }

    private static String getStringToSign(
            Date date,
            String region,
            String service,
            String method,
            String uri,
            ArrayList<AbstractMap.SimpleEntry<String, String>> headers,
            ArrayList<AbstractMap.SimpleEntry<String, String>> queryParams,
            byte[] payload) throws NoSuchAlgorithmException {

        return "AWS4-HMAC-SHA256" + "\n" +
                dateTimeFormat.format(date) + "\n" +
                dateFormat.format(date) + "/" + region + "/" + service + "/aws4_request" + "\n" +
                base16(hashSHA256(getCanonicalRequest(method, uri, headers, queryParams, payload).getBytes(StandardCharsets.UTF_8)));
    }


    // Add Authorization:
    public static String getAuthHeader(
            String awsAccessKey,
            String awsSecretKey,
            Date date,
            String region,
            String service,
            String method,
            String uri,
            ArrayList<AbstractMap.SimpleEntry<String, String>> headers,
            ArrayList<AbstractMap.SimpleEntry<String, String>> queryParams,
            byte[] payload) throws Exception {

        String _date = dateFormat.format(date);
        String _dateTime = dateTimeFormat.format(date);
        headers.add(new AbstractMap.SimpleEntry("X-Amz-Date", _dateTime));
        String stringToSign = getStringToSign(date, region, service, method, uri, headers, queryParams, payload);
        System.out.println(stringToSign);
        String signature = encodeHex(hmac(stringToSign, getSignatureKey(awsSecretKey, _date, region, service)));
        return "AWS4-HMAC-SHA256 " +
                "Credential=" +
                awsAccessKey + stringJoin("/", Arrays.asList(new String[]{"", _date, region, service, "aws4_request"})) + ", " +
                "SignedHeaders=" + getSignedHeaders(headers) + ", " +
                "Signature=" + signature;
    }

    public static void main(String[] args) throws Exception {
        ArrayList<AbstractMap.SimpleEntry<String, String>> headers = new ArrayList<AbstractMap.SimpleEntry<String, String>>();
        ArrayList<AbstractMap.SimpleEntry<String, String>> queryParams = new ArrayList<AbstractMap.SimpleEntry<String, String>>();
        queryParams.add(new AbstractMap.SimpleEntry("foo", "Zoo"));
        queryParams.add(new AbstractMap.SimpleEntry("foo", "aha"));
        headers.add(new AbstractMap.SimpleEntry("Host", "search-recommendation-auth-nssxzbi2fyds6z3gan2zeactci.eu-west-1.es.amazonaws.com"));
        String awsAccessKey = "ACCESS";
        String awsSecretKey = "SECRET";
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

