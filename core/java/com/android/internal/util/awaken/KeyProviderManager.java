/*
 * SPDX-FileCopyrightText: 2024 Paranoid Android
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.internal.util.awaken;

import android.app.ActivityThread;
import android.content.Context;
import android.provider.Settings;
import android.text.TextUtils;
import android.util.Log;
import android.util.Xml;

import org.json.JSONObject;
import org.xmlpull.v1.XmlPullParser;

import java.io.StringReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * Manager class for handling keybox providers.
 * @hide
 */
public final class KeyProviderManager {
    private static final String TAG = "KeyProviderManager";
    private static final int MAX_CERT_COUNT = 3;

    private static IKeyboxProvider instance = null;
    private static String lastKeyboxData = null;

    private KeyProviderManager() {}

    public static synchronized IKeyboxProvider getProvider() {
        Context context = DefaultKeyboxProvider.getApplicationContext();
        if (context == null) {
            return null;
        }

        String keyboxData = Settings.Secure.getString(
                context.getContentResolver(), Settings.Secure.KEYBOX_DATA);
                
        if (TextUtils.isEmpty(keyboxData)) return null;

        if (isSameData(lastKeyboxData, keyboxData)) {
            return instance;
        }

        instance = new DefaultKeyboxProvider(keyboxData);
        lastKeyboxData = keyboxData;
        return instance;
    }

    public static boolean isKeyboxAvailable() {
        IKeyboxProvider provider = getProvider();
        return provider != null && provider.hasKeybox();
    }

    private static boolean isSameData(String oldData, String newData) {
        return instance != null && TextUtils.equals(oldData, newData);
    }

    private static class DefaultKeyboxProvider implements IKeyboxProvider {
        private final Map<String, String> keyboxData = new HashMap<>();

        private DefaultKeyboxProvider(String rawData) {
            if (rawData.trim().startsWith("<")) {
                parseKeyboxXml(rawData);
            } else {
                parseKeyboxJson(rawData);
            }
        }

        private void parseKeyboxXml(String xmlContent) {
            try {
                XmlPullParser parser = Xml.newPullParser();
                parser.setInput(new StringReader(xmlContent));

                int eventType = parser.getEventType();
                String currentAlgo = null;
                int ecCertIndex = 1;
                int rsaCertIndex = 1;

                while (eventType != XmlPullParser.END_DOCUMENT) {
                    String tagName = parser.getName();
                    switch (eventType) {
                        case XmlPullParser.START_TAG:
                            if ("Key".equalsIgnoreCase(tagName)) {
                                String algoAttr = parser.getAttributeValue(null, "algorithm");
                                if (algoAttr != null) {
                                    if (algoAttr.equalsIgnoreCase("ecdsa") || algoAttr.equalsIgnoreCase("ec")) {
                                        currentAlgo = "EC";
                                    } else if (algoAttr.equalsIgnoreCase("rsa")) {
                                        currentAlgo = "RSA";
                                    }
                                }
                            } else if ("PrivateKey".equalsIgnoreCase(tagName) && currentAlgo != null) {
                                String privKey = parser.nextText();
                                keyboxData.put(currentAlgo + ".PRIV", privKey.trim());
                            } else if ("Certificate".equalsIgnoreCase(tagName) && currentAlgo != null) {
                                String certPem = parser.nextText();
                                if ("EC".equals(currentAlgo) && ecCertIndex <= MAX_CERT_COUNT) {
                                    keyboxData.put("EC.CERT_" + ecCertIndex, certPem.trim());
                                    ecCertIndex++;
                                } else if ("RSA".equals(currentAlgo) && rsaCertIndex <= MAX_CERT_COUNT) {
                                    keyboxData.put("RSA.CERT_" + rsaCertIndex, certPem.trim());
                                    rsaCertIndex++;
                                }
                            }
                            break;

                        case XmlPullParser.END_TAG:
                            if ("Key".equalsIgnoreCase(tagName)) {
                                currentAlgo = null;
                            }
                            break;
                    }
                    eventType = parser.next();
                }

                if (hasKeybox()) {
                    Log.i(TAG, "Successfully parsed Keybox XML from Settings");
                } else {
                    Log.w(TAG, "Parsed Keybox XML but no valid keys/certificates found");
                }

            } catch (Exception e) {
                Log.e(TAG, "Failed to parse Keybox XML", e);
            }
        }

        private void parseKeyboxJson(String json) {
            try {
                JSONObject obj = new JSONObject(json);
                Iterator<String> keys = obj.keys();
                while (keys.hasNext()) {
                    String key = keys.next();
                    keyboxData.put(key, obj.getString(key));
                }
                if (hasKeybox()) {
                    Log.i(TAG, "Successfully parsed Keybox JSON from Settings");
                }
            } catch (Exception e) {
                Log.e(TAG, "Failed to parse Keybox JSON", e);
            }
        }

        public static Context getApplicationContext() {
            try {
                return ActivityThread.currentApplication().getApplicationContext();
            } catch (Exception e) {
                Log.e(TAG, "Error getting application context", e);
                return null;
            }
        }

        @Override
        public boolean hasKeybox() {
            return hasCertificateChain("EC") || hasCertificateChain("RSA");
        }

        private boolean hasCertificateChain(String prefix) {
            if (!keyboxData.containsKey(prefix + ".PRIV")) return false;
            for (int i = 1; i <= MAX_CERT_COUNT; i++) {
                if (keyboxData.containsKey(prefix + ".CERT_" + i)) return true;
            }
            return false;
        }

        @Override
        public String getEcPrivateKey() {
            return keyboxData.get("EC.PRIV");
        }

        @Override
        public String getRsaPrivateKey() {
            return keyboxData.get("RSA.PRIV");
        }

        @Override
        public String[] getEcCertificateChain() {
            return getCertificateChain("EC");
        }

        @Override
        public String[] getRsaCertificateChain() {
            return getCertificateChain("RSA");
        }

        private String[] getCertificateChain(String prefix) {
            List<String> chain = new ArrayList<>(3);
            for (int i = 1; i <= MAX_CERT_COUNT; i++) {
                String key = prefix + ".CERT_" + i;
                String val = keyboxData.get(key);
                if (val == null) break;
                chain.add(val);
            }
            return chain.toArray(new String[0]);
        }
    }
}
