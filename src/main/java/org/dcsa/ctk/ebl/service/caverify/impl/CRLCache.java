/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *   * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */
package org.dcsa.ctk.ebl.service.caverify.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.dcsa.ctk.ebl.service.caverify.ManageableCache;
import org.dcsa.ctk.ebl.service.caverify.ManageableCacheValue;
import org.springframework.stereotype.Service;

import java.security.cert.X509CRL;
import java.util.Date;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class CRLCache implements ManageableCache {

    private static volatile CRLCache cache;
    private static volatile Map<String, CRLCacheValue> hashMap = new ConcurrentHashMap<>();
    private static volatile Iterator<Map.Entry<String, CRLCacheValue>> iterator = hashMap.entrySet().iterator();
    private static volatile CacheManager cacheManager;
    private static CRLVerifier crlVerifier = new CRLVerifier(null);
    private static final Log log = LogFactory.getLog(CRLCache.class);

    private CRLCache() {
    }

    public static CRLCache getCache() {
        //Double checked locking
        if (cache == null) {
            synchronized (CRLCache.class) {
                if (cache == null) {
                    cache = new CRLCache();
                }
            }
        }
        return cache;
    }

    public synchronized ManageableCacheValue getNextCacheValue() {
        //changes to the map are reflected on the keySet. And its iterator is weakly consistent. so will never
        //throw concurrent modification exception.
        if (iterator.hasNext()) {
            return hashMap.get(iterator.next().getKey());
        } else {
            resetIterator();
            return null;
        }
    }
    public synchronized int getCacheSize() {
        return hashMap.size();
    }

    public void resetIterator() {
        iterator = hashMap.entrySet().iterator();
    }

    private synchronized void replaceNewCacheValue(CRLCacheValue cacheValue) {
        //If someone has updated with the new value before current Thread.
        if (cacheValue.isValid()) {
            return;
        }
        try {
            String crlUrl = cacheValue.crlUrl;
            X509CRL x509CRL = crlVerifier.downloadCRLFromWeb(crlUrl);
            this.setCacheValue(crlUrl, x509CRL);
        } catch (Exception e) {
            log.info("Cant replace old CacheValue with new CacheValue. So remove", e);
            //If cant be replaced remove.
            cacheValue.removeThisCacheValue();
        }
    }

    public synchronized X509CRL getCacheValue(String crlUrl) {
        CRLCacheValue cacheValue = hashMap.get(crlUrl);
        if (cacheValue != null) {
            //If who ever gets this cache value before Cache manager task found its invalid, update it and get the
            // new value.
            if (!cacheValue.isValid()) {
                cacheValue.updateCacheWithNewValue();
                CRLCacheValue crlCacheValue = hashMap.get(crlUrl);
                return (crlCacheValue != null ? crlCacheValue.getValue() : null);
            }
            return cacheValue.getValue();
        } else {
            return null;
        }

    }

    public synchronized void setCacheValue(String crlUrl, X509CRL crl) {
        CRLCacheValue cacheValue = new CRLCacheValue(crlUrl, crl);
        log.info("Before set- HashMap size " + hashMap.size());
        hashMap.put(crlUrl, cacheValue);
        log.info("After set - HashMap size " + hashMap.size());
    }

    public synchronized void removeCacheValue(String crlUrl) {
        log.info("Before remove - HashMap size " + hashMap.size());
        hashMap.remove(crlUrl);
        log.info("After remove - HashMap size " + hashMap.size());

    }

    /**
     * This is the wrapper class of the actual cache value which is a X509CRL.
     */
    private class CRLCacheValue implements ManageableCacheValue {

        private String crlUrl;
        private X509CRL crl;
        private long timeStamp = System.currentTimeMillis();

        public CRLCacheValue(String crlUrl, X509CRL crl) {
            this.crlUrl = crlUrl;
            this.crl = crl;
        }

        public String getKey() {
            return crlUrl;
        }

        public X509CRL getValue() {
            timeStamp = System.currentTimeMillis();
            return crl;
        }

        /**
         * CRL has a validity period. We can reuse a downloaded CRL within that period.
         */
        public boolean isValid() {
            Date today = new Date();
            Date nextUpdate = crl.getNextUpdate();
            return nextUpdate != null && nextUpdate.after(today);
        }

        public long getTimeStamp() {
            return timeStamp;
        }

        /**
         * Used by cacheManager to remove invalid entries.
         */
        public void removeThisCacheValue() {
            removeCacheValue(crlUrl);
        }

        public void updateCacheWithNewValue() {
            replaceNewCacheValue(this);
        }
    }
}
