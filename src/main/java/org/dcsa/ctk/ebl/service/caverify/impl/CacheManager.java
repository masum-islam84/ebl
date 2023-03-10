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

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

public class CacheManager {

    private final boolean DO_NOT_INTERRUPT_IF_RUNNING = false;
    private ScheduledExecutorService scheduler;
    private ScheduledFuture scheduledFuture = null;
    private ManageableCache cache;
    private int cacheMaxSize;
    private int delay;
    private CacheManagingTask cacheManagingTask;
    private static final Log log = LogFactory.getLog(CacheManager.class);

    public CacheManager(ManageableCache cache, int cacheMaxSize, int delay) {
        int NUM_THREADS = 1;
        scheduler = Executors.newScheduledThreadPool(NUM_THREADS);
        this.cache = cache;
        this.cacheMaxSize = cacheMaxSize;
        this.cacheManagingTask = new CacheManagingTask();
        this.delay = delay;
        start();
    }

    private boolean start() {
        if(scheduledFuture == null || (scheduledFuture.isCancelled())) {
            scheduledFuture = scheduler.scheduleWithFixedDelay(cacheManagingTask,
                    delay, delay, TimeUnit.MINUTES);
            log.info(cache.getClass().getSimpleName()+" Cache Manager Started");
            return true;
        }
        return false;
    }

    /**
     * To wake cacheManager up at will. If this method is called while its task is running, it will run its task again
     * soon after its done. CacheManagerTask will be rescheduled as before.
     * @return true if successfully waken up. false otherwise.
     */
    public boolean wakeUpNow(){
        if(scheduledFuture !=null) {
            if(!scheduledFuture.isCancelled()) {
                scheduledFuture.cancel(DO_NOT_INTERRUPT_IF_RUNNING);
            }
            scheduledFuture = scheduler.scheduleWithFixedDelay(cacheManagingTask,
                    0, delay,TimeUnit.MINUTES);
            log.info(cache.getClass().getSimpleName()+" Cache Manager Wakened Up.....");
            return true;
        }
        return false;
    }


    public boolean stop(){
        if(scheduledFuture !=null && !scheduledFuture.isCancelled()){
            scheduledFuture.cancel(DO_NOT_INTERRUPT_IF_RUNNING);
            log.info(cache.getClass().getSimpleName()+" Cache Manager Stopped.....");
            return true;
        }
        return false;
    }

    public boolean isRunning() {
        return !scheduledFuture.isCancelled();
    }

    /**
     * This is the Scheduled Task the CacheManager uses in order to remove invalid cache values and
     * to remove LRU values if the cache reaches cacheMaxSize.
     */
    private class CacheManagingTask implements Runnable {

        public void run() {

            long start = System.currentTimeMillis();
            log.info(cache.getClass().getSimpleName()+" Cache Manager Task Started.");

            ManageableCacheValue nextCacheValue;
            //cache.getCacheSize() can vary when new entries are added. So get cache size at this point
            int cacheSize = cache.getCacheSize();
            int numberToRemove = (cacheSize>cacheMaxSize)?  cacheSize - cacheMaxSize: 0;

            List<ManageableCacheValue> entriesToRemove = new ArrayList<ManageableCacheValue>();
            LRUEntryCollector lruEntryCollector = new LRUEntryCollector(entriesToRemove, numberToRemove);

            //Start looking at cache entries from the beginning.
            cache.resetIterator();
            //Iteration through the cache entries.
            while ((cacheSize--)>0) {

                nextCacheValue = cache.getNextCacheValue();
                if (nextCacheValue == null) {
                    log.info("Cache manager iteration through Cache values done");
                    break;
                }

                //Updating invalid cache values
                if (!nextCacheValue.isValid()) {
                    log.info("Updating Invalid Cache Value by Manager");
                    nextCacheValue.updateCacheWithNewValue();
                }

                //There are LRU entries tobe removed since cacheSize > maxCacheSize. So collect them.
                if(numberToRemove>0) {
                    lruEntryCollector.collectEntriesToRemove(nextCacheValue);
                }
            }

            //LRU entries removing
            for(ManageableCacheValue oldCacheValue: entriesToRemove) {
                log.info("Removing LRU value from cache");
                oldCacheValue.removeThisCacheValue();
            }

            log.info(cache.getClass().getSimpleName()+" Cache Manager Task Done. Took " +
                    (System.currentTimeMillis() - start) + " ms.");
        }

        private class LRUEntryCollector {

            private List<ManageableCacheValue> entriesToRemove;
            private int listMaxSize;

            LRUEntryCollector(List<ManageableCacheValue> entriesToRemove, int numberToRemove){
                this.entriesToRemove = entriesToRemove;
                this.listMaxSize = numberToRemove;
            }

            /**
             * This method collects the listMaxSize number of LRU values from the Cache. These values
             * will be removed from the cache. This uses a part of the Logic in Insertion Sort.
             * @param value to be collected.
             */
            private void collectEntriesToRemove(ManageableCacheValue value) {

                entriesToRemove.add(value);
                int i = entriesToRemove.size()-1;
                int j = i;
                for(; j>0 && (value.getTimeStamp() < entriesToRemove.get(j-1).getTimeStamp()); j--) {
                    entriesToRemove.remove(j);
                    entriesToRemove.add(j,(entriesToRemove.get(j-1)));
                }
                entriesToRemove.remove(j);
                entriesToRemove.add(j,value);
                /**
                 * First entry in the list will be the oldest. Last is the earliest in the list.
                 * So remove the earliest since we need to collect the old (LRU) values to remove
                 * from cache later
                 */
                if(entriesToRemove.size() > listMaxSize) {
                    entriesToRemove.remove(entriesToRemove.size() -1);
                }
            }

        }
    }
}
