package org.dcsa.ctk.ebl.service.caverify;

/**
 * A cache which needs to be managed by a CacheManager should have values which implement this interface.
 */
public interface ManageableCacheValue {

    //To remove invalid entries from the cache.
    public boolean isValid();

    //To decide LRU value to replace.
    public long getTimeStamp();

    public void removeThisCacheValue();

    public void updateCacheWithNewValue();
}
