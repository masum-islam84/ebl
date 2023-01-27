package org.dcsa.ctk.ebl.service.caverify;

/**
 * A cache which needs to be managed by CacheManager needs to implement this interface.
 */
public interface ManageableCache {

    public ManageableCacheValue getNextCacheValue();

    public int getCacheSize();

    public void resetIterator();
}
