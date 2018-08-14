package pcapdb.core.frame;

import java.util.concurrent.ConcurrentHashMap;

public enum  SVRCODLevel {
    INFO(0),WARNING(4),ERROR(8),SEVERE(16),ACCDMG(32),PRMDMG(64),SESDMG(128);

    private static ConcurrentHashMap<Integer,SVRCODLevel> hashMap;

    private int value;

    SVRCODLevel(int _value) {
        this.value = _value;
    }

    static {
        hashMap = new ConcurrentHashMap<>();
        SVRCODLevel[] types = SVRCODLevel.values();
        for (SVRCODLevel type : types) {
            hashMap.put(type.value(),type);
        }
    }

    public int value() {
        return this.value;
    }

    public static SVRCODLevel valueOf(int _value) {
        return hashMap.getOrDefault(_value,SVRCODLevel.INFO);
    }
}
