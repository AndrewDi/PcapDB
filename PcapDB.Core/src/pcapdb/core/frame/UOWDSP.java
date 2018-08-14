package pcapdb.core.frame;

import java.util.concurrent.ConcurrentHashMap;

public enum  UOWDSP {
    UNKNOW(0),COMMITTED(1),RollBack(2);

    private static ConcurrentHashMap<Integer,UOWDSP> hashMap;

    private int value;

    private UOWDSP(int _value){
        this.value = _value;
    }

    static {
        hashMap = new ConcurrentHashMap<>();
        UOWDSP[] types = UOWDSP.values();
        for (UOWDSP type : types) {
            hashMap.put(type.value(),type);
        }
    }

    public int value() {
        return this.value;
    }

    public static UOWDSP valueOf(int _value) {
        return hashMap.getOrDefault(_value,UOWDSP.UNKNOW);
    }
}
