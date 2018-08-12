package pcapdb.core.frame;

import javafx.util.converter.DefaultStringConverter;

import java.util.EnumMap;
import java.util.Map;

public enum LinkType {
    ARCnet(7), BSD_loopback_devices(0), Ethernet(1), FDDI(10), LocalTalk(114), PPP(9), SLIP(8), Token_Ring(6);

    private int value;

    LinkType(int _value) {
        this.value = _value;
    }

    static {

    }

    public int value() {
        return this.value;
    }

    public static LinkType valueOf(int _value) {
        LinkType[] linkTypes = LinkType.values();
        for (LinkType linkType : linkTypes) {
            if (linkType.value() == _value)
                return linkType;
        }
        return null;
    }
}
