package pcapdb.core.frame;

import java.util.EnumMap;
import java.util.Map;

public enum LinkType {
    //BSD_loopback_devices(0),Ethernet(1),Token_Ring(6),ARCnet(7),SLIP(8),PPP(9),FDDI(10),LocalTalk(114);
    BSD_loopback_devices,Ethernet,Token_Ring,ARCnet,SLIP,PPP,FDDI,LocalTalk;

    static Map<LinkType,Integer> linkTypeMap = new EnumMap<>(LinkType.class);

    static {
        linkTypeMap.put(BSD_loopback_devices,0);
        linkTypeMap.put(Ethernet,1);
        linkTypeMap.put(Token_Ring,6);
    }


}
