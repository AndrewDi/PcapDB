package pcapdb.core.frame;

public enum LinkType {
    BSD_loopback_devices(0),Ethernet(1),Token_Ring(6),ARCnet(7),SLIP(8),PPP(9),FDDI(10),LocalTalk(114);

    private LinkType(int type){

    }

}
