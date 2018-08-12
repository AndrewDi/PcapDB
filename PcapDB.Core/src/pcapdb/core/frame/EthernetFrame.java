package pcapdb.core.frame;

public class EthernetFrame {
    public static int DestinationAddressLength=6;

    public static int SourceAddressLength=6;

    public static int TypeLength=2;

    public static int DestinationAddressPosition=0;

    public static int SourceAddressPosition;

    public static int TypePosition;

    public static int totalLength;

    static {
        SourceAddressPosition=DestinationAddressPosition+DestinationAddressLength;
        TypePosition = SourceAddressPosition+SourceAddressLength;
        totalLength=TypePosition+TypeLength;
    }

    @Override
    public String toString() {
        return "EthernetFrame{" +
                "DestinationAddressLength=" + DestinationAddressLength +
                ", SourceAddressLength=" + SourceAddressLength +
                ", TypeLength=" + TypeLength +
                ", DestinationAddressPosition=" + DestinationAddressPosition +
                ", SourceAddressPosition=" + SourceAddressPosition +
                ", TypePosition=" + TypePosition +
                ", totalLength=" + totalLength +
                '}';
    }
}
