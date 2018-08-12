package pcapdb.core.frame;

public class PacketFrame {
    public PacketFrame(){}

    public static int GMTtimeLength=4;

    public static int MicroTimeLength=4;

    public static int CapLenLength=4;

    public static int LenLength=4;

    public static int GMTTimePosition=0;

    public static int MicroTimePosition;

    public static int CapLenPosition;

    public static int LenPosition;

    public static int totalLength;

    static {
        MicroTimePosition=GMTTimePosition+GMTtimeLength;
        CapLenPosition=MicroTimePosition+MicroTimeLength;
        LenPosition=CapLenPosition+CapLenLength;
        totalLength=LenPosition+LenLength;
    }

    @Override
    public String toString() {
        return "PacketFrame{" +
                "GMTtimeLength=" + GMTtimeLength +
                ", MicroTimeLength=" + MicroTimeLength +
                ", CapLenLength=" + CapLenLength +
                ", LenLength=" + LenLength +
                ", GMTTimePosition=" + GMTTimePosition +
                ", MicroTimePosition=" + MicroTimePosition +
                ", CapLenPosition=" + CapLenPosition +
                ", LenPosition=" + LenPosition +
                '}';
    }
}
