package pcapdb.core.frame;

/**
 * This class contains Packet Header Structure
 *
 * @author PanDi(anonymous-oss@outlook.com)
 */
public class PacketFrame {

    /**
     * The length of GMTtime field
     */
    public static final int GMTTimeLength =4;

    /**
     * The length of MicroTime field
     */
    public static final int MicroTimeLength=4;

    /**
     * The length of Capture Length field
     */
    public static final int CapLenLength=4;

    /**
     * The length of Length field
     */
    public static final int LenLength=4;

    /**
     * The offset of GMTTime field
     */
    public static final int GMTTimePosition=0;

    /**
     * The offset of MicroTime field
     */
    public static final int MicroTimePosition;

    /**
     * The offset of Capture Length field
     */
    public static final int CapLenPosition;

    /**
     * The offset of Length field
     */
    public static final int LenPosition;

    /**
     * The totalLength of this header
     */
    public static final int totalLength;

    static {
        MicroTimePosition=GMTTimePosition+ GMTTimeLength;
        CapLenPosition=MicroTimePosition+MicroTimeLength;
        LenPosition=CapLenPosition+CapLenLength;
        totalLength=LenPosition+LenLength;
    }

    @Override
    public String toString() {
        return "PacketFrame{" +
                "GMTTimeLength=" + GMTTimeLength +
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
