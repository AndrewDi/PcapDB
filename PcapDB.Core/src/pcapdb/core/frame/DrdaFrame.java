package pcapdb.core.frame;

/**
 * This class contains DRDA Packet Structure
 *
 * @author PanDi(anonymous-oss@outlook.com)
 */
public class DrdaFrame {

    /**
     * The length of DDM Length field
     */
    public static final int DDMLengthLength = 2;

    /**
     * The length of DDM Magic field
     */
    public static final int DDMMagicLength = 1;

    /**
     * The length of DDM Format field
     */
    public static final int DDMFormatLength = 1;

    /**
     * The length of DDM CorrelId field
     */
    public static final int DDMCorrelIdLength = 2;

    /**
     * The length of DDM Length2 field
     */
    public static final int DDMLength2Length = 2;

    /**
     * The length of DDM CodePoint field
     */
    public static final int DDMCodePointLength = 2;

    /**
     * The offset of DDM Length field
     */
    public static final int DDMLengthPosition = 0 ;

    /**
     * The offset of DDM Magic field
     */
    public static final int DDMMagicPosition;

    /**
     * The offset of DDM Format field
     */
    public static final int DDMFormatPosition;

    /**
     * The offset of DDM CorrelId field
     */
    public static final int DDMCorrelIdPosition;

    /**
     * The offset of DDM Length2 field
     */
    public static final int DDMLength2Position;

    /**
     * The offset of DDM CodePoint field
     */
    public static final int DDMCodePointPosition;

    /**
     * The totalLength of DDM header
     */
    public static final int totalLength;

    //Extra Parameter Length
    public static final int DDMParameterLengthLength = 2;

    public static final int DDMParameterCodePointLength = 2;

    static {
        DDMMagicPosition = DDMLengthPosition+DDMLengthLength;
        DDMFormatPosition = DDMMagicPosition+DDMMagicLength;
        DDMCorrelIdPosition = DDMFormatPosition+DDMFormatLength;
        DDMLength2Position = DDMCorrelIdPosition+DDMCorrelIdLength;
        DDMCodePointPosition=DDMLength2Position+DDMLength2Length;
        totalLength = DDMCodePointPosition+DDMCodePointLength;
    }

    @Override
    public String toString() {
        return "DrdaFrame{" +
                "DDMLengthLength=" + DDMLengthLength +
                ", DDMMagicLength=" + DDMMagicLength +
                ", DDMFormatLength=" + DDMFormatLength +
                ", DDMCorrelIdLength=" + DDMCorrelIdLength +
                ", DDMLength2Length=" + DDMLength2Length +
                ", DDMCodePointLength=" + DDMCodePointLength +
                ", DDMLengthPosition=" + DDMLengthPosition +
                ", DDMMagicPosition=" + DDMMagicPosition +
                ", DDMFormatPosition=" + DDMFormatPosition +
                ", DDMCorrelIdPosition=" + DDMCorrelIdPosition +
                ", DDMLength2Position=" + DDMLength2Position +
                ", DDMCodePointPosition=" + DDMCodePointPosition +
                ", totalLength=" + totalLength +
                ", DDMParameterLengthLength=" + DDMParameterLengthLength +
                ", DDMParameterCodePointLength=" + DDMParameterCodePointLength +
                '}';
    }
}
