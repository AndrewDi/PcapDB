package pcapdb.core.engine;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pcapdb.core.buffer.MappedByteBufferLocater;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

/**
 * This class is used to Open Pcap files
 *
 * @author PanDi(anonymous-oss@outlook.com)
 */
public class CapturePcapDevice {

    final static Logger logger = LoggerFactory.getLogger(CapturePcapDevice.class.getName());

    /**
     * Open file with MappedByteBuffer
     * @param path Full file path
     * @return Basic MappedByteBufferLocater object
     */
    public static MappedByteBufferLocater OpenFile(String path){
        try {
            logger.debug("Open Capture File: {}", path);
            RandomAccessFile randomAccessFile = new RandomAccessFile(path,"r");
            FileChannel fileChannel = randomAccessFile.getChannel();
            long fileSize = fileChannel.size();
            MappedByteBuffer mappedByteBuffer = fileChannel.map(FileChannel.MapMode.READ_ONLY,0,fileSize);
            return new MappedByteBufferLocater(mappedByteBuffer,0);
        }
        catch (IOException ex){
            logger.error(ex.getLocalizedMessage());
            return null;
        }
    }

    /**
     * Open Pcap file with specific path
     * @param path pcap file path
     * @return JNetPcap object
     */
    public static Pcap PcapOpenFile(String path){
        StringBuilder errbuf = new StringBuilder();
        Pcap pcap = Pcap.openOffline(path,errbuf);
        if(pcap==null){
            logger.error("Error while opening device for capture: {}",errbuf.toString());
            return null;
        }

        PacketBus packetBus = new PacketBus();
        PcapDBPacketHandler packetBusPcapDBPacketHandler = new PcapDBPacketHandler();
        try {
            pcap.loop(Pcap.LOOP_INFINITE,packetBusPcapDBPacketHandler,packetBus);
        }
        finally {
            pcap.close();
            //packetBus.stop();
        }
        return pcap;
    }

    /**
     * Open Ethernet Device with specific name
     * @param deviceName Ethernet Device Name
     * @return JNetPcap object
     */
    public static Pcap PcapOpenDevice(String deviceName){
        StringBuilder errbuf = new StringBuilder();
        int snaplen = 64 * 1024;
        // Capture all packets, no trucation 不截断的捕获所有包
        int flags = Pcap.MODE_PROMISCUOUS;
        int timeout = 10 * 1000;
        Pcap pcap = Pcap.openLive(deviceName,snaplen, flags, timeout, errbuf);
        // 参数：snaplen指定的是可以捕获的最大的byte数，
        // 如果 snaplen的值 比 我们捕获的包的大小要小的话，
        // 那么只有snaplen大小的数据会被捕获并以packet data的形式提供。
        // IP协议用16位来表示IP的数据包长度，所有最大长度是65535的长度
        // 这个长度对于大多数的网络是足够捕获全部的数据包的

        // 参数：flags promisc指定了接口是promisc模式的，也就是混杂模式，
        // 混杂模式是网卡几种工作模式之一，比较于直接模式：
        // 直接模式只接收mac地址是自己的帧，
        // 但是混杂模式是让网卡接收所有的，流过网卡的帧，达到了网络信息监视捕捉的目的

        // 参数：timeout 这个参数使得捕获报后等待一定的时间，来捕获更多的数据包，
        // 然后一次操作读多个包，不过不是所有的平台都支持，不支持的会自动忽略这个参数

        // 参数：errbuf pcap_open_live()失败返回NULL的错误信息，或者成功时候的警告信息

        if(pcap==null){
            logger.error("Error while opening device for capture: {}",errbuf.toString());
            return null;
        }
        PacketBus packetBus = new PacketBus();
        PcapDBPacketHandler packetBusPcapDBPacketHandler = new PcapDBPacketHandler();
        try {
            pcap.loop(Pcap.LOOP_INFINITE,packetBusPcapDBPacketHandler,packetBus);
        }
        finally {
            pcap.close();
        }
        return pcap;
    }

    public static List<String> getAllDevices(){
        List<PcapIf> alldevs = new ArrayList<PcapIf>();
        List<String> ethname = new LinkedList<>();
        StringBuilder errbuf = new StringBuilder();
        int r = Pcap.findAllDevs(alldevs, errbuf);
        /** 这个方法构造了可以用pcap_open_live()打开的所有网络设备
         * 这个列表中的元素都是 pcap_if_t，
         * name 一个指向设备名字的指针；
         * adderess 是一个接口的地址列表的第一个元素的指针；
         * flag 一个PCAP_IF_LOOPBACK标记接口是否是loopback的
         * 失败返回-1，成功返回0
         */

        if (alldevs.isEmpty()||alldevs==null) {
            // 如果获取失败，或者获取到列表为空，则输出错误信息，退出
            System.err.printf("Can't read list of devices, error is %s", errbuf
                    .toString());
            return null;
        }

        logger.error("Network devices found:");

        int i = 0;  // 遍历所有的设备
        for (PcapIf device : alldevs) {
            String description =
                    (device.getDescription() != null) ? device.getDescription()
                            : "No description available";  // 如果该设备介绍，则输出介绍
            logger.info("#{}: {} [{}]", i++, device.getName(), description);
            ethname.add(device.getName());
        }

        return ethname;
    }

    /**
     * Close Pcap packet
     * @param packetBus
     */
    public static void PcapClose(Pcap packetBus){
        if(packetBus!=null){
            packetBus.close();
        }
    }
}
