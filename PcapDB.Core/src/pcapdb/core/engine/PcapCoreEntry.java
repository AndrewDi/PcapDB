package pcapdb.core.engine;

import org.jnetpcap.Pcap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

public class PcapCoreEntry {

    final static Logger logger = LoggerFactory.getLogger(PcapCoreEntry.class.getName());

    public static void main(String[] args) {
        String deviceName="\\Device\\NPF_{53DAF392-2D04-43AA-B9C8-420CBC60B245}";

        List<String> devices= CapturePcapDevice.getAllDevices();
        Pcap pcap = CapturePcapDevice.PcapOpenDevice(deviceName);
    }
}
