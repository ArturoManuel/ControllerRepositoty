package net.floodlightcontroller.portScanning;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.mactracker.MACTracker;
import net.floodlightcontroller.packet.*;


import org.projectfloodlight.openflow.protocol.*;

import java.util.*;


import net.floodlightcontroller.core.IFloodlightProviderService;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentSkipListSet;

import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;



public class PortScanning implements IOFMessageListener, IFloodlightModule {
    protected IOFSwitchService switchService;


    protected IFloodlightProviderService floodlightProvider;

    protected Map<IPv4Address, Set<TransportPort>> portAccessMap;
    protected Map<IPv4Address, Long> lastAccessTimeMap;
    protected final int PORT_SCAN_THRESHOLD = 40; // Ejemplo: umbral de puertos
    protected final long TIME_WINDOW = 10 * 1000;

    protected Set<Long> macAddresses;
    protected static Logger logger;


    @Override
    public String getName() {
        return  PortScanning.class.getSimpleName();
    }

    @Override
    public boolean isCallbackOrderingPrereq(OFType type, String name) {
        return false;
    }

    @Override
    public boolean isCallbackOrderingPostreq(OFType type, String name) {
        return false;
    }


    @Override
    public net.floodlightcontroller.core.IListener.Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
        Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

//        if (eth.getEtherType() == EthType.IPv4) {
//            IPv4 ipv4 = (IPv4) eth.getPayload();
//            if (ipv4.getProtocol() == IpProtocol.TCP || ipv4.getProtocol() == IpProtocol.UDP) {
//                IPv4Address srcIp = ipv4.getSourceAddress();
//                MacAddress srcMac = eth.getSourceMACAddress();
//                MacAddress dstMac = eth.getDestinationMACAddress();
//                TransportPort dstPort = (ipv4.getPayload() instanceof TCP) ?
//                        ((TCP) ipv4.getPayload()).getDestinationPort() :
//                        ((UDP) ipv4.getPayload()).getDestinationPort();
//
//                Set<TransportPort> ports = portAccessMap.get(srcIp);
//                if (ports == null) {
//                    ports = new ConcurrentSkipListSet<>();
//                    portAccessMap.put(srcIp, ports);
//                }
//                ports.add(dstPort);
//
//                lastAccessTimeMap.put(srcIp, System.currentTimeMillis());
//
//                if (isPortScan(srcIp)) {
//                    blockSourceIp(srcMac, dstMac); // Utiliza las direcciones MAC detectadas
//                    logger.info("Port scan detected from IP: {}, blocking source MAC: {}", srcIp.toString(), srcMac.toString());
//                    return Command.STOP;
//                }
//
//            }
//        }

        if (eth.getEtherType() == EthType.IPv4) {
            IPv4 ipv4 = (IPv4) eth.getPayload();
            if (ipv4.getProtocol() == IpProtocol.ICMP) {
                handleICMPPacket(ipv4, eth);
            } else if (ipv4.getProtocol() == IpProtocol.TCP || ipv4.getProtocol() == IpProtocol.UDP) {
                handleTCPOrUDPPacket(ipv4, eth);
            }
        }

        return Command.CONTINUE;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleServices() {
        return null;
    }

    @Override
    public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
        return null;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
        Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
        l.add(IFloodlightProviderService.class);
        return l;
    }

    @Override
    public void init(FloodlightModuleContext context) throws FloodlightModuleException {
        floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
        macAddresses = new ConcurrentSkipListSet<Long>();
        logger = LoggerFactory.getLogger(PortScanning.class);
        switchService = context.getServiceImpl(IOFSwitchService.class);

        portAccessMap = new ConcurrentHashMap<>();

        lastAccessTimeMap = new ConcurrentHashMap<>();
    }

    @Override
    public void startUp(FloodlightModuleContext context) {
        floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
    }
    protected boolean isPortScan(IPv4Address srcIp) {
        Set<TransportPort> accessedPorts = portAccessMap.get(srcIp);
        long currentTime = System.currentTimeMillis();
        Long lastAccessTime = lastAccessTimeMap.get(srcIp);
        if (lastAccessTime == null) {
            lastAccessTime = currentTime; // o podrías usar un valor predeterminado
        }

        // Verificar si el número de accesos en el tiempo establecido excede el umbral
        if (accessedPorts != null && (currentTime - lastAccessTime <= TIME_WINDOW) && accessedPorts.size() > PORT_SCAN_THRESHOLD) {
            return true;
        }

        return false;
    }


    protected void blockSourceIp(MacAddress srcMac, MacAddress dstMac) {
        DatapathId dpid = DatapathId.of("00:00:f2:20:f9:45:4c:4e"); // Datapath ID de tu switch
        IOFSwitch sw = switchService.getSwitch(dpid); // Obtener el switch

        if (sw == null) {
            logger.error("Switch {} no encontrado", dpid.toString());
            return;
        }

        OFFactory factory = sw.getOFFactory(); // Obtener la fábrica de mensajes para la versión OF del switch

        // Construir el Match
        Match match = factory.buildMatch()
                .setExact(MatchField.ETH_SRC, srcMac)
                .setExact(MatchField.ETH_DST, dstMac)
                .build();

        // Construir el FlowMod
        // Valor decimal que deseas establecer como cookie
        long decimalValue = 30; // Por ejemplo, el valor decimal 12345

// Construir el FlowMod con el valor de cookie
        OFFlowAdd flowAdd = factory.buildFlowAdd()
                .setCookie(U64.of(decimalValue)) // Convertirá el valor decimal a hexadecimal internamente
                .setMatch(match)
                .setPriority(32768)
                .setIdleTimeout(0)
                .setHardTimeout(3600)
                .setBufferId(OFBufferId.NO_BUFFER)
                .setOutPort(OFPort.ANY)
                .build();

        // Enviar el FlowMod al switch
        sw.write(flowAdd);

        logger.info("Flow rule added to block traffic from MAC: {}", srcMac.toString());
    }

    protected void deleteBlockingFlowRule(MacAddress srcMac, MacAddress dstMac) {
        DatapathId dpid = DatapathId.of("00:00:f2:20:f9:45:4c:4e");
        IOFSwitch sw = switchService.getSwitch(dpid);
        if (sw == null) {
            logger.error("Switch {} no encontrado", dpid.toString());
            return;
        }

        OFFactory factory = sw.getOFFactory();
        Match match = factory.buildMatch()
                .setExact(MatchField.ETH_SRC, srcMac)
                .setExact(MatchField.ETH_DST, dstMac)
                .build();

        OFFlowDelete flowDelete = factory.buildFlowDelete()
                .setMatch(match)
                .setCookie(U64.of(30))
                .setPriority(32768) // La misma prioridad que se usó para añadir la regla
                .setOutPort(OFPort.ANY)
                .build();

        sw.write(flowDelete);
        logger.info("Flow rule to block traffic from MAC: {} has been deleted", srcMac.toString());
    }



//    @Override
//    public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
//        Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
//
//        if (eth.getEtherType() == EthType.IPv4) {
//            IPv4 ipv4 = (IPv4) eth.getPayload();
//            if (ipv4.getProtocol() == IpProtocol.ICMP) {
//                handleICMPPacket(ipv4, eth, sw);
//            } else if (ipv4.getProtocol() == IpProtocol.TCP || ipv4.getProtocol() == IpProtocol.UDP) {
//                handleTCPOrUDPPacket(ipv4, eth);
//            }
//        }
//        return Command.CONTINUE;
//    }
//
    private void handleTCPOrUDPPacket(IPv4 ipv4, Ethernet eth) {
        IPv4Address srcIp = ipv4.getSourceAddress();
        MacAddress srcMac = eth.getSourceMACAddress();
        MacAddress dstMac = eth.getDestinationMACAddress();
        TransportPort dstPort = ipv4.getPayload() instanceof TCP ?
                ((TCP) ipv4.getPayload()).getDestinationPort() :
                ((UDP) ipv4.getPayload()).getDestinationPort();

        Set<TransportPort> ports = portAccessMap.get(srcIp);
        if (ports == null) {
            ports = new ConcurrentSkipListSet<>();
            portAccessMap.put(srcIp, ports);
        }
        ports.add(dstPort);
        lastAccessTimeMap.put(srcIp, System.currentTimeMillis());

        if (isPortScan(srcIp)) {
            blockSourceIp(srcMac, dstMac);
            logger.info("Port scan detected from IP: {}, blocking source MAC: {}", srcIp.toString(), srcMac.toString());
        }
    }

    private void handleICMPPacket(IPv4 ipv4, Ethernet eth) {
        ICMP icmp = (ICMP) ipv4.getPayload();
        if (icmp.getIcmpType() == ICMP.ECHO_REQUEST && ipv4.getSourceAddress().equals(IPv4Address.of("10.0.0.22"))) {
            MacAddress srcMac = eth.getSourceMACAddress();
            MacAddress dstMac = eth.getDestinationMACAddress();
            deleteBlockingFlowRule(srcMac, dstMac);
            logger.info("ICMP echo request from 10.0.0.22 detected, deleting block rule");
        }
    }
//
//    protected boolean isPortScan(IPv4Address srcIp) {
//        Set<TransportPort> accessedPorts = portAccessMap.get(srcIp);
//        Long lastAccessTime = lastAccessTimeMap.get(srcIp);
//        if (lastAccessTime == null) {
//            lastAccessTime = System.currentTimeMillis();
//        }
//
//        long currentTime = System.currentTimeMillis();
//        return accessedPorts != null && (currentTime - lastAccessTime <= TIME_WINDOW) && accessedPorts.size() > PORT_SCAN_THRESHOLD;
//    }
//
//    protected void blockSourceIp(MacAddress srcMac, MacAddress dstMac) {
//        DatapathId dpid = DatapathId.of("00:00:f2:20:f9:45:4c:4e");
//        IOFSwitch sw = switchService.getSwitch(dpid);
//        if (sw == null) {
//            logger.error("Switch {} no encontrado", dpid.toString());
//            return;
//        }
//
//        OFFactory factory = sw.getOFFactory();
//        Match match = factory.buildMatch()
//                .setExact(MatchField.ETH_SRC, srcMac)
//                .setExact(MatchField.ETH_DST, dstMac)
//                .build();
//
//        OFFlowAdd flowAdd = factory.buildFlowAdd()
//                .setCookie(U64.of(30))
//                .setMatch(match)
//                .setPriority(32768)
//                .setIdleTimeout(0)
//                .setHardTimeout(3600)
//                .setBufferId(OFBufferId.NO_BUFFER)
//                .setOutPort(OFPort.ANY)
//                .build();
//
//        sw.write(flowAdd);
//        logger.info("Flow rule added to block traffic from MAC: {}", srcMac.toString());
//    }
//
//    protected void deleteBlockingFlowRule(MacAddress srcMac, MacAddress dstMac, IOFSwitch sw) {
//        OFFactory factory = sw.getOFFactory();
//        Match match = factory.buildMatch()
//                .setExact(MatchField.ETH_SRC, srcMac)
//                .setExact(MatchField.ETH_DST, dstMac)
//                .build();
//
//        OFFlowDelete flowDelete = factory.buildFlowDelete()
//                .setMatch(match)
//                .setCookie(U64.of(30))
//                .setOutPort(OFPort.ANY)
//                .build();
//
//        sw.write(flowDelete);
//        logger.info("Flow rule to block traffic from MAC: {} has been deleted", srcMac.toString());
//    }
//
//    @Override
//    public Collection<Class<? extends IFloodlightService>> getModuleServices() {
//        return null;
//    }
//
//    @Override
//    public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
//        return null;
//    }
//
//    @Override
//    public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
//        ArrayList<Class<? extends IFloodlightService>> l = new ArrayList<>();
//        l.add(IFloodlightProviderService.class);
//        return l;
//    }
//
//    @Override
//    public void init(FloodlightModuleContext context) throws FloodlightModuleException {
//        floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
//        switchService = context.getServiceImpl(IOFSwitchService.class);
//        portAccessMap = new ConcurrentHashMap<>();
//        lastAccessTimeMap = new ConcurrentHashMap<>();
//        logger = LoggerFactory.getLogger(PortScanning.class);
//    }
//
//    @Override
//    public void startUp(FloodlightModuleContext context) {
//        floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
//    }
//}



















}
