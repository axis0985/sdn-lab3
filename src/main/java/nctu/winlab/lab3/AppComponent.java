/*
 * Copyright 2019-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nctu.winlab.lab3;

import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Service;
import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.Ip4Prefix;
import org.onlab.packet.MacAddress;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.onosproject.core.ApplicationId;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.FlowEntry;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.HostId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.core.CoreService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

import javax.sound.sampled.Port;

import java.util.HashMap;
/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true)
public class AppComponent {

    private final Logger log = LoggerFactory.getLogger(getClass());

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    private CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    private org.onosproject.net.packet.PacketService packetService;
    
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    private FlowObjectiveService flowobjService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    private FlowRuleService flowService;
    
    private PacketProcessor processor = new InternalPacketProcessor();

    private Map<DeviceId, Map<MacAddress, ConnectPoint>> macTable = new HashMap<DeviceId, Map<MacAddress, ConnectPoint>>();

    private ApplicationId appid;

    @Activate
    protected void activate() {
        appid = coreService.registerApplication("nctu.winlab.lab3");
        packetService.addProcessor(processor, PacketProcessor.director(2));
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appid);
        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        packetService.removeProcessor(processor);
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appid);
        flowService.removeFlowRulesById(appid);
        log.info("Stopped");
    }

    private class InternalPacketProcessor implements PacketProcessor {
        
        @Override
        public void process(PacketContext context) {
            // receive Packet in packet
            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();

            if (ethPkt == null) {
                return;
            }

            if (isControlPacket(ethPkt)) {
                return;
            }

            HostId id = HostId.hostId(ethPkt.getDestinationMAC());

            // Do not process LLDP MAC address in any way.
            if (id.mac().isLldp()) {
                return;
            }
            log.info("Packet in !!");
            MacAddress srcMac = ethPkt.getSourceMAC();
            MacAddress dstMac = ethPkt.getDestinationMAC();
            DeviceId did = pkt.receivedFrom().deviceId();

            if (macTable.get(did) == null) {
                macTable.put(did, new HashMap<MacAddress, ConnectPoint>());
            }
            ConnectPoint dstCP = macTable.get(did).get(dstMac);
            if (dstCP == null) {
                macTable.get(did).put(srcMac, pkt.receivedFrom());
                flood(context);
            } else {
                installRule(context, dstCP.port());
            }
        }
    }
    private void flood(PacketContext context) {
            packetOut(context, PortNumber.FLOOD);
    }
    private void packetOut(PacketContext context, PortNumber port) {
        context.treatmentBuilder().setOutput(port);
        context.send();
    }
    private boolean isControlPacket(Ethernet eth) {
        short type = eth.getEtherType();
        return type == Ethernet.TYPE_LLDP || type == Ethernet.TYPE_BSN;
    }
    private void installRule(PacketContext context, PortNumber port) {

        Ethernet inPkt = context.inPacket().parsed();
        if (inPkt.getEtherType() == Ethernet.TYPE_IPV4) {
            TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder();
            selectorBuilder.matchEthDst(inPkt.getDestinationMAC())
                    .matchEthType(Ethernet.TYPE_IPV4);
            IPv4 ipv4Packet = (IPv4) inPkt.getPayload();
            Ip4Prefix matchIp4SrcPrefix =
                    Ip4Prefix.valueOf(ipv4Packet.getSourceAddress(),
                                        Ip4Prefix.MAX_MASK_LENGTH);
            Ip4Prefix matchIp4DstPrefix =
                    Ip4Prefix.valueOf(ipv4Packet.getDestinationAddress(),
                                        Ip4Prefix.MAX_MASK_LENGTH);
            selectorBuilder.matchEthType(Ethernet.TYPE_IPV4)
                    .matchIPSrc(matchIp4SrcPrefix)
                    .matchIPDst(matchIp4DstPrefix);


            TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                    .setOutput(port)
                    .build();
            ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder()
                    .withSelector(selectorBuilder.build())
                    .withTreatment(treatment)
                    .withPriority(10)
                    .withFlag(ForwardingObjective.Flag.VERSATILE)
                    .fromApp(appid)
                    .makeTemporary(120)
                    .add();
            flowobjService.forward(context.inPacket().receivedFrom().deviceId(), forwardingObjective);

            packetOut(context, port);
            log.info("FLOOOOOOOOOOW");
        }
    }
}
