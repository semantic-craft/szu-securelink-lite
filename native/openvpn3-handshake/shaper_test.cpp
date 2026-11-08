#include "shaper.hpp"
#include <iostream>
using namespace securelink::shaper;
static void check(bool x) { if (!x) throw std::runtime_error("failed"); }
int main() {
    try {
        check(effectiveLimit(0)==0 && effectiveLimit(1)==100);
        check(effectiveLimit(-1)==100 && effectiveLimit(INT32_MAX)==0x50000000);
        WindowQueue q(100, 0, 3, 1000);
        check(q.submit({1, 70}, 0).action==Action::Send);
        check(q.submit({2, 30}, 500).action==Action::Send);
        check(q.submit({3, 60}, 1024).action==Action::Queued);
        check(q.deadline()==1025);
        check(q.submit({4, 60}, 1025).action==Action::Queued);
        check(q.poll(1024).empty());
        auto released=q.poll(1025);
        check(released.size()==2 && released[0].packet.id==3);
        check(released[0].action==Action::Send && released[1].action==Action::DropReplayExcess);
        check(q.queuedBytes()==0 && !q.deadline() && q.countedBytes()==60);
        // No timer: only an over-limit read resets an expired window.
        check(q.submit({5, 30}, 10000).action==Action::Send && q.countedBytes()==90);
        check(q.submit({6, 30}, 10000).action==Action::Send && q.countedBytes()==30);
        q.cancel(); q.restart(0);
        check(q.submit({7, 1000}, 0).action==Action::Send);
        check(q.submit({8, 1, true}, 0).action==Action::Queued);
        check(q.deadline()==1023);
        released=q.poll(1023);
        check(released.size()==1 && released[0].action==Action::Send && q.countedBytes()==0);
        check(q.submit({9, 100, true}, 1023).action==Action::Send && q.countedBytes()==0);
        check(q.submit({10, 100}, 1023).action==Action::Send);
        check(q.submit({11, 50}, 900).action==Action::Queued); // clock reversal
        check(q.deadline()==1923);
        check(q.submit({12, 50}, 900).action==Action::Queued);
        check(q.submit({13, 50}, 900).action==Action::Queued);
        check(q.submit({14, 50}, 900).action==Action::DropCapacity);
        released=q.cancel();
        check(released.size()==3 && released[0].action==Action::DropCancelled);
        check(q.poll(99999).empty() && q.submit({15, 1}, 99999).action==Action::DropStopped);
        q.restart(0);
        check(q.submit({16, 0}, 0).action==Action::DropInvalidPacket);
        check(q.submit({16, 65540}, 0).action==Action::DropInvalidPacket);
        WindowQueue bytes(100, 0, 3, 50);
        bytes.submit({1, 100},0);
        check(bytes.submit({2, 51},0).action==Action::DropCapacity && !bytes.deadline());
        check(bytes.submit({3, 50},0).action==Action::Queued);
        WindowQueue off(0, 0, 1, 1);
        for (int i=0;i<100;i++) check(off.submit({1,65539},0).action==Action::Send);
        check(off.queuedPackets()==0 && !off.deadline());
        WindowQueue edge(100, UINT64_MAX-100, 1, 100);
        edge.submit({1,100},UINT64_MAX-100);
        edge.submit({2,1},UINT64_MAX-100);
        check(edge.deadline()==UINT64_MAX && edge.poll(UINT64_MAX).size()==1);
        std::vector<std::uint8_t> probe(50,0);
        probe[4+9]=1;probe[4+3]=46;probe[4+20]=8;
        const char marker[]="Securelink";
        std::copy(marker,marker+10,probe.begin()+40);
        check(isCountExempt(probe.data(),probe.size(),true));
        check(!isCountExempt(probe.data(),49,true));
        probe[49]^=1;
        check(!isCountExempt(probe.data(),probe.size(),true));
        std::cout << "shaper core: passed\n";
    } catch (...) { std::cerr << "shaper core: failed\n";return 1; }
}
