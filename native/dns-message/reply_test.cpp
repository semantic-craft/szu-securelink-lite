#include "reply.hpp"
#include <cassert>
#include <cstdio>
using Bytes = std::vector<std::uint8_t>;
void word(Bytes &b, unsigned v) { b.push_back(v >> 8); b.push_back(v); }
Bytes name(const std::string &n) { Bytes b; std::size_t start=0; for (;;) { auto end=n.find('.',start); if(end==std::string::npos)end=n.size(); b.push_back(end-start); b.insert(b.end(),n.begin()+start,n.begin()+end); if(end==n.size())break; start=end+1; } b.push_back(0);return b; }
Bytes base(unsigned answers, unsigned additional=0) {
 Bytes b; for(auto v:{42u,0x8180u,1u,answers,0u,additional})word(b,v);
 auto n=name("service.example");b.insert(b.end(),n.begin(),n.end());word(b,1);word(b,1);return b;
}
void rr(Bytes &b, const Bytes &owner, unsigned type, unsigned ttl, const Bytes &data) {
 b.insert(b.end(),owner.begin(),owner.end());word(b,type);word(b,1);word(b,ttl>>16);word(b,ttl);word(b,data.size());b.insert(b.end(),data.begin(),data.end());
}
bool bad(const Bytes &b, securelink::dns::Question q={42,"service.example",1}) {
 try { (void)securelink::dns::parse(b.data(),b.size(),q);return false; } catch(const securelink::dns::Invalid&){return true;}
}
int main(){
 const securelink::dns::Question q{42,"SERVICE.example.",1};
 auto b=base(1,1); rr(b,{0xc0,12},1,60,{192,0,2,1}); rr(b,name("unrelated.example"),1,60,{192,0,2,99});
 auto r=securelink::dns::parse(b.data(),b.size(),q);assert(r.addresses.size()==1 && r.addresses[0].ttl==60 && r.addresses[0].bytes[3]==1);
 assert(bad(b,{43,"service.example",1}));assert(bad(b,{42,"other.example",1}));assert(bad(b,{42,"service.example",28}));
 auto alias=base(2);rr(alias,{0xc0,12},5,10,name("target.example"));rr(alias,name("target.example"),1,60,{192,0,2,2});
 r=securelink::dns::parse(alias.data(),alias.size(),q);assert(r.addresses.size()==1 && r.addresses[0].ttl==10);
 auto loop=base(1);rr(loop,{0xc0,12},5,10,{0xc0,12});assert(bad(loop));
 auto conflict=base(2);rr(conflict,{0xc0,12},5,10,name("target.example"));rr(conflict,{0xc0,12},1,10,{192,0,2,3});assert(bad(conflict));
 auto poison=base(1);rr(poison,name("unrelated.example"),1,10,{192,0,2,3});assert(securelink::dns::parse(poison.data(),poison.size(),q).addresses.empty());
 auto zero=base(1);rr(zero,{0xc0,12},1,0,{192,0,2,1});assert(securelink::dns::parse(zero.data(),zero.size(),q).addresses[0].ttl==0);
 auto shortA=base(1);rr(shortA,{0xc0,12},1,10,{192,0,2});assert(bad(shortA));
 auto ptr=base(1);rr(ptr,{0xff,0xff},1,10,{192,0,2,1});assert(bad(ptr));
 for(std::size_t i=0;i<b.size();++i){Bytes prefix(b.begin(),b.begin()+i);assert(bad(prefix));}
 auto truncated=b;truncated[2]|=2;r=securelink::dns::parse(truncated.data(),truncated.size(),q);assert(r.truncated && r.addresses.empty());
 auto refused=b;refused[3]=0x85;r=securelink::dns::parse(refused.data(),refused.size(),q);assert(r.rcode==5 && r.addresses.empty());
 auto ipv6=base(1);ipv6[ipv6.size()-3]=28;Bytes address(16);address[0]=0x20;address[1]=1;address[15]=1;rr(ipv6,{0xc0,12},28,30,address);
 r=securelink::dns::parse(ipv6.data(),ipv6.size(),{42,"service.example",28});assert(r.addresses.size()==1 && r.addresses[0].type==28 && r.addresses[0].bytes[15]==1);
 auto count=base(257);assert(bad(count));
 // RFC 2181 lifetime normalization applies to aliases and the whole RRset.
 auto high=base(1);rr(high,{0xc0,12},1,0x80000001u,{192,0,2,1});
 assert(securelink::dns::parse(high.data(),high.size(),q).addresses[0].ttl==0);
 auto mixed=base(2);rr(mixed,{0xc0,12},1,600,{192,0,2,1});rr(mixed,{0xc0,12},1,5,{192,0,2,2});
 r=securelink::dns::parse(mixed.data(),mixed.size(),q);assert(r.addresses.size()==2 && r.addresses[0].ttl==5 && r.addresses[1].ttl==5);
 auto highAlias=base(2);rr(highAlias,{0xc0,12},5,0xffffffffu,name("target.example"));rr(highAlias,name("target.example"),1,60,{192,0,2,2});
 assert(securelink::dns::parse(highAlias.data(),highAlias.size(),q).addresses[0].ttl==0);
 auto otherType=base(3);rr(otherType,{0xc0,12},5,10,name("target.example"));rr(otherType,{0xc0,12},28,10,Bytes(16));rr(otherType,name("target.example"),1,10,{192,0,2,1});assert(bad(otherType));
 // Same-owner additional data must not extend the resolved answer RRset.
 auto extra=base(1,1);rr(extra,{0xc0,12},1,10,{192,0,2,1});rr(extra,{0xc0,12},1,999,{192,0,2,99});
 r=securelink::dns::parse(extra.data(),extra.size(),q);assert(r.addresses.size()==1 && r.addresses[0].bytes[3]==1);
 // EDNS uses its pseudo-TTL as extended RCODE; BADVERS must not yield routes.
 auto edns=base(1,1);rr(edns,{0xc0,12},1,10,{192,0,2,1});rr(edns,{0},41,0x01000000u,{});
 r=securelink::dns::parse(edns.data(),edns.size(),q);assert(r.rcode==16 && r.addresses.empty());
 auto okayOpt=base(1,1);rr(okayOpt,{0xc0,12},1,10,{192,0,2,1});rr(okayOpt,{0},41,0x8000,{0,12,0,2,0,0});
 assert(securelink::dns::parse(okayOpt.data(),okayOpt.size(),q).addresses.size()==1);
 auto twoOpt=base(0,2);rr(twoOpt,{0},41,0,{});rr(twoOpt,{0},41,0,{});assert(bad(twoOpt));
 auto misplaced=base(1);rr(misplaced,{0},41,0,{});assert(bad(misplaced));
 auto namedOpt=base(0,1);rr(namedOpt,{0xc0,12},41,0,{});assert(bad(namedOpt));
 auto version=base(0,1);rr(version,{0},41,0x10000,{});assert(bad(version));
 for (auto data : {Bytes{0},Bytes{0,12,0,3,0}}) {auto opt=base(0,1);rr(opt,{0},41,0,data);assert(bad(opt));}
 auto z=b;z[3]|=0x40;assert(bad(z));
 auto wrongQR=b;wrongQR[2]&=0x7f;assert(bad(wrongQR));
 auto wrongOpcode=b;wrongOpcode[2]|=0x08;assert(bad(wrongOpcode));
 auto cnameJunk=base(1);auto target=name("target.example");target.push_back(0);rr(cnameJunk,{0xc0,12},5,1,target);assert(bad(cnameJunk));
 auto cnamePointerLoop=base(1);auto at=cnamePointerLoop.size()+12;rr(cnamePointerLoop,{0xc0,12},5,1,{static_cast<std::uint8_t>(0xc0|(at>>8)),static_cast<std::uint8_t>(at)});assert(bad(cnamePointerLoop));
 auto invalidAdditional=base(1,1);rr(invalidAdditional,{0xc0,12},1,10,{192,0,2,1});auto position=invalidAdditional.size();rr(invalidAdditional,{static_cast<std::uint8_t>(0xc0|(position>>8)),static_cast<std::uint8_t>(position)},1,10,{192,0,2,2});assert(bad(invalidAdditional));
 auto trailing=b;trailing.push_back(0);assert(bad(trailing));
 std::puts("DNS reply parser: passed");
}
