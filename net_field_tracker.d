#!/usr/sbin/dtrace -s

#pragma D option quiet
#pragma D option bufsize=32m
#pragma D option switchrate=10hz

dtrace:::BEGIN
{
        printf("============================================================\n");
        printf("=== net_field_tracker.d  (MSS/PMTU/GW/IPID/TTL)         ===\n");
        printf("============================================================\n");
        printf("Start: %Y\n", walltimestamp);
}

dtrace:::END
{
        printf("\n============================================================\n");
        printf("End:   %Y\n", walltimestamp);
}

fbt::tcp_mss_update:entry
{
        printf("\n[tcp_mss_update] %Y\n", walltimestamp);
        printf("  args: tp=0x%p offer=%d mtuoffer=%d metrics=0x%p cap=0x%p\n", arg0, (int)arg1, (int)arg2, arg3, arg4);

        this->tp   = (struct tcpcb *)arg0;
        this->inp  = &(this->tp->t_inpcb);
        this->ro   = &(this->inp->inp_route);
        this->nh   = this->ro->ro_nh;

        printf("  tcpcb 0x%p state=%u maxseg=%u cwnd=%u ssthresh=%u\n", this->tp, this->tp->t_state, this->tp->t_maxseg, this->tp->snd_cwnd, this->tp->snd_ssthresh);

        printf("    inpcb 0x%p ttl=%u flags=0x%x route=0x%p\n", this->inp, this->inp->inp_ip_ttl, this->inp->inp_flags, this->ro);

        printf("      route 0x%p flags=0x%x mtu=%u dst.family=%u nh=0x%p\n", this->ro, this->ro->ro_flags, this->ro->ro_mtu, this->ro->ro_dst.sa_family, this->nh);

        /* Guard pointer before deref */
        if (this->nh != 0) {
                printf("        nhop 0x%p flags=0x%x mtu=%u ifp=0x%p aifp=0x%p family=%u\n", this->nh, this->nh->nh_flags, this->nh->nh_mtu, this->nh->nh_ifp, this->nh->nh_aifp, this->nh->gw_sa.sa_family);
        }
}

fbt::tcp_mtudisc:entry
{
        printf("\n[tcp_mtudisc] %Y\n", walltimestamp);
        printf("  args: inp=0x%p mtuoffer/error=%d\n", arg0, (int)arg1);

        this->inp = (struct inpcb *)arg0;
        this->ro  = &(this->inp->inp_route);
        this->nh  = this->ro->ro_nh;

        printf("    inpcb 0x%p ttl=%u flags=0x%x route=0x%p\n", this->inp, this->inp->inp_ip_ttl, this->inp->inp_flags, this->ro);
        printf("      route 0x%p flags=0x%x mtu=%u dst.family=%u nh=0x%p\n", this->ro, this->ro->ro_flags, this->ro->ro_mtu, this->ro->ro_dst.sa_family, this->nh);
        if (this->nh != 0) {
                printf("        nhop 0x%p flags=0x%x mtu=%u ifp=0x%p aifp=0x%p family=%u\n", this->nh, this->nh->nh_flags, this->nh->nh_mtu, this->nh->nh_ifp, this->nh->nh_aifp, this->nh->gw_sa.sa_family);
        }
}

fbt::ip_output:entry
{
        printf("\n[ip_output] %Y\n", walltimestamp);
        printf("  args: m=0x%p opt=0x%p route=0x%p flags=0x%x\n", arg0, arg1, arg2, (uint32_t)arg3);

        /* IPv4 header in first mbuf */
        this->ip = (struct ip *)((struct mbuf *)arg0)->m_data;
        printf("    struct ip 0x%p id=%u ttl=%u len=%u off=0x%x tos=0x%x v=%d hl=%d src=0x%x dst=0x%x proto=%u sum=0x%x\n", this->ip, this->ip->ip_id, this->ip->ip_ttl, this->ip->ip_len, this->ip->ip_off, this->ip->ip_tos, this->ip->ip_v, this->ip->ip_hl, this->ip->ip_src.s_addr, this->ip->ip_dst.s_addr, this->ip->ip_p, this->ip->ip_sum);

        /* Route / nhop if supplied */
        this->ro = (struct route *)arg2;
        if (this->ro != 0) {
                this->nh = this->ro->ro_nh;
                printf("    route 0x%p flags=0x%x mtu=%u dst.family=%u nh=0x%p\n", this->ro, this->ro->ro_flags, this->ro->ro_mtu, this->ro->ro_dst.sa_family, this->nh);
                if (this->nh != 0) {
                        printf("      nhop 0x%p flags=0x%x mtu=%u ifp=0x%p aifp=0x%p family=%u\n", this->nh, this->nh->nh_flags, this->nh->nh_mtu, this->nh->nh_ifp, this->nh->nh_aifp, this->nh->gw_sa.sa_family);
                }
        }
}

fbt::ip_forward:entry
{
        printf("\n[ip_forward] %Y\n", walltimestamp);
        printf("  args: m=0x%p srcrt=%d\n", arg0, (int)arg1);
        this->ip = (struct ip *)((struct mbuf *)arg0)->m_data;
        printf("    struct ip 0x%p id=%u ttl=%u len=%u off=0x%x tos=0x%x v=%d hl=%d src=0x%x dst=0x%x proto=%u sum=0x%x\n", this->ip, this->ip->ip_id, this->ip->ip_ttl, this->ip->ip_len, this->ip->ip_off, this->ip->ip_tos, this->ip->ip_v, this->ip->ip_hl, this->ip->ip_src.s_addr, this->ip->ip_dst.s_addr, this->ip->ip_p, this->ip->ip_sum);
}

fbt::ip_fillid:entry
{
        printf("\n[ip_fillid] %Y (assign IPID)\n", walltimestamp);
        printf("  args: ip=0x%p do_random=%d\n", arg0, (int)arg1);
        this->ip = (struct ip *)arg0;
        printf("    struct ip 0x%p id=%u ttl=%u len=%u off=0x%x tos=0x%x src=0x%x dst=0x%x\n", this->ip, this->ip->ip_id, this->ip->ip_ttl, this->ip->ip_len, this->ip->ip_off, this->ip->ip_tos, this->ip->ip_src.s_addr, this->ip->ip_dst.s_addr);
}

fbt::nhop_set_mtu:entry
{
        printf("\n[nhop_set_mtu] %Y\n", walltimestamp);
        printf("  args: nh=0x%p mtu=%u from_user=%d\n", arg0, (uint32_t)arg1, (int)arg2);
        this->nh = (struct nhop_object *)arg0;
        printf("    nhop 0x%p flags=0x%x mtu=%u ifp=0x%p aifp=0x%p family=%u\n", this->nh, this->nh->nh_flags, this->nh->nh_mtu, this->nh->nh_ifp, this->nh->nh_aifp, this->nh->gw_sa.sa_family);
}

fbt::nhop_set_gw:entry
{
        printf("\n[nhop_set_gw] %Y\n", walltimestamp);
        printf("  args: nh=0x%p sa=0x%p is_gw=%d\n", arg0, arg1, (int)arg2);
        this->nh = (struct nhop_object *)arg0;
        printf("    nhop 0x%p flags=0x%x mtu=%u ifp=0x%p aifp=0x%p family=%u\n", this->nh, this->nh->nh_flags, this->nh->nh_mtu, this->nh->nh_ifp, this->nh->nh_aifp, this->nh->gw_sa.sa_family);
} 