#!/usr/sbin/dtrace -s

#pragma D option quiet
#pragma D option bufsize=64m
#pragma D option switchrate=10hz

dtrace:::BEGIN
{
        printf("================ socket_full_tracker.d START ================\n");
        printf("Start: %Y\n", walltimestamp);
}

dtrace:::END
{
        printf("\n================ socket_full_tracker.d END ==================\n");
        printf("End:   %Y\n", walltimestamp);
}

syscall::socket:entry
{
        printf("\n[syscall::socket:entry] %Y pid=%d (%s) domain=%d type=0x%x proto=%d\n",
            walltimestamp, pid, execname, arg0, arg1, arg2);
}

syscall::socket:return
{
        printf("[syscall::socket:return] %Y pid=%d fd=%d err=%d\n",
            walltimestamp, pid, (int)arg1, (int)arg0);
}

fbt::kern_socket:entry
{
        printf("\n[kern_socket] entry %Y td=0x%p domain=%d type=0x%x proto=%d\n",
            walltimestamp, arg0, arg1, arg2, arg3);
}

fbt::kern_socket:return
{
        printf("[kern_socket] return %Y ret=%d\n", walltimestamp, (int)arg1);
}

fbt::socreate:entry
{
        /* 2nd parameter of socreate is struct socket **aso (arg1) */
        self->aso = (struct socket **)arg1;
}

fbt::socreate:return
/self->aso != 0 && arg1 == 0/
{
        this->aso = (struct socket **)self->aso;
        self->aso = 0;

        this->so = *((struct socket **)this->aso);
        printf("\n[socreate] success %Y so=0x%p\n", walltimestamp, this->so);
        printf("  struct socket 0x%p {\n", this->so);
        printf("    so_type=%d so_state=0x%x so_options=0x%x\n",
            this->so->so_type, this->so->so_state, this->so->so_options);
        printf("    so_proto=0x%p so_pcb=0x%p so_cred=0x%p fib=%d\n",
            this->so->so_proto, this->so->so_pcb, this->so->so_cred, this->so->so_fibnum);
        printf("    so_rcv: hiwat=%u lowat=%u cc=%u flags=0x%x\n",
            (this->so->so_rcv).sb_hiwat, (this->so->so_rcv).sb_lowat, (this->so->so_rcv).sb_ccc, (this->so->so_rcv).sb_flags);
        printf("    so_snd: hiwat=%u lowat=%u cc=%u flags=0x%x\n",
            (this->so->so_snd).sb_hiwat, (this->so->so_snd).sb_lowat, (this->so->so_snd).sb_ccc, (this->so->so_snd).sb_flags);
        printf("  }\n");
}

fbt::tcp_usr_attach:entry
{
        this->so = (struct socket *)arg0;
        printf("\n[tcp_usr_attach] entry %Y so=0x%p proto=%d td=0x%p\n",
            walltimestamp, this->so, arg1, arg2);
        printf("  struct socket 0x%p {\n", this->so);
        printf("    so_type=%d so_state=0x%x so_options=0x%x\n",
            this->so->so_type, this->so->so_state, this->so->so_options);
        printf("    so_proto=0x%p so_pcb=0x%p so_cred=0x%p fib=%d\n",
            this->so->so_proto, this->so->so_pcb, this->so->so_cred, this->so->so_fibnum);
        printf("    so_rcv: hiwat=%u lowat=%u cc=%u flags=0x%x\n",
            (this->so->so_rcv).sb_hiwat, (this->so->so_rcv).sb_lowat, (this->so->so_rcv).sb_ccc, (this->so->so_rcv).sb_flags);
        printf("    so_snd: hiwat=%u lowat=%u cc=%u flags=0x%x\n",
            (this->so->so_snd).sb_hiwat, (this->so->so_snd).sb_lowat, (this->so->so_snd).sb_ccc, (this->so->so_snd).sb_flags);
        printf("  }\n");
}

fbt::in_pcballoc:entry
{
        self->so = (struct socket *)arg0;
}

fbt::in_pcballoc:return
/self->so != 0 && arg1 == 0/
{
        this->so  = (struct socket *)self->so;
        self->so  = 0;  

        this->inp = (struct inpcb *)this->so->so_pcb;
        printf("\n[in_pcballoc] success %Y so=0x%p inp=0x%p\n", walltimestamp, this->so, this->inp);
        printf("  struct inpcb 0x%p { flags=0x%x vflag=0x%x fib=%d\n",
            this->inp, this->inp->inp_flags, this->inp->inp_vflag, this->inp->inp_inc.inc_fibnum);
        printf("    laddr=%u.%u.%u.%u lport=%u faddr=%u.%u.%u.%u fport=%u\n",
            (this->inp->inp_inc.inc_ie.ie_dependladdr.id46_addr.ia46_addr4.s_addr >> 0) & 0xff,
            (this->inp->inp_inc.inc_ie.ie_dependladdr.id46_addr.ia46_addr4.s_addr >> 8) & 0xff,
            (this->inp->inp_inc.inc_ie.ie_dependladdr.id46_addr.ia46_addr4.s_addr >> 16) & 0xff,
            (this->inp->inp_inc.inc_ie.ie_dependladdr.id46_addr.ia46_addr4.s_addr >> 24) & 0xff,
            ntohs(this->inp->inp_inc.inc_ie.ie_lport),
            (this->inp->inp_inc.inc_ie.ie_dependfaddr.id46_addr.ia46_addr4.s_addr >> 0) & 0xff,
            (this->inp->inp_inc.inc_ie.ie_dependfaddr.id46_addr.ia46_addr4.s_addr >> 8) & 0xff,
            (this->inp->inp_inc.inc_ie.ie_dependfaddr.id46_addr.ia46_addr4.s_addr >> 16) & 0xff,
            (this->inp->inp_inc.inc_ie.ie_dependfaddr.id46_addr.ia46_addr4.s_addr >> 24) & 0xff,
            ntohs(this->inp->inp_inc.inc_ie.ie_fport));
        printf("    socket=0x%p pcbinfo=0x%p }\n", this->inp->inp_socket, this->inp->inp_pcbinfo);
}

fbt::tcp_newtcpcb:return
/arg1 != 0/
{
        this->tp = (struct tcpcb *)arg1;
        printf("\n[tcp_newtcpcb] success %Y tp=0x%p\n", walltimestamp, this->tp);
        printf("  struct tcpcb 0x%p { state=%d snd_cwnd=%u snd_ssthresh=%u rcv_nxt=%u snd_nxt=%u srtt=%u rttvar=%u flags=0x%x }\n",
            this->tp, this->tp->t_state, this->tp->snd_cwnd, this->tp->snd_ssthresh,
            this->tp->rcv_nxt, this->tp->snd_nxt, this->tp->t_srtt, this->tp->t_rttvar, this->tp->t_flags);
        printf("============================================================\n");
} 