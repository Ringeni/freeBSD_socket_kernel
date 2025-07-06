#!/usr/sbin/dtrace -s

#pragma D option quiet
#pragma D option bufsize=32m
#pragma D option switchrate=10hz

dtrace:::BEGIN
{
        printf("============================================================\n");
        printf("=== bind_field_tracker.d  (socket -> bind path)          ===\n");
        printf("============================================================\n");
        printf("Start: %Y\n", walltimestamp);
}

dtrace:::END
{
        printf("\n============================================================\n");
        printf("End:   %Y\n", walltimestamp);
}

fbt::sys_bind:entry
{
        printf("\n[sys_bind] %Y\n", walltimestamp);
        printf("  td=0x%p uap=0x%p\n", arg0, arg1);
        this->uap = (struct bind_args *)arg1;
        printf("  bind_args: s=%d name=0x%p namelen=%u\n", this->uap->s, this->uap->name, this->uap->namelen);
}

fbt::kern_bindat:entry
{
        printf("\n[kern_bindat] %Y\n", walltimestamp);
        printf("  td=0x%p dirfd=%d fd=%d sa=0x%p\n", arg0, (int)arg1, (int)arg2, arg3);
}

fbt::sobind:entry
{
        printf("\n[sobind] %Y\n", walltimestamp);
        this->so = (struct socket *)arg0;
        printf("  so=0x%p nam=0x%p\n", this->so, arg1);
        printf("    so_type=%d so_state=0x%x so_options=0x%x\n",
               this->so->so_type, this->so->so_state, this->so->so_options);
        printf("    so_pcb=0x%p proto=0x%p\n", this->so->so_pcb, this->so->so_proto);
}

fbt::tcp_usr_bind:entry
{
        printf("\n[tcp_usr_bind] %Y\n", walltimestamp);
        this->so = (struct socket *)arg0;
        printf("  so=0x%p nam=0x%p td=0x%p\n", this->so, arg1, arg2);

        printf("  struct socket { type=%d state=0x%x options=0x%x rcv.sb_hiwat=%u snd.sb_hiwat=%u }\n",
               this->so->so_type, this->so->so_state, this->so->so_options,
               this->so->so_rcv.sb_hiwat, this->so->so_snd.sb_hiwat);

        this->inp = (struct inpcb *)this->so->so_pcb;
        printf("  struct inpcb 0x%p {\n", this->inp);
        this->laddr = this->inp->inp_inc.inc_ie.ie_dependladdr.id46_addr.ia46_addr4.s_addr;
        this->faddr = this->inp->inp_inc.inc_ie.ie_dependfaddr.id46_addr.ia46_addr4.s_addr;
        printf("    laddr=%u.%u.%u.%u lport=%u faddr=%u.%u.%u.%u fport=%u\n",
               (this->laddr >> 0) & 0xff,
               (this->laddr >> 8) & 0xff,
               (this->laddr >> 16) & 0xff,
               (this->laddr >> 24) & 0xff,
               ntohs(this->inp->inp_inc.inc_ie.ie_lport),
               (this->faddr >> 0) & 0xff,
               (this->faddr >> 8) & 0xff,
               (this->faddr >> 16) & 0xff,
               (this->faddr >> 24) & 0xff,
               ntohs(this->inp->inp_inc.inc_ie.ie_fport));
        printf("    flags=0x%x vflag=0x%x fib=%d\n",
               this->inp->inp_flags, this->inp->inp_vflag, this->inp->inp_inc.inc_fibnum);
        printf("    so=0x%p pcbinfo=0x%p tcb=0x%p }\n",this->inp->inp_socket, this->inp->inp_pcbinfo, this->inp->inp_ppcb);

        this->tp = (struct tcpcb *)this->inp->inp_ppcb;
        if (this->tp != 0) {
                printf("    struct tcpcb 0x%p { state=%d snd_una=%u snd_nxt=%u rcv_nxt=%u t_flags=0x%x }\n",
                       this->tp, this->tp->t_state, this->tp->snd_una, this->tp->snd_nxt,
                       this->tp->rcv_nxt, this->tp->t_flags);
        }
}

fbt::in_pcbbind:entry
{
        printf("\n[in_pcbbind] entry %Y\n", walltimestamp);
        this->inp = (struct inpcb *)arg0;
        this->sin = (struct sockaddr_in *)arg1;
        printf("  inp=0x%p sin=0x%p flags=0x%x\n", this->inp, this->sin, (int)arg2);
        this->laddr_b = this->inp->inp_inc.inc_ie.ie_dependladdr.id46_addr.ia46_addr4.s_addr;
        printf("  BEFORE: laddr=%u.%u.%u.%u lport=%u flags=0x%x\n",
               (this->laddr_b >> 0) & 0xff,
               (this->laddr_b >> 8) & 0xff,
               (this->laddr_b >> 16) & 0xff,
               (this->laddr_b >> 24) & 0xff,
               ntohs(this->inp->inp_inc.inc_ie.ie_lport), this->inp->inp_flags);
}

fbt::in_pcbbind:return
/arg1 == 0/
{
        printf("  AFTER:  ret=%d laddr=%u.%u.%u.%u lport=%u flags=0x%x\n",
               (int)arg1,
               ((((struct inpcb *)arg0)->inp_inc.inc_ie.ie_dependladdr.id46_addr.ia46_addr4.s_addr >> 0) & 0xff),
               ((((struct inpcb *)arg0)->inp_inc.inc_ie.ie_dependladdr.id46_addr.ia46_addr4.s_addr >> 8) & 0xff),
               ((((struct inpcb *)arg0)->inp_inc.inc_ie.ie_dependladdr.id46_addr.ia46_addr4.s_addr >> 16) & 0xff),
               ((((struct inpcb *)arg0)->inp_inc.inc_ie.ie_dependladdr.id46_addr.ia46_addr4.s_addr >> 24) & 0xff),
               ntohs(((struct inpcb *)arg0)->inp_inc.inc_ie.ie_lport),
               ((struct inpcb *)arg0)->inp_flags);
}

fbt::in_pcb_lport:return
{
        printf("\n[in_pcb_lport] ret=%d chosen_port=%u\n", (int)arg1, ntohs(*(u_short *)copyin(arg2, sizeof(u_short))));
}
