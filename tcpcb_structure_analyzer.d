#!/usr/sbin/dtrace -s

#pragma D option quiet
#pragma D option switchrate=10hz
#pragma D option bufsize=128m
dtrace:::BEGIN
{
    printf("==============================================================\n");
    printf("=== FreeBSD tcpcb Structure Comprehensive Analyzer ===\n");
    printf("==============================================================\n");
    printf("Start Time: %Y\n", walltimestamp);
    printf("Specialized focus: Complete tcpcb Structure Analysis\n\n");

    total_tcpcb_events  = 0;
    tcpcb_creates       = 0;
    tcpcb_drops         = 0;
}

fbt::tcp_newtcpcb:return
/arg1 != 0/
{
    this->tp = (struct tcpcb *)arg1;
    printf("++++++++++ TCPCB CREATE ++++++++++\n");
    printf("Function: tcp_newtcpcb:return, PID %d (%s), Time: %Y\n", pid, execname, walltimestamp);
    printf("================ TCPCB STRUCTURE SNAPSHOT =================\n");
    printf("tcpcb address : 0x%p\n", this->tp);
    printf("t_state       : %d\n", this->tp->t_state);
    printf("snd_una       : %u\n", this->tp->snd_una);
    printf("snd_nxt       : %u\n", this->tp->snd_nxt);
    printf("snd_max       : %u\n", this->tp->snd_max);
    printf("snd_wnd       : %u\n", this->tp->snd_wnd);
    printf("snd_cwnd      : %u\n", this->tp->snd_cwnd);
    printf("rcv_nxt       : %u\n", this->tp->rcv_nxt);
    printf("rcv_wnd       : %u\n", this->tp->rcv_wnd);
    printf("t_srtt        : %d\n", this->tp->t_srtt);
    printf("t_rttvar      : %d\n", this->tp->t_rttvar);
    printf("t_rxtcur      : %d\n", this->tp->t_rxtcur);
    printf("t_flags       : 0x%08x\n", this->tp->t_flags);
    printf("t_flags2      : 0x%08x\n", this->tp->t_flags2);
    printf("t_fb          : 0x%p\n", this->tp->t_fb);
    printf("t_cc          : 0x%p\n", this->tp->t_cc);
    printf("sndbytes      : %lu\n", (unsigned long)this->tp->t_sndbytes);
    printf("retransbytes  : %lu\n", (unsigned long)this->tp->t_snd_rxt_bytes);
    printf("dsack bytes   : %lu\n", (unsigned long)this->tp->t_dsack_bytes);
    printf("===========================================================\n\n");
    tcpcb_creates++;
    total_tcpcb_events++;
}

fbt::tcp_*:entry
/arg0!= 0/
{
    this->tp = (struct tcpcb *)arg0;
    this->state = this->tp->t_state;

    printf("---------- TCPCB USAGE ----------\n");
    printf("Function: %s:entry, PID %d (%s), Time: %Y\n", probefunc, pid, execname, walltimestamp);
    printf("tcpcb 0x%p state %d, snd_nxt %u, rcv_nxt %u, cwnd %u\n", this->tp, this->tp->t_state, this->tp->snd_nxt, this->tp->rcv_nxt, this->tp->snd_cwnd);
    total_tcpcb_events++;
}
fbt::tcp_drop:entry
/arg0 != 0/
{
    this->tp = (struct tcpcb *)arg0;
    printf("********** TCPCB DROP **********\n");
    printf("Function: tcp_drop:entry, PID %d (%s), Time: %Y\n", pid, execname, walltimestamp);
    printf("tcpcb 0x%p state %d final drop, snd_una %u, snd_max %u, rcv_nxt %u\n", this->tp, this->tp->t_state, this->tp->snd_una, this->tp->snd_max, this->tp->rcv_nxt);
    tcpcb_drops++;
    total_tcpcb_events++;
}

tick-30s
{
    printf("==========================================================\n");
    printf("=== TCPCB STRUCTURE ANALYSIS SUMMARY ===\n");
    printf("Timestamp: %Y\n", walltimestamp);
    printf("----------------------------------------------------------\n");
    printf("Total tcpcb Events : %d\n", total_tcpcb_events);
    printf("tcpcb Creates      : %d\n", tcpcb_creates);
    printf("tcpcb Drops        : %d\n", tcpcb_drops);
    printf("==========================================================\n\n");
}

dtrace:::END
{
    printf("\n==========================================================\n");
    printf("=== TCPCB STRUCTURE ANALYZER COMPLETE ===\n");
    printf("End Time: %Y\n", walltimestamp);
    printf("==========================================================\n");
    printf("Total tcpcb Events : %d\n", total_tcpcb_events);
    printf("tcpcb Creates      : %d\n", tcpcb_creates);
    printf("tcpcb Drops        : %d\n", tcpcb_drops);
} 