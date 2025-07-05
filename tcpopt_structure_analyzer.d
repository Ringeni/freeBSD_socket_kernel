#!/usr/sbin/dtrace -s

#pragma D option quiet
#pragma D option switchrate=10hz
#pragma D option bufsize=32m

dtrace:::BEGIN
{
    printf("====================================================\n");
    printf("=== tcpopt Structure Comprehensive Analyzer     ===\n");
    printf("====================================================\n");
    printf("Start Time: %Y\n", walltimestamp);
    total_tcpopt_events = 0;
}

fbt::tcp_dooptions:entry
/arg0 != 0/
{
    this->opt = (struct tcpopt *)arg0;
    printf("tcp_dooptions called with tcpopt 0x%p at %Y\n", this->opt, walltimestamp);
    printf("  to_flags       : 0x%08x\n", this->opt->to_flags);
    printf("  to_tsval       : %u\n", this->opt->to_tsval);
    printf("  to_tsecr       : %u\n", this->opt->to_tsecr);
    printf("  to_mss         : %u\n", this->opt->to_mss);
    printf("  to_wscale      : %u\n", this->opt->to_wscale);
    printf("  to_nsacks      : %u\n", this->opt->to_nsacks);
    printf("  to_tfo_len     : %u\n", this->opt->to_tfo_len);
    printf("  to_spare       : %u\n", this->opt->to_spare);
    printf("  ptrs ----------\n");
    printf("    to_sacks     : 0x%p\n", this->opt->to_sacks);
    printf("    to_signature : 0x%p\n", this->opt->to_signature);
    printf("    to_tfo_cookie: 0x%p\n", this->opt->to_tfo_cookie);
    printf("----------------------------------------------------\n\n");
    total_tcpopt_events++;
}

tick-30s
{
    printf("[tcpopt] events so far: %d  (Time %Y)\n", total_tcpopt_events, walltimestamp);
}

dtrace:::END
{
    printf("\n====================================================\n");
    printf("tcpopt analyzer complete. Total events: %d\n", total_tcpopt_events);
    printf("End Time: %Y\n", walltimestamp);
    printf("====================================================\n");
} 