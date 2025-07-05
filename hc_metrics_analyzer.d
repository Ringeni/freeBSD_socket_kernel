#!/usr/sbin/dtrace -s

#pragma D option quiet
#pragma D option switchrate=10hz
#pragma D option bufsize=32m


dtrace:::BEGIN
{
    printf("====================================================\n");
    printf("=== hc_metrics_lite Analyzer (tcp_hc_get)        ===\n");
    printf("====================================================\n");
    printf("Start Time: %Y\n", walltimestamp);
    total_hc_events = 0;
}

fbt::tcp_hc_get:entry
/arg1 != 0/
{
    this->hc = (struct hc_metrics_lite *)arg1;
    printf("hc_metrics_lite ptr 0x%p at %Y\n", this->hc, walltimestamp);
    printf("  hc_mtu       : %u\n", *(((uint32_t *)this->hc) + 0));
    printf("  hc_ssthresh  : %u\n", *(((uint32_t *)this->hc) + 1));
    printf("  hc_rtt       : %u\n", *(((uint32_t *)this->hc) + 2));
    printf("  hc_rttvar    : %u\n", *(((uint32_t *)this->hc) + 3));
    printf("  hc_cwnd      : %u\n", *(((uint32_t *)this->hc) + 4));
    printf("  hc_sendpipe  : %u\n", *(((uint32_t *)this->hc) + 5));
    printf("  hc_recvpipe  : %u\n", *(((uint32_t *)this->hc) + 6));
    printf("----------------------------------------------------\n\n");
    total_hc_events++;
}

tick-30s
{
    printf("[hc_metrics] events so far: %d  (Time %Y)\n", total_hc_events, walltimestamp);
}

dtrace:::END
{
    printf("\n====================================================\n");
    printf("hc_metrics analyzer complete. Total events: %d\n", total_hc_events);
    printf("End Time: %Y\n", walltimestamp);
    printf("====================================================\n");
} 