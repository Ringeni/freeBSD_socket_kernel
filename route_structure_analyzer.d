#!/usr/sbin/dtrace -s

#pragma D option quiet
#pragma D option switchrate=10hz
#pragma D option bufsize=64m

dtrace:::BEGIN
{
    printf("========================================================\n");
    printf("=== FreeBSD route Structure Comprehensive Analyzer ===\n");
    printf("========================================================\n");
    printf("Start Time: %Y\n", walltimestamp);
    printf("Monitoring struct route usage (ip_output & ip6_output)\n\n");

    total_route_events = 0;
}

fbt::ip_output:entry
/arg2 != 0/
{
    this->ro = (struct route *)arg2;
    this->dummy = this->ro->ro_flags;

    printf(">>> ip_output:entry, PID %d (%s), Time: %Y\n", pid, execname, walltimestamp);
    printf("route 0x%p flags 0x%04x mtu %u plen %u dst_sa_family %u\n", this->ro, this->ro->ro_flags, this->ro->ro_mtu, this->ro->ro_plen, this->ro->ro_dst.sa_family);
    printf("nhop ptr 0x%p lle ptr 0x%p\n", this->ro->ro_nh, this->ro->ro_lle);
    if (this->ro->ro_nh != NULL) {
        printf("   nh_flags 0x%04x nh_mtu %u\n", this->ro->ro_nh->nh_flags, this->ro->ro_nh->nh_mtu);
    }
    if (this->ro->ro_lle != NULL) {
        printf("   lle_family %u lle_flags 0x%04x\n", this->ro->ro_lle->r_family, this->ro->ro_lle->r_flags);
    }
    total_route_events++;
}

fbt::ip6_output:entry
/arg2 != 0/
{
    this->ro = (struct route *)arg2;
    this->dummy = this->ro->ro_flags;

    printf(">>> ip6_output:entry, PID %d (%s), Time: %Y\n", pid, execname, walltimestamp);
    printf("route 0x%p flags 0x%04x mtu %u plen %u dst_sa_family %u\n", this->ro, this->ro->ro_flags, this->ro->ro_mtu, this->ro->ro_plen, this->ro->ro_dst.sa_family);
    printf("nhop ptr 0x%p lle ptr 0x%p\n", this->ro->ro_nh, this->ro->ro_lle);
    if (this->ro->ro_nh != NULL) {
        printf("   nh_flags 0x%04x nh_mtu %u\n", this->ro->ro_nh->nh_flags, this->ro->ro_nh->nh_mtu);
    }
    if (this->ro->ro_lle != NULL) {
        printf("   lle_family %u lle_flags 0x%04x\n", this->ro->ro_lle->r_family, this->ro->ro_lle->r_flags);
    }
    total_route_events++;
}

tick-30s
{
    printf("========================================================\n");
    printf("route events so far : %d\n", total_route_events);
    printf("Timestamp           : %Y\n", walltimestamp);
    printf("========================================================\n\n");
}

dtrace:::END
{
    printf("\n========================================================\n");
    printf("=== route STRUCTURE ANALYZER COMPLETE ===\n");
    printf("End Time: %Y\n", walltimestamp);
    printf("Total route events : %d\n", total_route_events);
    printf("========================================================\n");
} 