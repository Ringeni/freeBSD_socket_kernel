#!/usr/sbin/dtrace -s

#pragma D option quiet
#pragma D option switchrate=10hz
#pragma D option bufsize=64m


dtrace:::BEGIN
{
    printf("========================================================\n");
    printf("=== FreeBSD ifnet Structure Comprehensive Analyzer ===\n");
    printf("========================================================\n");
    printf("Start Time: %Y\n", walltimestamp);
    printf("Probes: if_attach, ether_output_frame, if_up, if_down\n\n");

    total_ifnet_events = 0;
}

fbt::if_attach:entry
/arg0 != 0/
{
    this->ifp = (struct ifnet *)arg0;
    printf("+++ if_attach:entry, PID %d (%s), Time: %Y\n", pid, execname, walltimestamp);
    printf("ifnet 0x%p xname %s index %u type %u\n", this->ifp, stringof(this->ifp->if_xname), this->ifp->if_index, this->ifp->if_type);
    printf("flags 0x%08x drv_flags 0x%08x mtu %u link_state %u\n", this->ifp->if_flags, this->ifp->if_drv_flags, this->ifp->if_mtu, this->ifp->if_link_state);
    printf("capenable 0x%08x baudrate %lu\n", this->ifp->if_capenable, (unsigned long)this->ifp->if_baudrate);
    printf("softc 0x%p l2com 0x%p hw_addr 0x%p\n", this->ifp->if_softc, this->ifp->if_l2com, this->ifp->if_hw_addr);
    printf("if_addr ptr 0x%p\n", this->ifp->if_addr);
    /* Nested ifaddr */
    if (this->ifp->if_addr != NULL && this->ifp->if_addr->ifa_addr != NULL) {
        printf("  ifa_addr sa_family %u\n", this->ifp->if_addr->ifa_addr->sa_family);
    }
    total_ifnet_events++;
}

fbt::ether_output_frame:entry
/arg0 != 0/
{
    this->ifp = (struct ifnet *)arg0;
    printf(">>> ether_output_frame:entry, PID %d (%s), Time: %Y\n", pid, execname, walltimestamp);
    printf("ifnet 0x%p name %s idx %u mtu %u flags 0x%08x\n", this->ifp, stringof(this->ifp->if_xname), this->ifp->if_index, this->ifp->if_mtu, this->ifp->if_flags);
    printf("link_state %u hwassist 0x%lx tsomax %u\n", this->ifp->if_link_state, (unsigned long)this->ifp->if_hwassist, this->ifp->if_hw_tsomax);
    total_ifnet_events++;
}

fbt::if_up:entry
/arg0 != 0/
{
    this->ifp = (struct ifnet *)arg0;
    printf("*** if_up:entry, PID %d (%s), Time: %Y\n", pid, execname, walltimestamp);
    printf("ifnet 0x%p name %s flags 0x%08x -> going UP\n", this->ifp, stringof(this->ifp->if_xname), this->ifp->if_flags);
    total_ifnet_events++;
}

fbt::if_down:entry
/arg0 != 0/
{
    this->ifp = (struct ifnet *)arg0;
    printf("*** if_down:entry, PID %d (%s), Time: %Y\n", pid, execname, walltimestamp);
    printf("ifnet 0x%p name %s flags 0x%08x -> going DOWN\n", this->ifp, stringof(this->ifp->if_xname), this->ifp->if_flags);
    total_ifnet_events++;
}

tick-30s
{
    printf("========================================================\n");
    printf("ifnet events so far : %d\n", total_ifnet_events);
    printf("Timestamp           : %Y\n", walltimestamp);
    printf("========================================================\n\n");
}

dtrace:::END
{
    printf("\n========================================================\n");
    printf("=== ifnet STRUCTURE ANALYZER COMPLETE ===\n");
    printf("End Time: %Y\n", walltimestamp);
    printf("Total ifnet events : %d\n", total_ifnet_events);
    printf("========================================================\n");
} 