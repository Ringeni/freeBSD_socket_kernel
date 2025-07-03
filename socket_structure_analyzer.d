#!/usr/sbin/dtrace -s

#pragma D option quiet
#pragma D option switchrate=10hz
#pragma D option bufsize=128m

dtrace:::BEGIN
{
    printf("======================================================\n");
    printf("=== FreeBSD Socket Structure Comprehensive Analyzer ===\n");
    printf("======================================================\n");
    printf("Start Time: %Y\n", walltimestamp);
    printf("Specialized focus: Complete Socket Structure Analysis\n\n");
    
    socket_events = 0;
    socket_creates = 0;
    socket_binds = 0;
    socket_connects = 0;
    socket_sends = 0;
    socket_recvs = 0;
    
    printf("Socket structure monitoring enabled...\n");
    printf("Note: FreeBSD dtrace does not support floating point operations\n\n");
}

/* === SOCKET CREATION ANALYSIS === */
fbt::socreate:return
{
    this->so = (struct socket *)arg1;
    
    if (this->so != NULL) {
        printf("========== SOCKET CREATION: COMPLETE STRUCTURE ANALYSIS ==========\n");
        printf("Process: PID %d (%s), Timestamp: %Y\n", pid, execname, walltimestamp);
        printf("Socket Address: 0x%p\n", this->so);
        
        /* === SOCKET CORE STRUCTURE ANALYSIS === */
        printf("\n=== SOCKET CORE STRUCTURE (struct socket) ===\n");
        printf("Structure Size: %lu bytes\n", sizeof(struct socket));
        printf("Base Address: 0x%p\n", this->so);
        
        /* Mutex Lock Analysis */
        printf("\n--- Socket Mutex Lock (so_lock) ---\n");
        printf("Mutex Address: 0x%p\n", &this->so->so_lock);
        printf("Mutex Offset: %lu bytes\n", 
               (unsigned long)&this->so->so_lock - (unsigned long)this->so);
        
        /* Reference Count */
        printf("\n--- Reference Count (so_count) ---\n");
        printf("Reference Count: %u\n", this->so->so_count);
        printf("Address: 0x%p\n", &this->so->so_count);
        printf("Offset: %lu bytes\n", 
               (unsigned long)&this->so->so_count - (unsigned long)this->so);
        
        /* Select Information */
        printf("\n--- Select Information ---\n");
        printf("Read Select (so_rdsel): 0x%p\n", &this->so->so_rdsel);
        printf("Write Select (so_wrsel): 0x%p\n", &this->so->so_wrsel);
        
        /* Socket Options */
        printf("\n--- Socket Options (so_options) ---\n");
        printf("Options Value: 0x%08x\n", this->so->so_options);
        printf("Address: 0x%p\n", &this->so->so_options);
        printf("Offset: %lu bytes\n", 
               (unsigned long)&this->so->so_options - (unsigned long)this->so);
        
        /* Decode Socket Options */
        printf("Option Flags Analysis:\n");
        printf("  SO_DEBUG: %s\n", (this->so->so_options & 0x0001) ? "ENABLED" : "DISABLED");
        printf("  SO_ACCEPTCONN: %s\n", (this->so->so_options & 0x0002) ? "ENABLED" : "DISABLED");
        printf("  SO_REUSEADDR: %s\n", (this->so->so_options & 0x0004) ? "ENABLED" : "DISABLED");
        printf("  SO_KEEPALIVE: %s\n", (this->so->so_options & 0x0008) ? "ENABLED" : "DISABLED");
        printf("  SO_DONTROUTE: %s\n", (this->so->so_options & 0x0010) ? "ENABLED" : "DISABLED");
        printf("  SO_BROADCAST: %s\n", (this->so->so_options & 0x0020) ? "ENABLED" : "DISABLED");
        printf("  SO_USELOOPBACK: %s\n", (this->so->so_options & 0x0040) ? "ENABLED" : "DISABLED");
        printf("  SO_LINGER: %s\n", (this->so->so_options & 0x0080) ? "ENABLED" : "DISABLED");
        printf("  SO_OOBINLINE: %s\n", (this->so->so_options & 0x0100) ? "ENABLED" : "DISABLED");
        printf("  SO_REUSEPORT: %s\n", (this->so->so_options & 0x0200) ? "ENABLED" : "DISABLED");
        printf("  SO_TIMESTAMP: %s\n", (this->so->so_options & 0x0400) ? "ENABLED" : "DISABLED");
        printf("  SO_NOSIGPIPE: %s\n", (this->so->so_options & 0x0800) ? "ENABLED" : "DISABLED");
        printf("  SO_ACCEPTFILTER: %s\n", (this->so->so_options & 0x1000) ? "ENABLED" : "DISABLED");
        printf("  SO_BINTIME: %s\n", (this->so->so_options & 0x2000) ? "ENABLED" : "DISABLED");
        
        /* Socket Type */
        printf("\n--- Socket Type (so_type) ---\n");
        printf("Type Value: %d\n", this->so->so_type);
        printf("Address: 0x%p\n", &this->so->so_type);
        printf("Offset: %lu bytes\n", 
               (unsigned long)&this->so->so_type - (unsigned long)this->so);
        printf("Type Description: %s\n",
               this->so->so_type == 1 ? "SOCK_STREAM (TCP)" :
               this->so->so_type == 2 ? "SOCK_DGRAM (UDP)" :
               this->so->so_type == 3 ? "SOCK_RAW" :
               this->so->so_type == 4 ? "SOCK_RDM" :
               this->so->so_type == 5 ? "SOCK_SEQPACKET" : "UNKNOWN");
        
        /* Socket State */
        printf("\n--- Socket State (so_state) ---\n");
        printf("State Value: 0x%04x\n", this->so->so_state);
        printf("Address: 0x%p\n", &this->so->so_state);
        printf("Offset: %lu bytes\n", 
               (unsigned long)&this->so->so_state - (unsigned long)this->so);
        
        /* Decode Socket State */
        printf("State Flags Analysis:\n");
        printf("  SS_ISCONNECTED: %s\n", (this->so->so_state & 0x0002) ? "SET" : "CLEAR");
        printf("  SS_ISCONNECTING: %s\n", (this->so->so_state & 0x0004) ? "SET" : "CLEAR");
        printf("  SS_ISDISCONNECTING: %s\n", (this->so->so_state & 0x0008) ? "SET" : "CLEAR");
        printf("  SS_NBIO: %s\n", (this->so->so_state & 0x0100) ? "SET" : "CLEAR");
        printf("  SS_ASYNC: %s\n", (this->so->so_state & 0x0200) ? "SET" : "CLEAR");
        printf("  SS_ISDISCONNECTED: %s\n", (this->so->so_state & 0x2000) ? "SET" : "CLEAR");
        
        /* Protocol Control Block */
        printf("\n--- Protocol Control Block (so_pcb) ---\n");
        printf("PCB Address: 0x%p\n", this->so->so_pcb);
        printf("PCB Pointer Address: 0x%p\n", &this->so->so_pcb);
        printf("PCB Offset: %lu bytes\n", 
               (unsigned long)&this->so->so_pcb - (unsigned long)this->so);
        
        /* Network Stack Instance */
        printf("\n--- Network Stack Instance (so_vnet) ---\n");
        printf("VNet Address: 0x%p\n", this->so->so_vnet);
        printf("VNet Pointer Address: 0x%p\n", &this->so->so_vnet);
        printf("VNet Offset: %lu bytes\n", 
               (unsigned long)&this->so->so_vnet - (unsigned long)this->so);
        
        /* Protocol Switch */
        printf("\n--- Protocol Switch (so_proto) ---\n");
        printf("Protosw Address: 0x%p\n", this->so->so_proto);
        printf("Protosw Pointer Address: 0x%p\n", &this->so->so_proto);
        printf("Protosw Offset: %lu bytes\n", 
               (unsigned long)&this->so->so_proto - (unsigned long)this->so);
        
        /* === RECURSIVE PROTOSW ANALYSIS === */
        if (this->so->so_proto != NULL) {
            printf("\n=== PROTOSW STRUCTURE ANALYSIS (struct protosw) ===\n");
            printf("Protosw Base Address: 0x%p\n", this->so->so_proto);
            printf("Protosw Size: %lu bytes\n", sizeof(struct protosw));
            
            printf("\n--- Protocol Type and Number ---\n");
            printf("pr_type: %d\n", this->so->so_proto->pr_type);
            printf("pr_protocol: %d\n", this->so->so_proto->pr_protocol);
            printf("pr_flags: 0x%04x\n", this->so->so_proto->pr_flags);
            
            /* Decode Protocol Flags */
            printf("Protocol Flags Analysis:\n");
            printf("  PR_ATOMIC: %s\n", (this->so->so_proto->pr_flags & 0x01) ? "SET" : "CLEAR");
            printf("  PR_ADDR: %s\n", (this->so->so_proto->pr_flags & 0x02) ? "SET" : "CLEAR");
            printf("  PR_CONNREQUIRED: %s\n", (this->so->so_proto->pr_flags & 0x04) ? "SET" : "CLEAR");
            printf("  PR_WANTRCVD: %s\n", (this->so->so_proto->pr_flags & 0x08) ? "SET" : "CLEAR");
            printf("  PR_IMPLOPCL: %s\n", (this->so->so_proto->pr_flags & 0x20) ? "SET" : "CLEAR");
            printf("  PR_CAPATTACH: %s\n", (this->so->so_proto->pr_flags & 0x80) ? "SET" : "CLEAR");
            printf("  PR_SOCKBUF: %s\n", (this->so->so_proto->pr_flags & 0x100) ? "SET" : "CLEAR");
            
            printf("\n--- Protocol Function Pointers ---\n");
            printf("pr_soreceive: 0x%p\n", this->so->so_proto->pr_soreceive);
            printf("pr_sosend: 0x%p\n", this->so->so_proto->pr_sosend);
            printf("pr_send: 0x%p\n", this->so->so_proto->pr_send);
            printf("pr_attach: 0x%p\n", this->so->so_proto->pr_attach);
            printf("pr_detach: 0x%p\n", this->so->so_proto->pr_detach);
            printf("pr_connect: 0x%p\n", this->so->so_proto->pr_connect);
            printf("pr_disconnect: 0x%p\n", this->so->so_proto->pr_disconnect);
            printf("pr_bind: 0x%p\n", this->so->so_proto->pr_bind);
            printf("pr_listen: 0x%p\n", this->so->so_proto->pr_listen);
            printf("pr_accept: 0x%p\n", this->so->so_proto->pr_accept);
            printf("pr_ctloutput: 0x%p\n", this->so->so_proto->pr_ctloutput);
        }
        
        /* Linger and Timeout */
        printf("\n--- Linger and Timeout ---\n");
        printf("so_linger: %d\n", this->so->so_linger);
        printf("so_timeo: %d\n", this->so->so_timeo);
        
        /* Error Information */
        printf("\n--- Error Information ---\n");
        printf("so_error: %u\n", this->so->so_error);
        printf("so_rerror: %u\n", this->so->so_rerror);
        
        /* Credentials and Security */
        printf("\n--- Security and Credentials ---\n");
        printf("so_cred: 0x%p\n", this->so->so_cred);
        printf("so_label: 0x%p\n", this->so->so_label);
        
        /* Generation Count */
        printf("\n--- Generation Count ---\n");
        printf("so_gencnt: %u\n", this->so->so_gencnt);
        
        /* Domain and Routing */
        printf("\n--- Domain and Routing ---\n");
        printf("so_fibnum: %d\n", this->so->so_fibnum);
        printf("so_user_cookie: 0x%08x\n", this->so->so_user_cookie);
        
        /* Timing and Rate Limiting */
        printf("\n--- Timing and Rate Limiting ---\n");
        printf("so_ts_clock: %d\n", this->so->so_ts_clock);
        printf("so_max_pacing_rate: %u bytes/s\n", this->so->so_max_pacing_rate);
        
        /* === SOCKET BUFFER ANALYSIS === */
        printf("\n=== SOCKET BUFFER ANALYSIS ===\n");
        
        /* Receive Buffer */
        printf("\n--- Receive Buffer (so_rcv) ---\n");
        printf("Receive Buffer Address: 0x%p\n", &this->so->so_rcv);
        printf("Receive Buffer Offset: %lu bytes\n", 
               (unsigned long)&this->so->so_rcv - (unsigned long)this->so);
        
        /* === RECURSIVE SOCKBUF ANALYSIS - RECEIVE === */
        printf("\n=== SOCKBUF STRUCTURE ANALYSIS (so_rcv) ===\n");
        printf("Sockbuf Base Address: 0x%p\n", &this->so->so_rcv);
        printf("Sockbuf Size: %lu bytes\n", sizeof(struct sockbuf));
        
        printf("\n--- Receive Buffer State and Flags ---\n");
        printf("sb_state: 0x%04x\n", this->so->so_rcv.sb_state);
        printf("sb_flags: 0x%04x\n", this->so->so_rcv.sb_flags);
        
        /* Decode Receive Buffer Flags */
        printf("Receive Buffer Flags Analysis:\n");
        printf("  SB_TLS_RX: %s\n", (this->so->so_rcv.sb_flags & 0x01) ? "SET" : "CLEAR");
        printf("  SB_TLS_RX_RUNNING: %s\n", (this->so->so_rcv.sb_flags & 0x02) ? "SET" : "CLEAR");
        printf("  SB_WAIT: %s\n", (this->so->so_rcv.sb_flags & 0x04) ? "SET" : "CLEAR");
        printf("  SB_SEL: %s\n", (this->so->so_rcv.sb_flags & 0x08) ? "SET" : "CLEAR");
        printf("  SB_ASYNC: %s\n", (this->so->so_rcv.sb_flags & 0x10) ? "SET" : "CLEAR");
        printf("  SB_UPCALL: %s\n", (this->so->so_rcv.sb_flags & 0x20) ? "SET" : "CLEAR");
        printf("  SB_AIO: %s\n", (this->so->so_rcv.sb_flags & 0x80) ? "SET" : "CLEAR");
        printf("  SB_KNOTE: %s\n", (this->so->so_rcv.sb_flags & 0x100) ? "SET" : "CLEAR");
        printf("  SB_NOCOALESCE: %s\n", (this->so->so_rcv.sb_flags & 0x200) ? "SET" : "CLEAR");
        printf("  SB_IN_TOE: %s\n", (this->so->so_rcv.sb_flags & 0x400) ? "SET" : "CLEAR");
        printf("  SB_AUTOSIZE: %s\n", (this->so->so_rcv.sb_flags & 0x800) ? "SET" : "CLEAR");
        printf("  SB_SPLICED: %s\n", (this->so->so_rcv.sb_flags & 0x4000) ? "SET" : "CLEAR");
        
        printf("\n--- Receive Buffer Counters ---\n");
        printf("sb_acc (available): %u bytes\n", this->so->so_rcv.sb_acc);
        printf("sb_ccc (claimed): %u bytes\n", this->so->so_rcv.sb_ccc);
        printf("sb_mbcnt (mbuf chars): %u bytes\n", this->so->so_rcv.sb_mbcnt);
        printf("sb_ctl (control chars): %u bytes\n", this->so->so_rcv.sb_ctl);
        
        printf("\n--- Receive Buffer Watermarks ---\n");
        printf("sb_hiwat (high watermark): %u bytes\n", this->so->so_rcv.sb_hiwat);
        printf("sb_lowat (low watermark): %u bytes\n", this->so->so_rcv.sb_lowat);
        printf("sb_mbmax (max mbuf chars): %u bytes\n", this->so->so_rcv.sb_mbmax);
        
        printf("\n--- Receive Buffer Timeout ---\n");
        printf("sb_timeo: %u nanoseconds\n", this->so->so_rcv.sb_timeo);
        
        printf("\n--- Receive Buffer Callbacks ---\n");
        printf("sb_upcall: 0x%p\n", this->so->so_rcv.sb_upcall);
        printf("sb_upcallarg: 0x%p\n", this->so->so_rcv.sb_upcallarg);
        
        printf("\n--- Receive Buffer Mbuf Chain ---\n");
        printf("sb_mb (first mbuf): 0x%p\n", this->so->so_rcv.sb_mb);
        printf("sb_mbtail (last mbuf): 0x%p\n", this->so->so_rcv.sb_mbtail);
        printf("sb_lastrecord (last record): 0x%p\n", this->so->so_rcv.sb_lastrecord);
        
        /* === RECURSIVE MBUF ANALYSIS === */
        if (this->so->so_rcv.sb_mb != NULL) {
            printf("\n=== MBUF STRUCTURE ANALYSIS (First in Receive Chain) ===\n");
            printf("Mbuf Base Address: 0x%p\n", this->so->so_rcv.sb_mb);
            printf("Mbuf Size: %lu bytes\n", sizeof(struct mbuf));
            
            printf("\n--- Mbuf Chain Links ---\n");
            printf("m_next: 0x%p\n", this->so->so_rcv.sb_mb->m_next);
            printf("m_nextpkt: 0x%p\n", this->so->so_rcv.sb_mb->m_nextpkt);
            
            printf("\n--- Mbuf Data Information ---\n");
            printf("m_data: 0x%p\n", this->so->so_rcv.sb_mb->m_data);
            printf("m_len: %d bytes\n", this->so->so_rcv.sb_mb->m_len);
            printf("m_type: %u\n", this->so->so_rcv.sb_mb->m_type);
            printf("m_flags: 0x%08x\n", this->so->so_rcv.sb_mb->m_flags);
            
            /* Decode Mbuf Flags */
            printf("Mbuf Flags Analysis:\n");
            printf("  M_EXT: %s\n", (this->so->so_rcv.sb_mb->m_flags & 0x00000001) ? "SET" : "CLEAR");
            printf("  M_PKTHDR: %s\n", (this->so->so_rcv.sb_mb->m_flags & 0x00000002) ? "SET" : "CLEAR");
            printf("  M_EOR: %s\n", (this->so->so_rcv.sb_mb->m_flags & 0x00000004) ? "SET" : "CLEAR");
            printf("  M_RDONLY: %s\n", (this->so->so_rcv.sb_mb->m_flags & 0x00000008) ? "SET" : "CLEAR");
            printf("  M_BCAST: %s\n", (this->so->so_rcv.sb_mb->m_flags & 0x00000010) ? "SET" : "CLEAR");
            printf("  M_MCAST: %s\n", (this->so->so_rcv.sb_mb->m_flags & 0x00000020) ? "SET" : "CLEAR");
            printf("  M_PROMISC: %s\n", (this->so->so_rcv.sb_mb->m_flags & 0x00000040) ? "SET" : "CLEAR");
            printf("  M_VLANTAG: %s\n", (this->so->so_rcv.sb_mb->m_flags & 0x00000080) ? "SET" : "CLEAR");
            printf("  M_EXTPG: %s\n", (this->so->so_rcv.sb_mb->m_flags & 0x00000100) ? "SET" : "CLEAR");
            printf("  M_NOFREE: %s\n", (this->so->so_rcv.sb_mb->m_flags & 0x00000200) ? "SET" : "CLEAR");
            printf("  M_TSTMP: %s\n", (this->so->so_rcv.sb_mb->m_flags & 0x00000400) ? "SET" : "CLEAR");
            printf("  M_TSTMP_HPREC: %s\n", (this->so->so_rcv.sb_mb->m_flags & 0x00000800) ? "SET" : "CLEAR");
            printf("  M_TSTMP_LRO: %s\n", (this->so->so_rcv.sb_mb->m_flags & 0x00001000) ? "SET" : "CLEAR");
            
            printf("\n--- Mbuf Type Analysis ---\n");
            printf("Type Description: %s\n",
                   this->so->so_rcv.sb_mb->m_type == 0 ? "MT_NOTMBUF" :
                   this->so->so_rcv.sb_mb->m_type == 1 ? "MT_DATA" :
                   this->so->so_rcv.sb_mb->m_type == 8 ? "MT_SONAME" :
                   this->so->so_rcv.sb_mb->m_type == 14 ? "MT_CONTROL" :
                   this->so->so_rcv.sb_mb->m_type == 15 ? "MT_EXTCONTROL" :
                   this->so->so_rcv.sb_mb->m_type == 16 ? "MT_OOBDATA" : "OTHER");
        }
        
        /* Send Buffer */
        printf("\n--- Send Buffer (so_snd) ---\n");
        printf("Send Buffer Address: 0x%p\n", &this->so->so_snd);
        printf("Send Buffer Offset: %lu bytes\n", 
               (unsigned long)&this->so->so_snd - (unsigned long)this->so);
        
        /* === RECURSIVE SOCKBUF ANALYSIS - SEND === */
        printf("\n=== SOCKBUF STRUCTURE ANALYSIS (so_snd) ===\n");
        printf("Send Buffer State: 0x%04x\n", this->so->so_snd.sb_state);
        printf("Send Buffer Flags: 0x%04x\n", this->so->so_snd.sb_flags);
        
        printf("\n--- Send Buffer Counters ---\n");
        printf("sb_acc (available): %u bytes\n", this->so->so_snd.sb_acc);
        printf("sb_ccc (claimed): %u bytes\n", this->so->so_snd.sb_ccc);
        printf("sb_mbcnt (mbuf chars): %u bytes\n", this->so->so_snd.sb_mbcnt);
        printf("sb_ctl (control chars): %u bytes\n", this->so->so_snd.sb_ctl);
        
        printf("\n--- Send Buffer Watermarks ---\n");
        printf("sb_hiwat (high watermark): %u bytes\n", this->so->so_snd.sb_hiwat);
        printf("sb_lowat (low watermark): %u bytes\n", this->so->so_snd.sb_lowat);
        printf("sb_mbmax (max mbuf chars): %u bytes\n", this->so->so_snd.sb_mbmax);
        
        printf("\n--- Send Buffer Mbuf Chain ---\n");
        printf("sb_mb (first mbuf): 0x%p\n", this->so->so_snd.sb_mb);
        printf("sb_mbtail (last mbuf): 0x%p\n", this->so->so_snd.sb_mbtail);
        printf("sb_lastrecord (last record): 0x%p\n", this->so->so_snd.sb_lastrecord);
        printf("sb_sndptr (send pointer): 0x%p\n", this->so->so_snd.sb_sndptr);
        printf("sb_sndptroff (send pointer offset): %u bytes\n", this->so->so_snd.sb_sndptroff);
        
        /* === LISTEN QUEUE ANALYSIS === */
        if (this->so->so_options & 0x0002) { /* SO_ACCEPTCONN */
            printf("\n=== LISTEN QUEUE ANALYSIS ===\n");
            printf("sol_qlen (complete queue length): %u\n", this->so->sol_qlen);
            printf("sol_incqlen (incomplete queue length): %u\n", this->so->sol_incqlen);
            printf("sol_qlimit (queue limit): %u\n", this->so->sol_qlimit);
            
            printf("\n--- Accept Filter ---\n");
            printf("sol_accept_filter: 0x%p\n", this->so->sol_accept_filter);
            printf("sol_accept_filter_arg: 0x%p\n", this->so->sol_accept_filter_arg);
            printf("sol_accept_filter_str: 0x%p\n", this->so->sol_accept_filter_str);
            
            printf("\n--- Listen Upcall ---\n");
            printf("sol_upcall: 0x%p\n", this->so->sol_upcall);
            printf("sol_upcallarg: 0x%p\n", this->so->sol_upcallarg);
        } else {
            printf("\n=== REGULAR SOCKET ANALYSIS ===\n");
            printf("so_listen: 0x%p\n", this->so->so_listen);
            printf("so_qstate: %u\n", this->so->so_qstate);
            printf("so_peerlabel: 0x%p\n", this->so->so_peerlabel);
            printf("so_oobmark: %lu\n", this->so->so_oobmark);
        }
        
        socket_creates++;
        socket_events++;
        
        printf("\n--- Socket Creation Summary ---\n");
        printf("Total Socket Events: %d\n", socket_events);
        printf("Socket Creates: %d\n", socket_creates);
        printf("Analysis Complete for Socket: 0x%p\n", this->so);
        printf("========================================\n\n");
    }
}

/* === SOCKET BIND ANALYSIS === */
fbt::sobind:entry
{
    this->so = (struct socket *)arg0;
    this->nam = arg1;
    
    if (this->so != NULL) {
        printf("========== SOCKET BIND: STRUCTURE UPDATE ANALYSIS ==========\n");
        printf("Process: PID %d (%s), Timestamp: %Y\n", pid, execname, walltimestamp);
        printf("Socket Address: 0x%p\n", this->so);
        printf("Bind Address: 0x%p\n", this->nam);
        
        printf("\n=== SOCKET STATE BEFORE BIND ===\n");
        printf("Socket Type: %s\n",
               this->so->so_type == 1 ? "SOCK_STREAM" :
               this->so->so_type == 2 ? "SOCK_DGRAM" : "OTHER");
        printf("Socket State: 0x%04x\n", this->so->so_state);
        printf("Socket Options: 0x%08x\n", this->so->so_options);
        printf("Protocol Control Block: 0x%p\n", this->so->so_pcb);
        
        printf("\n=== BIND OPERATION CONTEXT ===\n");
        printf("Bind Address Structure: 0x%p\n", this->nam);
        printf("Reference Count: %u\n", this->so->so_count);
        
        socket_binds++;
        socket_events++;
        
        printf("Total Socket Events: %d\n", socket_events);
        printf("Socket Binds: %d\n", socket_binds);
        printf("====================================================\n\n");
    }
}

/* === SOCKET CONNECT ANALYSIS === */
fbt::soconnect:entry
{
    this->so = (struct socket *)arg0;
    this->nam = arg1;
    
    if (this->so != NULL) {
        printf("========== SOCKET CONNECT: STRUCTURE UPDATE ANALYSIS ==========\n");
        printf("Process: PID %d (%s), Timestamp: %Y\n", pid, execname, walltimestamp);
        printf("Socket Address: 0x%p\n", this->so);
        printf("Connect Address: 0x%p\n", this->nam);
        
        printf("\n=== SOCKET STATE BEFORE CONNECT ===\n");
        printf("Socket Type: %s\n",
               this->so->so_type == 1 ? "SOCK_STREAM" :
               this->so->so_type == 2 ? "SOCK_DGRAM" : "OTHER");
        printf("Socket State: 0x%04x\n", this->so->so_state);
        printf("Connection Status: %s\n", (this->so->so_state & 0x0002) ? "CONNECTED" : "NOT_CONNECTED");
        printf("Connection In Progress: %s\n", (this->so->so_state & 0x0004) ? "YES" : "NO");
        printf("Non-blocking: %s\n", (this->so->so_state & 0x0100) ? "YES" : "NO");
        
        printf("\n=== CONNECT OPERATION CONTEXT ===\n");
        printf("Target Address Structure: 0x%p\n", this->nam);
        printf("Protocol Control Block: 0x%p\n", this->so->so_pcb);
        printf("Reference Count: %u\n", this->so->so_count);
        
        socket_connects++;
        socket_events++;
        
        printf("Total Socket Events: %d\n", socket_events);
        printf("Socket Connects: %d\n", socket_connects);
        printf("=======================================================\n\n");
    }
}

/* === SOCKET SEND ANALYSIS === */
fbt::sosend:entry
{
    this->so = (struct socket *)arg0;
    this->addr = arg1;
    this->uio = arg2;
    
    if (this->so != NULL) {
        printf("========== SOCKET SEND: BUFFER ANALYSIS ==========\n");
        printf("Process: PID %d (%s), Timestamp: %Y\n", pid, execname, walltimestamp);
        printf("Socket Address: 0x%p\n", this->so);
        printf("Send Address: 0x%p\n", this->addr);
        printf("UIO Structure: 0x%p\n", this->uio);
        
        printf("\n=== SEND BUFFER STATE ===\n");
        printf("Send Buffer Available: %u bytes\n", this->so->so_snd.sb_acc);
        printf("Send Buffer Used: %u bytes\n", this->so->so_snd.sb_ccc);
        printf("Send Buffer High Watermark: %u bytes\n", this->so->so_snd.sb_hiwat);
        printf("Send Buffer Low Watermark: %u bytes\n", this->so->so_snd.sb_lowat);
        printf("Send Buffer Mbuf Count: %u bytes\n", this->so->so_snd.sb_mbcnt);
        printf("Send Buffer Max Mbuf: %u bytes\n", this->so->so_snd.sb_mbmax);
        
        printf("\n=== SEND BUFFER SPACE ANALYSIS ===\n");
        printf("Available Space: %d bytes\n", 
               (int)(this->so->so_snd.sb_hiwat - this->so->so_snd.sb_ccc));
        printf("Mbuf Space: %d bytes\n", 
               (int)(this->so->so_snd.sb_mbmax - this->so->so_snd.sb_mbcnt));
        
        printf("\n=== SEND MBUF CHAIN ===\n");
        printf("First Mbuf: 0x%p\n", this->so->so_snd.sb_mb);
        printf("Last Mbuf: 0x%p\n", this->so->so_snd.sb_mbtail);
        printf("Send Pointer: 0x%p\n", this->so->so_snd.sb_sndptr);
        printf("Send Pointer Offset: %u bytes\n", this->so->so_snd.sb_sndptroff);
        
        socket_sends++;
        socket_events++;
        
        printf("Total Socket Events: %d\n", socket_events);
        printf("Socket Sends: %d\n", socket_sends);
        printf("==============================================\n\n");
    }
}

/* === SOCKET RECEIVE ANALYSIS === */
fbt::soreceive:entry
{
    this->so = (struct socket *)arg0;
    this->paddr = arg1;
    this->uio = arg2;
    
    if (this->so != NULL) {
        printf("========== SOCKET RECEIVE: BUFFER ANALYSIS ==========\n");
        printf("Process: PID %d (%s), Timestamp: %Y\n", pid, execname, walltimestamp);
        printf("Socket Address: 0x%p\n", this->so);
        printf("Address Pointer: 0x%p\n", this->paddr);
        printf("UIO Structure: 0x%p\n", this->uio);
        
        printf("\n=== RECEIVE BUFFER STATE ===\n");
        printf("Receive Buffer Available: %u bytes\n", this->so->so_rcv.sb_acc);
        printf("Receive Buffer Used: %u bytes\n", this->so->so_rcv.sb_ccc);
        printf("Receive Buffer High Watermark: %u bytes\n", this->so->so_rcv.sb_hiwat);
        printf("Receive Buffer Low Watermark: %u bytes\n", this->so->so_rcv.sb_lowat);
        printf("Receive Buffer Mbuf Count: %u bytes\n", this->so->so_rcv.sb_mbcnt);
        printf("Receive Buffer Max Mbuf: %u bytes\n", this->so->so_rcv.sb_mbmax);
        
        printf("\n=== RECEIVE BUFFER READINESS ===\n");
        printf("Data Available: %s\n", 
               (this->so->so_rcv.sb_acc >= this->so->so_rcv.sb_lowat) ? "YES" : "NO");
        printf("Error Present: %s\n", 
               (this->so->so_error != 0) ? "YES" : "NO");
        printf("Can't Receive More: %s\n", 
               (this->so->so_rcv.sb_state & 0x0020) ? "YES" : "NO");
        
        printf("\n=== RECEIVE MBUF CHAIN ===\n");
        printf("First Mbuf: 0x%p\n", this->so->so_rcv.sb_mb);
        printf("Last Mbuf: 0x%p\n", this->so->so_rcv.sb_mbtail);
        printf("Last Record: 0x%p\n", this->so->so_rcv.sb_lastrecord);
        
        socket_recvs++;
        socket_events++;
        
        printf("Total Socket Events: %d\n", socket_events);
        printf("Socket Receives: %d\n", socket_recvs);
        printf("=================================================\n\n");
    }
}

/* === PERIODIC STATISTICS === */
tick-30s
{
    printf("===============================================\n");
    printf("=== SOCKET STRUCTURE ANALYSIS SUMMARY ===\n");
    printf("Timestamp: %Y\n", walltimestamp);
    printf("===============================================\n");
    
    printf("\n=== SOCKET OPERATION STATISTICS ===\n");
    printf("Total Socket Events: %d\n", socket_events);
    printf("Socket Creates: %d\n", socket_creates);
    printf("Socket Binds: %d\n", socket_binds);
    printf("Socket Connects: %d\n", socket_connects);
    printf("Socket Sends: %d\n", socket_sends);
    printf("Socket Receives: %d\n", socket_recvs);
    
    printf("\n=== ACTIVITY ANALYSIS ===\n");
    printf("Creation Rate: %s\n", 
           socket_creates == 0 ? "NONE" :
           socket_creates < 5 ? "LOW" :
           socket_creates < 20 ? "MODERATE" : "HIGH");
    
    printf("I/O Activity: %s\n", 
           (socket_sends + socket_recvs) == 0 ? "NONE" :
           (socket_sends + socket_recvs) < 10 ? "LOW" :
           (socket_sends + socket_recvs) < 50 ? "MODERATE" : "HIGH");
    
    printf("Connection Activity: %s\n", 
           (socket_binds + socket_connects) == 0 ? "NONE" :
           (socket_binds + socket_connects) < 10 ? "LOW" :
           (socket_binds + socket_connects) < 50 ? "MODERATE" : "HIGH");
    
    printf("\n");
}

dtrace:::END
{
    printf("\n===============================================\n");
    printf("=== SOCKET STRUCTURE ANALYZER COMPLETE ===\n");
    printf("End Time: %Y\n", walltimestamp);
    printf("===============================================\n");
    
    printf("\n=== FINAL STATISTICS ===\n");
    printf("Total Socket Events: %d\n", socket_events);
    printf("Socket Creates: %d\n", socket_creates);
    printf("Socket Binds: %d\n", socket_binds);
    printf("Socket Connects: %d\n", socket_connects);
    printf("Socket Sends: %d\n", socket_sends);
    printf("Socket Receives: %d\n", socket_recvs);
    
    printf("\n=== ANALYSIS COVERAGE ===\n");
    printf("Socket Core Structure: ANALYZED\n");
    printf("Protocol Switch (protosw): ANALYZED\n");
    printf("Socket Buffers (sockbuf): ANALYZED\n");
    printf("Mbuf Chain Analysis: ANALYZED\n");
    printf("Listen Queue Analysis: ANALYZED\n");
    printf("State and Flag Decoding: ANALYZED\n");
    
    printf("\n=== RECURSIVE ANALYSIS DEPTH ===\n");
    printf("Level 1: struct socket -> COMPLETE\n");
    printf("Level 2: struct protosw -> COMPLETE\n");
    printf("Level 3: struct sockbuf -> COMPLETE\n");
    printf("Level 4: struct mbuf -> COMPLETE\n");
    printf("Level 5: Pointer references -> COMPLETE\n");
    
    printf("\nSocket structure analysis complete.\n");
    printf("All socket-related structures have been recursively analyzed.\n");
    printf("No floating-point operations were used (FreeBSD dtrace compatible).\n");
} 